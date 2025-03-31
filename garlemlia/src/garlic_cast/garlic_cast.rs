use crate::file_utils::garlemlia_files::{FileInfo, FileStorage, FileUpload};
use crate::garlemlia_structs::garlemlia_structs;
use crate::garlemlia_structs::garlemlia_structs::{u256_random, CloveRequestID, GarlemliaResponse};
use crate::simulator::simulator::{get_global_socket, SimulatedMessageHandler};
use crate::time_hash::time_based_hash::HashLocation;
use aes::Aes256;
use bincode;
use chrono::{DateTime, Timelike, Utc};
use cipher::generic_array::GenericArray;
use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use garlemlia_structs::{Clove, CloveData, CloveMessage, CloveNode, GMessage, GarlemliaMessage, GarlicMessage, MessageError, Node};
use primitive_types::U256;
use rand::random_bool;
use rand::seq::IndexedRandom;
use rand::{rng, RngCore};
use reed_solomon_erasure::galois_8::ReedSolomon;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::cmp::PartialEq;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;

pub const FORWARD_P: f64 = 0.95;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableCloveCache {
    cloves: HashMap<U256, CloveData>,
    next_hop_key: HashMap<u32, CloveNode>,
    next_hop_val: HashMap<u32, Option<CloveNode>>,
    alt_nodes_key: HashMap<u32, CloveNode>,
    alt_nodes_val: HashMap<u32, CloveNode>,
    alt_to_sequence_key: HashMap<u32, CloveNode>,
    alt_to_sequence_val: HashMap<u32, U256>,
    associations: HashMap<U256, Vec<CloveNode>>,
    seen_last: HashMap<U256, DateTime<Utc>>,
    my_alt_nodes: HashMap<U256, CloveNode>,
    am_alt_for: HashSet<U256>
}

impl SerializableCloveCache {
    pub fn from(cache: CloveCache) -> SerializableCloveCache {
        let mut next_hop_key = HashMap::new();
        let mut next_hop_val = HashMap::new();
        let mut alt_nodes_key = HashMap::new();
        let mut alt_nodes_val = HashMap::new();
        let mut alt_to_sequence_key = HashMap::new();
        let mut alt_to_sequence_val = HashMap::new();

        let mut index = 0;
        for info in cache.next_hop.iter() {
            next_hop_key.insert(index, info.0.clone());
            next_hop_val.insert(index, info.1.clone());

            index += 1;
        }

        index = 0;
        for info in cache.alt_nodes.iter() {
            alt_nodes_key.insert(index, info.0.clone());
            alt_nodes_val.insert(index, info.1.clone());

            index += 1;
        }

        index = 0;
        for info in cache.alt_to_sequence.iter() {
            alt_to_sequence_key.insert(index, info.0.clone());
            alt_to_sequence_val.insert(index, info.1.clone());

            index += 1;
        }

        SerializableCloveCache {
            cloves: cache.cloves,
            next_hop_key,
            next_hop_val,
            alt_nodes_key,
            alt_nodes_val,
            alt_to_sequence_key,
            alt_to_sequence_val,
            associations: cache.associations,
            seen_last: cache.seen_last,
            my_alt_nodes: cache.my_alt_nodes,
            am_alt_for: cache.am_alt_for
        }
    }

    pub fn to_clove_cache(self) -> CloveCache {
        let mut next_hop = HashMap::new();
        let mut alt_nodes = HashMap::new();
        let mut alt_to_sequence = HashMap::new();

        for entry in self.next_hop_key.iter() {
            let val = self.next_hop_val.get(entry.0).unwrap().clone();
            next_hop.insert(entry.1.clone(), val);
        }

        for entry in self.alt_nodes_key.iter() {
            let val = self.alt_nodes_val.get(entry.0).unwrap().clone();
            alt_nodes.insert(entry.1.clone(), val);
        }

        for entry in self.alt_to_sequence_key.iter() {
            let val = self.alt_to_sequence_val.get(entry.0).unwrap().clone();
            alt_to_sequence.insert(entry.1.clone(), val);
        }

        CloveCache {
            cloves: self.cloves,
            next_hop,
            alt_nodes,
            alt_to_sequence,
            associations: self.associations,
            seen_last: self.seen_last,
            my_alt_nodes: self.my_alt_nodes,
            am_alt_for: self.am_alt_for,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CloveCache {
    cloves: HashMap<U256, CloveData>,
    next_hop: HashMap<CloveNode, Option<CloveNode>>,
    alt_nodes: HashMap<CloveNode, CloveNode>,
    alt_to_sequence: HashMap<CloveNode, U256>,
    associations: HashMap<U256, Vec<CloveNode>>,
    seen_last: HashMap<U256, DateTime<Utc>>,
    my_alt_nodes: HashMap<U256, CloveNode>,
    am_alt_for: HashSet<U256>
}

impl CloveCache {
    pub fn new() -> CloveCache {
        CloveCache {
            cloves: HashMap::new(),
            next_hop: HashMap::new(),
            alt_nodes: HashMap::new(),
            alt_to_sequence: HashMap::new(),
            associations: HashMap::new(),
            seen_last: HashMap::new(),
            my_alt_nodes: HashMap::new(),
            am_alt_for: HashSet::new(),
        }
    }

    pub fn remove_sequence(&mut self, sequence_number: U256) {
        let associated = self.associations.remove(&sequence_number);

        match associated {
            Some(associated_nodes) => {
                self.cloves.remove(&sequence_number);
                self.seen_last.remove(&sequence_number);
                self.my_alt_nodes.remove(&sequence_number);

                for node in associated_nodes {
                    self.next_hop.remove(&node);
                    self.alt_nodes.remove(&node);
                }
            }
            None => {
                // If the clove exists in the cache, there should be nodes associated with it
                // So this should never happen in theory.
                println!("This should not happen: CloveCache::remove_sequence():1");
            }
        }
    }

    pub fn insert_clove(&mut self, clove: Clove, from: Node) {
        self.cloves.insert(clove.sequence_number, CloveData { clove, from });
    }

    pub fn remove_clove(&mut self, sequence_number: U256) {
        self.cloves.remove(&sequence_number);
    }

    pub fn insert_association(&mut self, sequence_number: U256, node: CloveNode) {
        if self.associations.contains_key(&sequence_number) {
            self.associations.get_mut(&sequence_number).unwrap().push(node);
            self.associations.get_mut(&sequence_number).unwrap().dedup();
        } else {
            self.associations.insert(sequence_number, vec![node]);
        }
    }

    pub fn insert_updated_association(&mut self, sequence_number: U256, new_sequence_number: U256) {
        if self.associations.contains_key(&sequence_number) {
            let associations = self.associations.get(&sequence_number).unwrap().clone();

            self.associations.insert(new_sequence_number, vec![]);
            for mut node in associations.iter().cloned() {
                node.sequence_number = new_sequence_number;
                self.associations.get_mut(&new_sequence_number).unwrap().push(node);
            }
        } else {
            self.associations.insert(new_sequence_number, vec![]);
        }
    }

    pub fn remove_association(&mut self, sequence_number: U256) {
        self.associations.remove(&sequence_number);
    }

    pub fn insert_next_hop(&mut self, node: CloveNode, next_hop: Option<CloveNode>) {
        self.next_hop.insert(node.clone(), next_hop.clone());

        if let Some(next_hop) = next_hop {
            self.insert_association(node.sequence_number, next_hop);
        }
    }

    pub fn update_next_hop(&mut self, node: CloveNode, next_hop: Option<CloveNode>) {
        let prev_next = self.next_hop.remove(&node.clone());
        self.next_hop.insert(node.clone(), next_hop.clone());

        if let Some(previous_wrapped) = prev_next {
            if let Some(previous) = previous_wrapped {
                let associations = self.associations.get_mut(&node.sequence_number).unwrap();
                associations.retain(|x| *x != previous);
                if let Some(next_hop) = next_hop {
                    self.insert_association(node.sequence_number, next_hop);
                }
            }
        }
    }

    pub fn remove_next_hop(&mut self, node: CloveNode) {
        self.next_hop.remove(&node);
    }

    pub fn insert_am_alt(&mut self, sequence_number: U256) {
        self.am_alt_for.insert(sequence_number);
    }

    pub fn remove_am_alt(&mut self, sequence_number: U256) {
        self.am_alt_for.remove(&sequence_number);
    }

    pub fn insert_alt_node(&mut self, node: CloveNode, alt_node: CloveNode) {
        self.alt_nodes.insert(node.clone(), alt_node.clone());

        let try_sequence = self.alt_to_sequence.get(&node).cloned();
        if try_sequence.is_some() {
            self.alt_to_sequence.insert(alt_node.clone(), try_sequence.unwrap());
            self.insert_association(try_sequence.clone().unwrap(), alt_node.clone());
        } else {
            self.alt_to_sequence.insert(alt_node.clone(), node.sequence_number);
            self.insert_association(node.sequence_number, alt_node);
        }
    }

    pub fn remove_alt_node(&mut self, node: CloveNode) {
        self.alt_nodes.remove(&node);
        self.alt_to_sequence.remove(&node);
    }

    pub fn get_alt(&self, node: CloveNode) -> Option<CloveNode> {
        self.alt_nodes.get(&node).cloned()
    }

    pub fn get_old_from_alt(&self, node: &CloveNode) -> Option<CloveNode> {
        for info in self.alt_nodes.iter() {
            if info.1.sequence_number == node.sequence_number {
                return Some(info.0.clone());
            }
        }
        None
    }

    pub fn get_sequence_from_alt(&self, node: CloveNode) -> Option<U256> {
        self.alt_to_sequence.get(&node).cloned()
    }

    pub fn insert_my_alt_node(&mut self, sequence_number: U256, my_alt_node: CloveNode) {
        self.my_alt_nodes.insert(sequence_number, my_alt_node.clone());

        self.insert_association(sequence_number, my_alt_node);
    }

    pub fn remove_my_alt_node(&mut self, sequence_number: U256) {
        self.my_alt_nodes.remove(&sequence_number);
    }
    
    pub fn get_forward_node(&self, clove_node: CloveNode) -> Result<Option<CloveNode>, ()> {
        let info = self.next_hop.get(&clove_node);

        match info {
            Some(info) => {
                Ok(info.clone())
            }
            _ => {
                Err(())
            }
        }
    }

    pub fn update_sequence_number(&mut self, new_sequence_number: U256, clove_node: CloveNode) {
        let node = clove_node.node.clone();
        let new_clove_node = CloveNode { sequence_number: new_sequence_number, node };

        let next = self.get_forward_node(clove_node.clone());

        match next {
            Ok(next_hop) => {
                match next_hop {
                    Some(next_node) => {
                        let mut new_next_hop_clove_node = CloveNode { sequence_number: new_sequence_number, node: next_node.clone().node };
                        new_next_hop_clove_node.sequence_number = new_sequence_number;
                        self.insert_next_hop(new_clove_node.clone(), Some(new_next_hop_clove_node.clone()));
                        self.insert_next_hop(new_next_hop_clove_node.clone(), Some(new_clove_node.clone()));

                        let mut has_alt = self.alt_nodes.contains_key(&clove_node);

                        if has_alt {
                            // In theory this should never happen since alt nodes are assigned
                            // after the path has already been solidified
                            println!("This should not happen: CloveCache::update_sequence_number():1");
                            let mut alt = self.alt_nodes.get(&clove_node).unwrap().clone();
                            alt.sequence_number = new_sequence_number;
                            self.insert_alt_node(new_clove_node, alt);
                        }

                        has_alt = self.alt_nodes.contains_key(&next_node);

                        if has_alt {
                            // In theory this should never happen since alt nodes are assigned
                            // after the path has already been solidified
                            println!("This should not happen: CloveCache::update_sequence_number():2");
                            let mut alt = self.alt_nodes.get(&next_node).unwrap().clone();
                            alt.sequence_number = new_sequence_number;
                            self.insert_alt_node(new_next_hop_clove_node, alt);
                        }

                        self.insert_updated_association(clove_node.sequence_number, new_sequence_number);
                    }
                    None => {
                        // This is the end of the line, either at the initiator or proxy
                        self.next_hop.insert(new_clove_node.clone(), None);

                        let has_alt = self.alt_nodes.contains_key(&clove_node);

                        if has_alt {
                            // In theory this should never happen since alt nodes are assigned
                            // after the path has already been solidified
                            println!("This should not happen: CloveCache::update_sequence_number():3");
                            let alt = self.alt_nodes.get(&clove_node).unwrap().clone();
                            self.insert_alt_node(new_clove_node, alt);
                        }

                        self.insert_updated_association(clove_node.sequence_number, new_sequence_number);
                    }
                }
            }
            Err(_) => {
                // This shouldn't happen and is a failure
                // This method should only be called upon a proxy agree, meaning that this
                // Should exist
                println!("This should not happen: CloveCache::update_sequence_number():4");
            }
        }
    }

    pub fn replace_with_alt_node(&mut self, old_clove_node: &CloveNode) -> Option<CloveNode> {
        let new_clove_node = self.alt_nodes.remove(old_clove_node);

        match new_clove_node {
            Some(new_clove_node) => {
                let forward_clove_node_try = self.next_hop.remove(old_clove_node).unwrap();

                match forward_clove_node_try {
                    Some(forward_clove_node) => {
                        self.next_hop.insert(new_clove_node.clone(), Some(forward_clove_node.clone()));
                        self.next_hop.remove(&forward_clove_node);
                        self.next_hop.insert(forward_clove_node, Some(new_clove_node.clone()));
                    }
                    _ => {
                        self.next_hop.insert(new_clove_node.clone(), None);
                    }
                }
                Some(new_clove_node)
            }
            _ => {
                None
            }
        }
    }

    pub fn seen(&mut self, sequence_number: U256) {
        self.seen_last.insert(sequence_number, Utc::now());
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct SerializableProxy {
    sequence_number: U256,
    neighbor_1: CloveNode,
    neighbor_2: CloveNode,
    neighbor_1_hops: u16,
    neighbor_2_hops: u16,
    public_key: String,
    #[serde(with = "chrono::serde::ts_seconds")]
    used_last: DateTime<Utc>
}

impl SerializableProxy {
    pub fn from(proxy: Proxy) -> SerializableProxy {
        SerializableProxy {
            sequence_number: proxy.sequence_number,
            neighbor_1: proxy.neighbor_1,
            neighbor_2: proxy.neighbor_2,
            neighbor_1_hops: proxy.neighbor_1_hops,
            neighbor_2_hops: proxy.neighbor_2_hops,
            public_key: proxy.public_key.to_public_key_pem(rsa::pkcs8::LineEnding::LF).unwrap(),
            used_last: proxy.used_last
        }
    }

    pub fn to_proxy(self) -> Proxy {
        Proxy {
            sequence_number: self.sequence_number,
            neighbor_1: self.neighbor_1,
            neighbor_2: self.neighbor_2,
            neighbor_1_hops: self.neighbor_1_hops,
            neighbor_2_hops: self.neighbor_2_hops,
            public_key: RsaPublicKey::from_public_key_pem(&*self.public_key).unwrap(),
            used_last: self.used_last,
        }
    }

    pub fn hashmap_to_serializable(proxies: HashMap<U256, Proxy>) -> HashMap<U256, SerializableProxy> {
        let mut proxies_serial = HashMap::new();

        for item in proxies {
            proxies_serial.insert(item.0, SerializableProxy::from(item.1));
        }

        proxies_serial
    }

    pub fn hashmap_to_proxy(proxies: HashMap<U256, SerializableProxy>) -> HashMap<U256, Proxy> {
        let mut proxies_serial = HashMap::new();

        for item in proxies {
            proxies_serial.insert(item.0, item.1.to_proxy());
        }

        proxies_serial
    }

    pub fn vec_to_serializable(proxies: Vec<Proxy>) -> Vec<SerializableProxy> {
        let mut proxies_serial = vec![];

        for proxy in proxies {
            proxies_serial.push(SerializableProxy::from(proxy));
        }

        proxies_serial
    }

    pub fn vec_to_proxy(proxies_serial: Vec<SerializableProxy>) -> Vec<Proxy> {
        let mut proxies = vec![];

        for proxy in proxies_serial {
            proxies.push(proxy.to_proxy());
        }

        proxies
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proxy {
    pub sequence_number: U256,
    pub neighbor_1: CloveNode,
    pub neighbor_2: CloveNode,
    pub neighbor_1_hops: u16,
    pub neighbor_2_hops: u16,
    public_key: RsaPublicKey,
    used_last: DateTime<Utc>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableInitiatorRequest {
    request_id: U256,
    validator_required: bool,
    proxies: Vec<SerializableProxy>,
    proxy_id_associations: HashMap<U256, SerializableProxy>,
    responses: Vec<CloveMessage>
}

impl SerializableInitiatorRequest {
    pub fn from(initiator_request: InitiatorRequest) -> SerializableInitiatorRequest {
        SerializableInitiatorRequest {
            request_id: initiator_request.request_id,
            validator_required: initiator_request.validator_required,
            proxies: SerializableProxy::vec_to_serializable(initiator_request.proxies),
            proxy_id_associations: SerializableProxy::hashmap_to_serializable(initiator_request.proxy_id_associations),
            responses: initiator_request.responses
        }
    }

    pub fn to_initiator_request(self) -> InitiatorRequest {
        InitiatorRequest {
            request_id: self.request_id,
            validator_required: self.validator_required,
            proxies: SerializableProxy::vec_to_proxy(self.proxies),
            proxy_id_associations: SerializableProxy::hashmap_to_proxy(self.proxy_id_associations),
            responses: self.responses
        }
    }

    pub fn hashmap_to_serializable(proxies: HashMap<U256, InitiatorRequest>) -> HashMap<U256, SerializableInitiatorRequest> {
        let mut proxies_serial = HashMap::new();

        for item in proxies {
            proxies_serial.insert(item.0, SerializableInitiatorRequest::from(item.1));
        }

        proxies_serial
    }

    pub fn hashmap_to_initiator_request(proxies: HashMap<U256, SerializableInitiatorRequest>) -> HashMap<U256, InitiatorRequest> {
        let mut proxies_serial = HashMap::new();

        for item in proxies {
            proxies_serial.insert(item.0, item.1.to_initiator_request());
        }

        proxies_serial
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct InitiatorRequest {
    request_id: U256,
    validator_required: bool,
    proxies: Vec<Proxy>,
    proxy_id_associations: HashMap<U256, Proxy>,
    responses: Vec<CloveMessage>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableProxyRequest {
    sequence_number: U256,
    request_id: U256,
    self_proxy_id: Option<U256>,
    validator_required: bool,
    initiator: SerializableProxy,
    sent: DateTime<Utc>,
    request: CloveMessage
}

impl SerializableProxyRequest {
    pub fn from(initiator_request: ProxyRequest) -> SerializableProxyRequest {
        SerializableProxyRequest {
            sequence_number: initiator_request.sequence_number,
            request_id: initiator_request.request_id,
            self_proxy_id: initiator_request.self_proxy_id,
            validator_required: initiator_request.validator_required,
            initiator: SerializableProxy::from(initiator_request.initiator),
            sent: initiator_request.sent,
            request: initiator_request.request
        }
    }

    pub fn to_proxy_request(self) -> ProxyRequest {
        ProxyRequest {
            sequence_number: self.sequence_number,
            request_id: self.request_id,
            self_proxy_id: self.self_proxy_id,
            validator_required: self.validator_required,
            initiator: self.initiator.to_proxy(),
            sent: self.sent,
            request: self.request
        }
    }

    pub fn hashmap_to_serializable(proxies: HashMap<U256, ProxyRequest>) -> HashMap<U256, SerializableProxyRequest> {
        let mut proxies_serial = HashMap::new();

        for item in proxies {
            proxies_serial.insert(item.0, SerializableProxyRequest::from(item.1));
        }

        proxies_serial
    }

    pub fn hashmap_to_proxy_request(proxies: HashMap<U256, SerializableProxyRequest>) -> HashMap<U256, ProxyRequest> {
        let mut proxies_serial = HashMap::new();

        for item in proxies {
            proxies_serial.insert(item.0, item.1.to_proxy_request());
        }

        proxies_serial
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProxyRequest {
    sequence_number: U256,
    request_id: U256,
    self_proxy_id: Option<U256>,
    validator_required: bool,
    initiator: Proxy,
    sent: DateTime<Utc>,
    request: CloveMessage
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableGarlicCast {
    local_node: Node,
    pub known_nodes: Vec<Node>,
    proxies: Vec<SerializableProxy>,
    initiators: Vec<SerializableProxy>,
    partial_proxies: HashMap<U256, Node>,
    cache: SerializableCloveCache,
    requests_as_initiator: HashMap<U256, SerializableInitiatorRequest>,
    requests_as_proxy: HashMap<U256, SerializableProxyRequest>,
    do_not_forward: HashMap<U256, DateTime<Utc>>,
    pub public_key: String,
    pub private_key: String
}

impl SerializableGarlicCast {

    pub fn from(garlic: GarlicCast) -> SerializableGarlicCast {
        SerializableGarlicCast {
            local_node: garlic.local_node.clone(),
            known_nodes: garlic.known_nodes.clone(),
            proxies: SerializableProxy::vec_to_serializable(garlic.proxies.clone()),
            initiators: SerializableProxy::vec_to_serializable(garlic.initiators.clone()),
            partial_proxies: garlic.partial_proxies.clone(),
            cache: SerializableCloveCache::from(garlic.cache.clone()),
            requests_as_initiator: SerializableInitiatorRequest::hashmap_to_serializable(garlic.requests_as_initiator.clone()),
            requests_as_proxy: SerializableProxyRequest::hashmap_to_serializable(garlic.requests_as_proxy.clone()),
            do_not_forward: garlic.do_not_forward.clone(),
            public_key: garlic.public_key.unwrap().to_public_key_pem(rsa::pkcs8::LineEnding::LF).unwrap(),
            private_key: garlic.private_key.unwrap().to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap().to_string()
        }
    }

    pub fn to_garlic(self) -> GarlicCast {
        GarlicCast {
            socket: get_global_socket().unwrap(),
            local_node: self.local_node,
            message_handler: Arc::new(SimulatedMessageHandler::create(0)),
            known_nodes: self.known_nodes,
            proxies: SerializableProxy::vec_to_proxy(self.proxies),
            initiators: SerializableProxy::vec_to_proxy(self.initiators),
            partial_proxies: self.partial_proxies,
            cache: self.cache.to_clove_cache(),
            collected_messages: HashMap::new(),
            searches_checked: HashSet::new(),
            requests_as_initiator: SerializableInitiatorRequest::hashmap_to_initiator_request(self.requests_as_initiator),
            requests_as_proxy: SerializableProxyRequest::hashmap_to_proxy_request(self.requests_as_proxy),
            do_not_forward: self.do_not_forward,
            public_key: Some(RsaPublicKey::from_public_key_pem(&*self.public_key).unwrap()),
            private_key: Some(RsaPrivateKey::from_pkcs8_pem(&*self.private_key).unwrap())
        }
    }
}

#[derive(Clone, Debug)]
pub struct GarlicCast {
    socket: Arc<UdpSocket>,
    local_node: Node,
    message_handler: Arc<Box<dyn GMessage>>,
    pub known_nodes: Vec<Node>,
    pub proxies: Vec<Proxy>,
    pub initiators: Vec<Proxy>,
    pub partial_proxies: HashMap<U256, Node>,
    pub cache: CloveCache,
    pub collected_messages: HashMap<CloveRequestID, GarlicMessage>,
    pub searches_checked: HashSet<U256>,
    pub requests_as_initiator: HashMap<U256, InitiatorRequest>,
    pub requests_as_proxy: HashMap<U256, ProxyRequest>,
    pub do_not_forward: HashMap<U256, DateTime<Utc>>,
    public_key: Option<RsaPublicKey>,
    private_key: Option<RsaPrivateKey>
}

impl GarlicCast {
    pub fn new(socket: Arc<UdpSocket>, local_node: Node, message_handler: Arc<Box<dyn GMessage>>, known_nodes: Vec<Node>, public_key: Option<RsaPublicKey>, private_key: Option<RsaPrivateKey>) -> GarlicCast {
        GarlicCast {
            socket,
            local_node,
            message_handler,
            known_nodes,
            proxies: Vec::new(),
            initiators: Vec::new(),
            partial_proxies: HashMap::new(),
            cache: CloveCache::new(),
            collected_messages: HashMap::new(),
            searches_checked: HashSet::new(),
            requests_as_initiator: HashMap::new(),
            requests_as_proxy: HashMap::new(),
            do_not_forward: HashMap::new(),
            public_key,
            private_key
        }
    }

    pub fn set_public_key(&mut self, public_key: RsaPublicKey) {
        self.public_key = Some(public_key);
    }

    pub fn set_private_key(&mut self, private_key: RsaPrivateKey) {
        self.private_key = Some(private_key);
    }

    pub fn update_from(&mut self, gc: GarlicCast) {
        self.socket =  gc.socket.clone();
        self.local_node = gc.local_node.clone();
        self.message_handler = gc.message_handler.clone();
        self.known_nodes = gc.known_nodes.clone();
        self.proxies = gc.proxies.clone();
        self.cache = gc.cache.clone();
        self.collected_messages = gc.collected_messages.clone();
        self.public_key = gc.public_key.clone();
        self.private_key = gc.private_key.clone();
    }

    pub fn update_known(&mut self, nodes: Vec<Node>) {
        self.known_nodes.extend(nodes);
        self.known_nodes.sort_by_key(|n| n.id);
        self.known_nodes.dedup();
        self.known_nodes.retain(|n| *n != self.local_node);
    }

    pub fn set_known(&mut self, nodes: Vec<Node>) {
        self.known_nodes.clear();
        self.known_nodes.extend(nodes);
    }

    // Example of removing async if not needed:
    pub fn get_proxies(&self) -> Vec<Proxy> {
        self.proxies.clone()
    }
    pub fn get_proxy(&self, sequence_number: U256) -> Option<Proxy> {
        self.proxies.iter().find(|p| p.sequence_number == sequence_number).cloned()
    }

    pub fn get_initiators(&self) -> Vec<Proxy> {
        self.initiators.clone()
    }

    pub fn get_initiator(&self, sequence_number: U256) -> Option<Proxy> {
        self.initiators.iter().find(|p| p.sequence_number == sequence_number).cloned()
    }

    pub async fn discover_proxies(&mut self, count: u8) {
        let mut count_actual = count;
        if  count < 2 {
            count_actual = 2;
        }

        let sequence_number = u256_random();

        let msg = CloveMessage::RequestProxy {
            msg: "Will proxy?".to_string(),
            public_key: self.public_key.clone().unwrap().to_public_key_pem(rsa::pkcs8::LineEnding::LF).unwrap()
        };

        let mut known_nodes;
        {
            known_nodes = self.known_nodes.clone();
            self.do_not_forward.insert(sequence_number, Utc::now());
        }

        let mut cloves = GarlicCast::generate_cloves_no_rsa(msg, count_actual, sequence_number, None);

        let mut total_sent = 0;
        while total_sent < count_actual {
            let mut tasks = Vec::new();

            for _ in 0..count_actual - total_sent {
                let socket = Arc::clone(&self.socket);
                let message_handler = Arc::clone(&self.message_handler);
                let local_node = self.local_node.clone();
                let temp_node = known_nodes.remove(rand::random_range(0..known_nodes.len()));
                let clove = cloves.pop().unwrap();

                let task = tokio::spawn(async move {

                    let send_msg = GarlicMessage::FindProxy {
                        sequence_number,
                        clove: clove.clone()
                    };

                    {
                        if let Err(e) = message_handler.send(&Arc::from(socket.clone()), local_node.clone(), &temp_node.address, &GarlicMessage::build_send(local_node.clone(), send_msg)).await {
                            eprintln!("Failed to send Forward to {}: {:?}", temp_node.address, e);
                        }
                    }

                    let response;
                    {
                        response = message_handler.recv(200, &temp_node.address).await;
                    }

                    return match response {
                        Ok(_) => {
                            Ok(temp_node)
                        }
                        _ => {
                            Err((temp_node, clove))
                        }
                    }
                });
                tasks.push(task);
            }

            for task in tasks {
                match task.await {
                    Ok(val) => {
                        match val {
                            Ok(node_success) => {
                                let new_clove = CloveNode {
                                    sequence_number,
                                    node: node_success,
                                };

                                self.cache.insert_next_hop(new_clove.clone(), None);
                                // Insert associations
                                self.cache.insert_association(sequence_number, new_clove.clone());
                                // Insert seen last
                                self.cache.seen(sequence_number);
                                total_sent += 1;
                            }
                            Err(e) => {
                                cloves.push(e.1);
                                self.known_nodes.retain(|x| *x != e.0);
                            }
                        }
                    }
                    Err(e) => {
                        println!("{}: This should not happen: GarlicCast::discover_proxies():1 : {}", self.local_node.address, e);
                    }
                }
            }
        }
    }

    fn clove_to_message(clove_1: Clove, clove_2: Clove, self_priv_key: Option<RsaPrivateKey>) -> CloveMessage {
        let data_shards = 2usize;
        let parity_shards: usize = clove_1.ida_count as usize - data_shards;

        // Create the Reed-Solomon encoder
        let r = ReedSolomon::new(data_shards, parity_shards).unwrap();

        let mut message_shards = vec![];
        for _ in 0..parity_shards + data_shards {
            message_shards.push(None);
        }
        message_shards[clove_1.index as usize] = Some(clove_1.msg_fragment);
        message_shards[clove_2.index as usize] = Some(clove_2.msg_fragment);

        let mut key_shards = vec![];
        for _ in 0..parity_shards + data_shards {
            key_shards.push(None);
        }
        key_shards[clove_1.index as usize] = Some(clove_1.key_fragment);
        key_shards[clove_2.index as usize] = Some(clove_2.key_fragment);

        r.reconstruct(&mut message_shards).unwrap();
        r.reconstruct(&mut key_shards).unwrap();

        let encrypted_bytes: Vec<u8> = message_shards.iter()
            .take(2)
            .filter_map(|s| s.as_ref())
            .flatten()
            .cloned()
            .collect();

        let mut key_bytes: Vec<u8> = key_shards.iter()
            .take(2)
            .filter_map(|s| s.as_ref())
            .flatten()
            .cloned()
            .collect();

        match self_priv_key {
            Some(self_priv_key) => {
                key_bytes = self_priv_key.decrypt(
                    Pkcs1v15Encrypt,
                    &*key_bytes
                ).unwrap();
            }
            None => {}
        }

        let cipher = Aes256::new(GenericArray::from_slice(&key_bytes));
        let mut decrypted_padded = encrypted_bytes.clone();

        for chunk in decrypted_padded.chunks_exact_mut(16) {
            let block = GenericArray::from_mut_slice(chunk);
            cipher.decrypt_block(block);
        }

        // Remove padding
        let pad_len = *decrypted_padded.last().unwrap() as usize;

        let decrypted_bytes = decrypted_padded[..decrypted_padded.len() - pad_len].to_vec();

        let final_msg: CloveMessage = bincode::deserialize(&decrypted_bytes).unwrap();

        final_msg
    }

    pub fn message_from_cloves_no_rsa(clove_1: Clove, clove_2: Clove) -> CloveMessage {
        GarlicCast::clove_to_message(clove_1, clove_2, None)
    }

    pub fn message_from_cloves_rsa(clove_1: Clove, clove_2: Clove, self_priv_k: RsaPrivateKey) -> CloveMessage {
        GarlicCast::clove_to_message(clove_1, clove_2, Some(self_priv_k))
    }

    pub fn clove_generator(msg_serialized: Vec<u8>, count: u8, sequence_number: U256, recipient_pub_key: Option<RsaPublicKey>, request_id: CloveRequestID) -> Vec<Clove> {
        let mut cloves = vec![];

        let mut count_actual = count;
        if count < 3 {
            count_actual = 3;
        }

        let mut key = [0u8; 32];
        rng().fill_bytes(&mut key);

        // Pad the message to ensure it's a multiple of 16 bytes
        let block_size = 16;
        let mut padded_message = msg_serialized.clone();
        let pad_len = block_size - (padded_message.len() % block_size);
        // Padding
        padded_message.extend(vec![pad_len as u8; pad_len]);

        // Encrypt using AES
        // This is actually insecure as all hell, but it doesn't really need to be all that secure
        // The message is split up completely and uses a different random key each time
        // The only way to put it together is to have both halves of the message first
        // So this is relatively acceptable I think
        let cipher = Aes256::new(GenericArray::from_slice(&key));
        let mut ciphertext = padded_message.clone();

        for chunk in ciphertext.chunks_exact_mut(16) {
            let block = GenericArray::from_mut_slice(chunk);
            cipher.encrypt_block(block);
        }

        let data = ciphertext.to_vec();
        let mut key_data = key.to_vec();

        let mut rng = rand_core::OsRng;
        match recipient_pub_key {
            Some(recipient_pub_key) => {
                key_data = recipient_pub_key.encrypt(
                    &mut rng,
                    Pkcs1v15Encrypt,
                    &key_data
                ).unwrap();
            }
            None => {}
        }

        let data_shards = 2usize;
        let parity_shards: usize = count_actual as usize - data_shards;
        let total_shards = data_shards + parity_shards;

        let r = ReedSolomon::new(data_shards, parity_shards).unwrap();

        let data_shard_size = (data.len() + data_shards - 1) / data_shards;
        let key_shard_size  = (key_data.len() + data_shards - 1) / data_shards;

        // Make a vector of 30 shards (2 data, 28 parity).
        let mut data_shards_vec = vec![vec![0; data_shard_size];  total_shards];
        let mut key_shards_vec  = vec![vec![0; key_shard_size];   total_shards];

        // Only fill the first 2 shards with actual data
        for (i, chunk) in data.chunks(data_shard_size).enumerate() {
            if i < data_shards {
                data_shards_vec[i][..chunk.len()].copy_from_slice(chunk);
            }
        }
        // Ditto for the key data
        for (i, chunk) in key_data.chunks(key_shard_size).enumerate() {
            if i < data_shards {
                key_shards_vec[i][..chunk.len()].copy_from_slice(chunk);
            }
        }

        // The library overwrites the *last 28* shards with parity
        r.encode(&mut data_shards_vec).unwrap();
        r.encode(&mut key_shards_vec).unwrap();


        let mut send_count = count;
        if count < 2 {
            send_count = 2;
        }

        for i in 0..send_count as usize {
            let clove = Clove {
                sequence_number,
                request_id: request_id.clone(),
                msg_fragment: data_shards_vec[i].clone(),
                key_fragment: key_shards_vec[i].clone(),
                sent: Utc::now(),
                index: i as u8,
                ida_count: count_actual as u8
            };

            cloves.push(clove);
        }

        cloves
    }

    pub fn generate_cloves_no_rsa(msg: CloveMessage, count: u8, sequence_number: U256, request_id: Option<CloveRequestID>) -> Vec<Clove> {
        // Serialize message into bytes
        let msg_serialized = bincode::serialize(&msg).unwrap();

        GarlicCast::clove_generator(msg_serialized, count, sequence_number, None, request_id.unwrap_or(CloveRequestID::new(u256_random(), 0)))
    }

    pub fn generate_cloves_rsa(msg: CloveMessage, recipient_pub_k: RsaPublicKey, count: u8, sequence_number: U256, request_id: Option<CloveRequestID>) -> Vec<Clove> {
        // Serialize message into bytes
        let msg_serialized = bincode::serialize(&msg).unwrap();

        GarlicCast::clove_generator(msg_serialized, count, sequence_number, Some(recipient_pub_k), request_id.unwrap_or(CloveRequestID::new(u256_random(), 0)))
    }

    fn replace_proxy(&mut self, old_proxy: &Proxy, new_proxy: &Proxy) {
        for i in 0..self.proxies.len() {
            if self.proxies[i].sequence_number == old_proxy.sequence_number {
                self.proxies.remove(i);
                self.proxies.push(new_proxy.clone());
                break;
            }
        }

        for i in 0..self.initiators.len() {
            if self.initiators[i].sequence_number == old_proxy.sequence_number {
                self.initiators.remove(i);
                self.initiators.push(new_proxy.clone());
                break;
            }
        }

        for info in self.requests_as_proxy.clone().iter() {
            if info.1.initiator.sequence_number == old_proxy.sequence_number {
                let mut new_proxy_request = info.1.clone();
                new_proxy_request.initiator = new_proxy.clone();
                self.requests_as_proxy.remove(info.0);
                self.requests_as_proxy.insert(info.0.clone(), new_proxy_request);
            }
        }

        for info in self.requests_as_initiator.clone().iter() {
            for i in 0..info.1.proxies.len() {
                if info.1.proxies[i].sequence_number == old_proxy.sequence_number {
                    let mut new_initiator_request = info.1.clone();
                    new_initiator_request.proxies.remove(i);
                    new_initiator_request.proxies.push(new_proxy.clone());
                    self.requests_as_initiator.remove(info.0);
                    self.requests_as_initiator.insert(info.0.clone(), new_initiator_request);
                }
            }
        }
    }

    fn remove_proxy(&mut self, proxy: &Proxy) {
        for i in 0..self.proxies.len() {
            if self.proxies[i].sequence_number == proxy.sequence_number {
                self.proxies.remove(i);
                break;
            }
        }

        for i in 0..self.initiators.len() {
            if self.initiators[i].sequence_number == proxy.sequence_number {
                self.initiators.remove(i);
                break;
            }
        }

        for info in self.requests_as_proxy.clone().iter() {
            if info.1.sequence_number == proxy.sequence_number {
                self.requests_as_proxy.remove(info.0);
            }
        }

        for info in self.requests_as_initiator.clone().iter() {
            for i in 0..info.1.proxies.len() {
                if info.1.proxies[i].sequence_number == proxy.sequence_number {
                    let mut new_initiator_request = info.1.clone();
                    new_initiator_request.proxies.remove(i);
                    self.requests_as_initiator.remove(info.0);
                    self.requests_as_initiator.insert(info.0.clone(), new_initiator_request);
                }
            }
        }
    }

    async fn manage_error_parallel_send(&mut self, e: (i32, CloveNode, CloveNode, GarlicMessage, GarlicMessage, Proxy)) -> Option<Proxy> {
        let mut remove = true;
        let mut changed_proxy = e.5.clone();
        if e.0 == 1 {
            let n_1_replaced = self.replace_with_alt(e.1, e.3).await;

            if n_1_replaced.is_ok() {
                let new_proxy_n_1 = n_1_replaced.unwrap();
                let mut new_proxy = e.5.clone();
                new_proxy.neighbor_1 = new_proxy_n_1;

                self.replace_proxy(&e.5, &new_proxy);
                changed_proxy = new_proxy;
                remove = false;
            } else {
                let try_update = self.cache.get_alt(e.2);

                match try_update {
                    Some(updated) => {
                        self.cache.remove_sequence(updated.sequence_number);
                    }
                    None => {}
                }
            }
        } else if e.0 == 2 {
            let n_2_replaced = self.replace_with_alt(e.2, e.4).await;

            if n_2_replaced.is_ok() {
                let new_proxy_n_2 = n_2_replaced.unwrap();
                let mut new_proxy = e.5.clone();
                new_proxy.neighbor_2 = new_proxy_n_2;

                self.replace_proxy(&e.5, &new_proxy);
                changed_proxy = new_proxy;
                remove = false;
            } else {
                let try_update = self.cache.get_alt(e.1);

                match try_update {
                    Some(updated) => {
                        self.cache.remove_sequence(updated.sequence_number);
                    }
                    None => {}
                }
            }
        } else if e.0 == 3 {
            let n_1_replaced = self.replace_with_alt(e.1.clone(), e.3).await;
            let n_2_replaced = self.replace_with_alt(e.2.clone(), e.4).await;

            if n_1_replaced.is_ok() && n_2_replaced.is_ok() {
                let new_proxy_n_1 = n_1_replaced.unwrap();
                let new_proxy_n_2 = n_2_replaced.unwrap();
                let mut new_proxy = e.5.clone();
                new_proxy.neighbor_1 = new_proxy_n_1;
                new_proxy.neighbor_2 = new_proxy_n_2;

                self.replace_proxy(&e.5, &new_proxy);
                changed_proxy = new_proxy;
                remove = false;
            } else {
                if n_1_replaced.is_err() && n_2_replaced.is_ok() {
                    let try_update = self.cache.get_alt(e.2);

                    match try_update {
                        Some(updated) => {
                            self.cache.remove_sequence(updated.sequence_number);
                        }
                        None => {}
                    }
                }

                if n_2_replaced.is_err() && n_1_replaced.is_ok() {
                    let try_update = self.cache.get_alt(e.1);

                    match try_update {
                        Some(updated) => {
                            self.cache.remove_sequence(updated.sequence_number);
                        }
                        None => {}
                    }
                }
            }
        }

        if remove {
            None
        } else {
            Some(changed_proxy)
        }
    }

    pub async fn search_overlay(&mut self, req: String, proxy_id_pool: Vec<U256>, count: u8) {
        let mut count_actual = count;
        if  count < 2 {
            count_actual = 2;
        }

        let request_id = u256_random();
        let mut proxy_request = InitiatorRequest {
            request_id,
            validator_required: true,
            proxies: vec![],
            proxy_id_associations: HashMap::new(),
            responses: vec![],
        };

        let proxies_init = self.proxies.clone();

        let mut proxies = vec![];
        for proxy in proxies_init {
            if proxy_id_pool.contains(&proxy.sequence_number) {
                proxies.push(proxy);
            }
        }

        let mut total_sent = 0;
        while total_sent < count_actual {
            let mut tasks = Vec::new();

            for i in 0..count_actual - total_sent {
                let proxy_id = u256_random();
                let request_id_full = CloveRequestID::new(request_id, total_sent + i);
                let msg = CloveMessage::SearchOverlay {
                    request_id: request_id_full.clone(),
                    proxy_id,
                    search_term: req.clone(),
                    public_key: self.public_key.clone().unwrap().to_public_key_pem(rsa::pkcs8::LineEnding::LF).unwrap()
                };

                let socket = Arc::clone(&self.socket);
                let message_handler = Arc::clone(&self.message_handler);
                let local_node = self.local_node.clone();
                let msg_clone = msg.clone();
                let temp_proxy = proxies.remove(rand::random_range(0..proxies.len()));

                let task = tokio::spawn(async move {

                    let n_1 = temp_proxy.neighbor_1.node.clone();
                    let n_2 = temp_proxy.neighbor_2.node.clone();

                    let cloves = GarlicCast::generate_cloves_rsa(msg_clone.clone(), temp_proxy.clone().public_key, 2, temp_proxy.sequence_number, Some(request_id_full));

                    let n_1_msg = GarlicMessage::Forward {
                        sequence_number: temp_proxy.neighbor_1.sequence_number,
                        clove: cloves[0].clone()
                    };
                    let n_2_msg = GarlicMessage::Forward {
                        sequence_number: temp_proxy.neighbor_2.sequence_number,
                        clove: cloves[1].clone()
                    };

                    let n_1_clove_node = CloveNode {
                        sequence_number: temp_proxy.neighbor_1.sequence_number,
                        node: n_1.clone()
                    };
                    let n_2_clove_node = CloveNode {
                        sequence_number: temp_proxy.neighbor_2.sequence_number,
                        node: n_2.clone()
                    };

                    {
                        if let Err(e) = message_handler.send(&Arc::from(socket.clone()), local_node.clone(), &n_1.address, &GarlicMessage::build_send(local_node.clone(), n_1_msg.clone())).await {
                            eprintln!("Failed to send Forward to {}: {:?}", n_1.address, e);
                        }
                    }

                    let response;
                    {
                        response = message_handler.recv(200, &n_1.address).await;
                    }

                    {
                        if let Err(e) = message_handler.send(&Arc::from(socket.clone()), local_node.clone(), &n_2.address, &GarlicMessage::build_send(local_node.clone(), n_2_msg.clone())).await {
                            eprintln!("Failed to send Forward to {}: {:?}", n_2.address, e);
                        }
                    }

                    let response2;
                    {
                        response2 = message_handler.recv(200, &n_2.address).await;
                    }

                    let mut return_code = 0;
                    match response {
                        Ok(_) => {}
                        _ => {
                            return_code = 1;
                        }
                    }

                    match response2 {
                        Ok(_) => {
                            if return_code == 1 {
                                return Err((return_code, n_1_clove_node, n_2_clove_node, n_1_msg, n_2_msg, temp_proxy.clone(), proxy_id));
                            }

                            Ok((proxy_id, temp_proxy.clone()))
                        }
                        _ => {
                            if return_code == 1 {
                                return_code = 3;
                            } else {
                                return_code = 2;
                            }

                            Err((return_code, n_1_clove_node, n_2_clove_node, n_1_msg, n_2_msg, temp_proxy.clone(), proxy_id))
                        }
                    }
                });
                tasks.push(task);
            }

            for task in tasks {
                match task.await {
                    Ok(val) => {
                        match val {
                            Ok(info) => {
                                total_sent += 1;
                                proxy_request.proxies.push(info.1.clone());
                                proxy_request.proxy_id_associations.insert(info.0, info.1);
                            }
                            Err(e) => {
                                let changed_wrapped = self.manage_error_parallel_send((e.0, e.1, e.2, e.3, e.4, e.5.clone())).await;

                                if changed_wrapped.is_none() {
                                    self.remove_proxy(&e.5);
                                    self.cache.remove_sequence(e.5.sequence_number);
                                } else {
                                    total_sent += 1;
                                    proxy_request.proxies.push(changed_wrapped.clone().unwrap());
                                    proxy_request.proxy_id_associations.insert(e.6, changed_wrapped.unwrap());
                                }
                            }
                        }
                    }
                    Err(e) => {
                        println!("{}: This should not happen: GarlicCast::send_search_overlay():1 : {}", self.local_node.address, e);
                    }
                }
            }
        }

        self.requests_as_initiator.insert(request_id, proxy_request);
    }
    
    pub async fn send_to_proxy(&mut self, mut proxy: Proxy, cloves: Vec<Clove>) -> bool {
        let n_1_clove_node = proxy.neighbor_1.clone();
        let n_2_clove_node = proxy.neighbor_2.clone();

        let n_1_good = self.forward_from_proxy(&n_1_clove_node, &cloves[0], &proxy).await;

        if n_1_good.is_err() {
            let try_update = self.cache.get_alt(n_2_clove_node);

            match try_update {
                Some(updated) => {
                    self.cache.remove_sequence(updated.sequence_number);
                }
                None => {}
            }
            self.cache.remove_sequence(proxy.neighbor_2.sequence_number);
            self.remove_proxy(&proxy);

            return false;
        }

        let n_1_replaced = n_1_good.unwrap();

        if n_1_replaced.is_some() {
            let new_proxy_n_1 = n_1_replaced.unwrap();

            self.replace_proxy(&proxy, &new_proxy_n_1);
            proxy = new_proxy_n_1;
        }

        let n_2_good = self.forward_from_proxy(&n_2_clove_node, &cloves[1], &proxy).await;

        if n_2_good.is_ok() {
            let n_2_replaced = n_2_good.unwrap();

            if n_2_replaced.is_some() {
                let new_proxy_n_2 = n_2_replaced.unwrap();

                self.replace_proxy(&proxy, &new_proxy_n_2);
            }
            true
        } else {
            let try_update = self.cache.get_alt(n_1_clove_node);

            match try_update {
                Some(updated) => {
                    self.cache.remove_sequence(updated.sequence_number);
                }
                None => {}
            }
            self.cache.remove_sequence(proxy.neighbor_2.sequence_number);
            self.remove_proxy(&proxy);
            
            false
        }
    }
    
    pub async fn search_kademlia(&mut self, proxy_id_pool: Vec<U256>, key: U256) {
        let request_id = u256_random();
        let mut proxy_request = InitiatorRequest {
            request_id,
            validator_required: false,
            proxies: vec![],
            proxy_id_associations: HashMap::new(),
            responses: vec![],
        };

        let proxies_init = self.proxies.clone();

        let mut proxies = vec![];
        for proxy in proxies_init {
            if proxy_id_pool.contains(&proxy.sequence_number) {
                proxies.push(proxy);
            }
        }

        let mut sent = false;

        while !sent {
            let temp_proxy = proxies.remove(rand::random_range(0..proxies.len()));

            //let proxy_id = rand::random::<U256>();
            let msg = CloveMessage::SearchGarlemlia {
                request_id: CloveRequestID::new(request_id, 0),
                key
            };

            let cloves = GarlicCast::generate_cloves_rsa(msg.clone(), temp_proxy.clone().public_key, 2, temp_proxy.sequence_number, Some(CloveRequestID::new(request_id, 0)));

            sent = self.send_to_proxy(temp_proxy.clone(), cloves).await;

            if sent {
                proxy_request.proxies.push(temp_proxy);
            }
        }

        self.requests_as_initiator.insert(request_id, proxy_request);
    }

    pub async fn store_file(&mut self, mut file_info: FileUpload, search_id_pool: Vec<U256>, file_id_pool: Vec<U256>, file_storage: FileStorage) {
        let request_id = u256_random();
        let mut proxy_request = InitiatorRequest {
            request_id,
            validator_required: false,
            proxies: vec![],
            proxy_id_associations: HashMap::new(),
            responses: vec![],
        };

        let proxies_init = self.proxies.clone();

        let mut file_info_proxies = vec![];
        for proxy in proxies_init.clone() {
            if search_id_pool.contains(&proxy.sequence_number) {
                file_info_proxies.push(proxy);
            }
        }

        let mut file_chunk_proxies = vec![];
        for proxy in proxies_init {
            if file_id_pool.contains(&proxy.sequence_number) {
                file_chunk_proxies.push(proxy);
            }
        }

        file_info.metadata_location.store();
        file_info.key_location.store();

        let mut file_messages = CloveMessage::file_upload(file_info, file_storage, Some(request_id)).await;
        let messages_len = file_messages.len();

        let mut file_chunks_sent = 0;
        let mut total_sent = 0;
        while total_sent < messages_len {
            let mut tasks = Vec::new();

            for _ in 0..messages_len - total_sent {
                let socket = Arc::clone(&self.socket);
                let message_handler = Arc::clone(&self.message_handler);
                let local_node = self.local_node.clone();
                let msg_clone = file_messages.remove(0);

                let temp_proxy;
                if msg_clone.is_file_chunk {
                    temp_proxy = file_chunk_proxies.get(file_chunks_sent % file_chunk_proxies.len()).unwrap().clone();
                    file_chunks_sent += 1;
                } else {
                    temp_proxy = file_info_proxies.remove(rand::random_range(0..file_info_proxies.len()));
                }

                let task = tokio::spawn(async move {
                    let n_1 = temp_proxy.neighbor_1.node.clone();
                    let n_2 = temp_proxy.neighbor_2.node.clone();

                    let cloves = GarlicCast::generate_cloves_rsa(msg_clone.clone().message, temp_proxy.clone().public_key, 2, temp_proxy.sequence_number, Some(msg_clone.message.request_id().unwrap()));

                    let n_1_msg = GarlicMessage::Forward {
                        sequence_number: temp_proxy.neighbor_1.sequence_number,
                        clove: cloves[0].clone()
                    };
                    let n_2_msg = GarlicMessage::Forward {
                        sequence_number: temp_proxy.neighbor_2.sequence_number,
                        clove: cloves[1].clone()
                    };

                    let n_1_clove_node = CloveNode {
                        sequence_number: temp_proxy.neighbor_1.sequence_number,
                        node: n_1.clone()
                    };
                    let n_2_clove_node = CloveNode {
                        sequence_number: temp_proxy.neighbor_2.sequence_number,
                        node: n_2.clone()
                    };

                    {
                        if let Err(e) = message_handler.send(&Arc::from(socket.clone()), local_node.clone(), &n_1.address, &GarlicMessage::build_send(local_node.clone(), n_1_msg.clone())).await {
                            eprintln!("Failed to send Forward to {}: {:?}", n_1.address, e);
                        }
                    }

                    let response;
                    {
                        response = message_handler.recv(200, &n_1.address).await;
                    }

                    {
                        if let Err(e) = message_handler.send(&Arc::from(socket.clone()), local_node.clone(), &n_2.address, &GarlicMessage::build_send(local_node.clone(), n_2_msg.clone())).await {
                            eprintln!("Failed to send Forward to {}: {:?}", n_2.address, e);
                        }
                    }

                    let response2;
                    {
                        response2 = message_handler.recv(200, &n_2.address).await;
                    }

                    let mut return_code = 0;
                    match response {
                        Ok(_) => {}
                        _ => {
                            return_code = 1;
                        }
                    }

                    match response2 {
                        Ok(_) => {
                            if return_code == 1 {
                                return Err((return_code, n_1_clove_node, n_2_clove_node, n_1_msg, n_2_msg, temp_proxy.clone(), msg_clone));
                            }

                            Ok(temp_proxy.clone())
                        }
                        _ => {
                            if return_code == 1 {
                                return_code = 3;
                            } else {
                                return_code = 2;
                            }

                            Err((return_code, n_1_clove_node, n_2_clove_node, n_1_msg, n_2_msg, temp_proxy.clone(), msg_clone))
                        }
                    }
                });
                tasks.push(task);
            }

            for task in tasks {
                match task.await {
                    Ok(val) => {
                        match val {
                            Ok(info) => {
                                total_sent += 1;
                                proxy_request.proxies.push(info.clone());
                            }
                            Err(e) => {
                                let changed_wrapped = self.manage_error_parallel_send((e.0, e.1, e.2, e.3, e.4, e.5.clone())).await;

                                if changed_wrapped.is_none() {
                                    self.remove_proxy(&e.5);
                                    self.cache.remove_sequence(e.5.sequence_number);
                                    file_messages.push(e.6);
                                } else {
                                    total_sent += 1;
                                    proxy_request.proxies.push(changed_wrapped.clone().unwrap());
                                }
                            }
                        }
                    }
                    Err(e) => {
                        println!("{}: This should not happen: GarlicCast::send_search_overlay():1 : {}", self.local_node.address, e);
                    }
                }
            }
        }

        self.requests_as_initiator.insert(request_id, proxy_request);
    }

    pub async fn get_file_info(&mut self, search_id_pool: Vec<U256>, metadata_location: Vec<HashLocation>, key_location: Vec<HashLocation>) -> U256 {
        let request_id = u256_random();
        let mut proxy_request = InitiatorRequest {
            request_id,
            validator_required: false,
            proxies: vec![],
            proxy_id_associations: HashMap::new(),
            responses: vec![],
        };

        let proxies_init = self.proxies.clone();

        let mut proxies = vec![];
        for proxy in proxies_init.clone() {
            if search_id_pool.contains(&proxy.sequence_number) {
                proxies.push(proxy);
            }
        }

        let metadata_loc = metadata_location.iter().find(|l| l.time.hour() == Utc::now().hour()).unwrap().clone().id;
        let key_loc = key_location.iter().find(|l| l.time.hour() == Utc::now().hour()).unwrap().clone().id;

        let mut total_sent = 0;
        while total_sent < 2 {
            let temp_proxy = proxies.remove(rand::random_range(0..proxies.len()));

            let key;
            if total_sent == 0 {
                key = metadata_loc;
            } else {
                key = key_loc;
            }

            let msg = CloveMessage::SearchGarlemlia {
                request_id: CloveRequestID::new(request_id, total_sent),
                key
            };

            let cloves = GarlicCast::generate_cloves_rsa(msg.clone(), temp_proxy.clone().public_key, 2, temp_proxy.sequence_number, Some(msg.request_id().unwrap()));

            let sent = self.send_to_proxy(temp_proxy.clone(), cloves).await;

            if sent {
                proxy_request.proxies.push(temp_proxy);
                total_sent += 1;
            }
        }

        self.requests_as_initiator.insert(request_id, proxy_request);

        request_id
    }

    pub async fn download_file(&mut self, file_info: FileInfo, file_id_pool: Vec<U256>) -> U256 {
        let request_id = u256_random();
        let mut proxy_request = InitiatorRequest {
            request_id,
            validator_required: false,
            proxies: vec![],
            proxy_id_associations: HashMap::new(),
            responses: vec![],
        };

        println!("{:?}", file_info);

        let proxies_init = self.proxies.clone();

        let mut file_chunk_proxies = vec![];
        for proxy in proxies_init {
            if file_id_pool.contains(&proxy.sequence_number) {
                file_chunk_proxies.push(proxy);
            }
        }

        let mut chunk_ids = file_info.needed_chunks.iter().map(|c| c.chunk_id).collect::<Vec<U256>>();
        let chunks_len = chunk_ids.len();

        let mut file_chunks_requested = 0;
        let mut total_requested = 0;
        while total_requested < chunks_len {
            let mut tasks = Vec::new();

            for _ in 0..chunks_len - total_requested {
                let socket = Arc::clone(&self.socket);
                let message_handler = Arc::clone(&self.message_handler);
                let local_node = self.local_node.clone();
                let chunk_id = chunk_ids.remove(0);
                let msg_clone = CloveMessage::SearchGarlemlia {
                    request_id: CloveRequestID::new(request_id, file_chunks_requested),
                    key: chunk_id.clone()
                };

                let temp_proxy = file_chunk_proxies.get(file_chunks_requested as usize % file_chunk_proxies.len()).unwrap().clone();
                file_chunks_requested += 1;

                let task = tokio::spawn(async move {
                    let n_1 = temp_proxy.neighbor_1.node.clone();
                    let n_2 = temp_proxy.neighbor_2.node.clone();

                    let cloves = GarlicCast::generate_cloves_rsa(msg_clone.clone(), temp_proxy.clone().public_key, 2, temp_proxy.sequence_number, Some(msg_clone.request_id().unwrap()));

                    let n_1_msg = GarlicMessage::Forward {
                        sequence_number: temp_proxy.neighbor_1.sequence_number,
                        clove: cloves[0].clone()
                    };
                    let n_2_msg = GarlicMessage::Forward {
                        sequence_number: temp_proxy.neighbor_2.sequence_number,
                        clove: cloves[1].clone()
                    };

                    let n_1_clove_node = CloveNode {
                        sequence_number: temp_proxy.neighbor_1.sequence_number,
                        node: n_1.clone()
                    };
                    let n_2_clove_node = CloveNode {
                        sequence_number: temp_proxy.neighbor_2.sequence_number,
                        node: n_2.clone()
                    };

                    {
                        if let Err(e) = message_handler.send(&Arc::from(socket.clone()), local_node.clone(), &n_1.address, &GarlicMessage::build_send(local_node.clone(), n_1_msg.clone())).await {
                            eprintln!("Failed to send Forward to {}: {:?}", n_1.address, e);
                        }
                    }

                    let response;
                    {
                        response = message_handler.recv(200, &n_1.address).await;
                    }

                    {
                        if let Err(e) = message_handler.send(&Arc::from(socket.clone()), local_node.clone(), &n_2.address, &GarlicMessage::build_send(local_node.clone(), n_2_msg.clone())).await {
                            eprintln!("Failed to send Forward to {}: {:?}", n_2.address, e);
                        }
                    }

                    let response2;
                    {
                        response2 = message_handler.recv(200, &n_2.address).await;
                    }

                    let mut return_code = 0;
                    match response {
                        Ok(_) => {}
                        _ => {
                            return_code = 1;
                        }
                    }

                    match response2 {
                        Ok(_) => {
                            if return_code == 1 {
                                return Err((return_code, n_1_clove_node, n_2_clove_node, n_1_msg, n_2_msg, temp_proxy.clone(), chunk_id));
                            }

                            Ok(temp_proxy.clone())
                        }
                        _ => {
                            if return_code == 1 {
                                return_code = 3;
                            } else {
                                return_code = 2;
                            }

                            Err((return_code, n_1_clove_node, n_2_clove_node, n_1_msg, n_2_msg, temp_proxy.clone(), chunk_id))
                        }
                    }
                });
                tasks.push(task);
            }

            for task in tasks {
                match task.await {
                    Ok(val) => {
                        match val {
                            Ok(info) => {
                                total_requested += 1;
                                proxy_request.proxies.push(info.clone());
                            }
                            Err(e) => {
                                let changed_wrapped = self.manage_error_parallel_send((e.0, e.1, e.2, e.3, e.4, e.5.clone())).await;

                                if changed_wrapped.is_none() {
                                    self.remove_proxy(&e.5);
                                    self.cache.remove_sequence(e.5.sequence_number);
                                    chunk_ids.push(e.6);
                                } else {
                                    total_requested += 1;
                                    proxy_request.proxies.push(changed_wrapped.clone().unwrap());
                                }
                            }
                        }
                    }
                    Err(e) => {
                        println!("{}: This should not happen: GarlicCast::send_search_overlay():1 : {}", self.local_node.address, e);
                    }
                }
            }
        }

        self.requests_as_initiator.insert(request_id, proxy_request);

        request_id
    }

    async fn replace_with_alt(&mut self, next_node: CloveNode, mut alt_msg: GarlicMessage) -> Result<CloveNode, ()> {
        let try_update = self.cache.replace_with_alt_node(&next_node);

        match &try_update {
            Some(updated) => {
                alt_msg.update_sequence_number(updated.sequence_number);

                let socket = Arc::clone(&self.socket);

                {
                    if let Err(e) = self.message_handler.send(&Arc::from(socket), self.local_node.clone(), &updated.node.address, &GarlicMessage::build_send(self.local_node.clone(), alt_msg)).await {
                        eprintln!("Failed to send Forward to {}: {:?}", updated.node.address, e);
                    }
                }

                let response2;
                {
                    response2 = self.message_handler.recv(200, &updated.node.address).await;
                }

                match response2 {
                    Ok(_) => {
                        println!("{} :: REPLACEALT {} :: {} -> {}", Utc::now(), updated.sequence_number, self.local_node.address, updated.node.address);
                        Ok(try_update.unwrap())
                    }
                    _ => {
                        // Big failure
                        self.cache.remove_sequence(updated.sequence_number);
                        self.cache.remove_sequence(next_node.sequence_number);
                        println!("{} :: REPLACEALT {} :: FAILURE : OFFLINE :: {} -> {}", Utc::now(), updated.sequence_number, self.local_node.address, updated.node.address);
                        Err(())
                    }
                }
            }
            None => {
                // Big failure
                self.cache.remove_sequence(next_node.sequence_number);
                println!("{} :: REPLACEALT {} :: FAILURE : NONEXISTENT :: {}", Utc::now(), alt_msg.sequence_number(), self.local_node.address);
                Err(())
            }
        }
    }

    async fn forward(&mut self, next_node_hop: &CloveNode, msg: &Clove) -> bool {
        let mut new_clove = msg.clone();

        if msg.sequence_number != next_node_hop.sequence_number {
            new_clove.sequence_number = next_node_hop.sequence_number;
        }

        let new_msg = GarlicMessage::Forward {
            sequence_number: next_node_hop.sequence_number,
            clove: new_clove
        };

        let socket = Arc::clone(&self.socket);

        {
            if let Err(e) = self.message_handler.send(&Arc::from(socket.clone()), self.local_node.clone(), &next_node_hop.node.address, &GarlicMessage::build_send(self.local_node.clone(), new_msg.clone())).await {
                eprintln!("Failed to send Forward to {}: {:?}", next_node_hop.node.address, e);
            }
        }

        let response;
        {
            response = self.message_handler.recv(200, &next_node_hop.node.address).await;
        }

        match response {
            Ok(_) => {
                true
            }
            _ => {
                let replace_info = self.replace_with_alt(next_node_hop.clone(), new_msg).await;
                if replace_info.is_ok() {
                    let mut real_sequence_number = next_node_hop.sequence_number;

                    let try_sequence = self.cache.alt_to_sequence.get(next_node_hop).cloned();

                    if try_sequence.is_some() {
                        real_sequence_number = try_sequence.unwrap();
                    }
                    
                    let my_alt_for_seq = self.cache.my_alt_nodes.get(&real_sequence_number).cloned();

                    if my_alt_for_seq.is_some() {
                        self.send_alt(Some(replace_info.clone().unwrap()), None, my_alt_for_seq.clone().unwrap()).await;
                        self.update_my_alt_next_or_last(my_alt_for_seq.unwrap(), next_node_hop.clone().node, replace_info.unwrap().node).await;
                    }

                    true
                } else {
                    false
                }
            }
        }
    }

    async fn forward_from_proxy(&mut self, next_node_hop: &CloveNode, msg: &Clove, proxy: &Proxy) -> Result<Option<Proxy>, ()> {
        let next_node = next_node_hop.clone();
        let mut new_clove = msg.clone();

        if msg.sequence_number != next_node.sequence_number {
            new_clove.sequence_number = next_node.sequence_number;
        }

        let new_msg = GarlicMessage::Forward {
            sequence_number: next_node.sequence_number,
            clove: new_clove.clone()
        };

        let socket = Arc::clone(&self.socket);

        {
            if let Err(e) = self.message_handler.send(&Arc::from(socket.clone()), self.local_node.clone(), &next_node.node.address, &GarlicMessage::build_send(self.local_node.clone(), new_msg.clone())).await {
                eprintln!("Failed to send Forward to {}: {:?}", next_node.node.address, e);
            }
        }

        let response;
        {
            response = self.message_handler.recv(200, &next_node.node.address).await;
        }

        match response {
            Ok(_) => {
                Ok(None)
            }
            _ => {
                let replace_info = self.replace_with_alt(next_node, new_msg).await;

                match replace_info {
                    Ok(replacement) => {
                        let mut new_proxy = proxy.clone();

                        if proxy.neighbor_1.node.id == next_node_hop.node.id {
                            new_proxy.neighbor_1 = replacement.clone();
                        } else if proxy.neighbor_2.node.id == next_node_hop.node.id {
                            new_proxy.neighbor_2 = replacement.clone();
                        } else {
                            return Err(());
                        }

                        let my_alt_for_seq = self.cache.my_alt_nodes.get(&next_node_hop.sequence_number).cloned();

                        if my_alt_for_seq.is_some() {
                            self.update_my_alt_next_or_last(my_alt_for_seq.clone().unwrap(), next_node_hop.clone().node, replacement.node).await;
                        }

                        Ok(Some(new_proxy))
                    }
                    Err(info) => {
                        Err(info)
                    }
                }
            }
        }
    }

    async fn forward_find_proxy(&mut self, sequence_number: U256, node: Node, msg: Clove) {
        let mut keep_trying = true;
        while keep_trying {
            // Basically just try the fuck out of some nodes until one responds with an IsAlive message
            let mut choose_list = self.known_nodes.clone();

            choose_list.retain(|n| *n != node);

            let forward_node = choose_list.choose(&mut rand::rng()).unwrap().clone();

            let new_msg = GarlicMessage::FindProxy {
                sequence_number,
                clove: msg.clone()
            };

            let socket = Arc::clone(&self.socket);

            {
                if let Err(e) = self.message_handler.send(&Arc::from(socket.clone()), self.local_node.clone(), &forward_node.address, &GarlicMessage::build_send(self.local_node.clone(), new_msg)).await {
                    eprintln!("Failed to send Forward to {}: {:?}", forward_node.address, e);
                }
            }

            let response;
            {
                response = self.message_handler.recv(200, &forward_node.address).await;
            }

            match response {
                Ok(_) => {
                    // Insert two next_hops for original node and new forward node
                    let forward_clove = CloveNode { sequence_number, node: forward_node.clone() };
                    let original_clove = CloveNode { sequence_number, node: node.clone() };

                    self.cache.insert_next_hop(original_clove.clone(), Some(forward_clove.clone()));
                    self.cache.insert_next_hop(forward_clove.clone(), Some(original_clove.clone()));
                    // Insert clove
                    self.cache.insert_clove(msg.clone(), node.clone());
                    // Insert associations
                    self.cache.insert_association(sequence_number, original_clove.clone());
                    self.cache.insert_association(sequence_number, forward_clove.clone());
                    // Insert seen last
                    self.cache.seen(sequence_number);

                    keep_trying = false;
                }
                Err(_) => {}
            }
        }
    }

    async fn forward_proxy_accept(&mut self, proxy: Proxy, old_sequence: U256) {
        let hops_start = rand::random::<u16>() & 0b1111;
        
        let proxy_info = CloveMessage::ProxyInfo {
            public_key: self.public_key.clone().unwrap().to_public_key_pem(rsa::pkcs8::LineEnding::LF).unwrap(),
            starting_hops: hops_start,
        };

        let cloves = GarlicCast::generate_cloves_rsa(proxy_info, proxy.public_key, 2, proxy.sequence_number, None);

        let agreement_1 = GarlicMessage::ProxyAgree {
            sequence_number: old_sequence,
            updated_sequence_number: proxy.sequence_number,
            hops: hops_start,
            clove: cloves[0].clone(),
        };

        let agreement_2 = GarlicMessage::ProxyAgree {
            sequence_number: old_sequence,
            updated_sequence_number: proxy.sequence_number,
            hops: hops_start,
            clove: cloves[1].clone(),
        };

        let n_1 = proxy.neighbor_1.node;
        let n_2 = proxy.neighbor_2.node;

        let socket = Arc::clone(&self.socket);

        {
            if let Err(e) = self.message_handler.send(&Arc::from(socket.clone()), self.local_node.clone(), &n_1.address, &GarlicMessage::build_send(self.local_node.clone(), agreement_1)).await {
                eprintln!("Failed to send Forward to {}: {:?}", n_1.address, e);
            }
        }

        let response;
        {
            response = self.message_handler.recv(200, &n_1.address).await;
        }

        {
            if let Err(e) = self.message_handler.send(&Arc::from(socket.clone()), self.local_node.clone(), &n_2.address, &GarlicMessage::build_send(self.local_node.clone(), agreement_2)).await {
                eprintln!("Failed to send Forward to {}: {:?}", n_2.address, e);
            }
        }

        let response2;
        {
            response2 = self.message_handler.recv(200, &n_2.address).await;
        }

        match response {
            Ok(_) => {
                match response2 {
                    Ok(_) => {
                        //println!("{} SENT ProxyAgree TO {} AND {}", self.local_node.address, n_2.address, n_1.address);
                    }
                    _ => {
                        println!("{} FAILED TO SEND ProxyAgree TO {} BUT SENT TO {}", self.local_node.address, n_2.address, n_1.address);
                        self.cache.remove_sequence(proxy.sequence_number);
                        self.cache.remove_sequence(old_sequence);
                    }
                }
            }
            _ => {
                match response2 {
                    Ok(_) => {
                        println!("{} FAILED TO SEND ProxyAgree TO {} BUT SENT TO {}", self.local_node.address, n_1.address, n_2.address);
                    }
                    _ => {
                        println!("{} FAILED TO SEND ProxyAgree TO {} AND {}", self.local_node.address, n_1.address, n_2.address);
                    }
                }

                self.cache.remove_sequence(proxy.sequence_number);
                self.cache.remove_sequence(old_sequence);
            }
        }
    }

    async fn accept_proxy(&mut self, sequence_number: U256, second_clove: Clove, node: Node) -> Option<Proxy> {
        let first_clove = self.cache.cloves.get(&sequence_number).unwrap().clone();
        let msg_from_initiator = GarlicCast::message_from_cloves_no_rsa(first_clove.clone().clove, second_clove.clone());

        if first_clove.from.id == node.id {
            println!("COULD NOT ACCEPT PROXY, RECEIVED FROM SAME NODE {}", node.address);
            self.cache.remove_clove(sequence_number);
            return None;
        }

        match msg_from_initiator {
            CloveMessage::RequestProxy { public_key, .. } => {
                let new_sequence = u256_random();
                let proxy = Proxy {
                    sequence_number: new_sequence,
                    neighbor_1: CloveNode { sequence_number: new_sequence, node: first_clove.from.clone() },
                    neighbor_2: CloveNode { sequence_number: new_sequence, node: node.clone() },
                    neighbor_1_hops: 0,
                    neighbor_2_hops: 0,
                    public_key: RsaPublicKey::from_public_key_pem(&*public_key).unwrap(),
                    used_last: Utc::now(),
                };

                self.initiators.push(proxy.clone());
                self.do_not_forward.insert(sequence_number, Utc::now());

                self.cache.insert_next_hop(CloveNode { sequence_number: new_sequence, node: node.clone() }, None);
                self.cache.insert_next_hop(CloveNode { sequence_number: new_sequence, node: first_clove.clone().from}, None);
                // Insert associations
                self.cache.insert_association(new_sequence, CloveNode { sequence_number: new_sequence, node: node.clone() });
                self.cache.insert_association(new_sequence, CloveNode { sequence_number: new_sequence, node: first_clove.from});
                // Insert seen last
                self.cache.seen(new_sequence);
                // Remove old clove
                self.cache.remove_clove(sequence_number);

                //println!("{} :: PROXY :: {}", Utc::now(), self.local_node.address);
                self.forward_proxy_accept(proxy.clone(), sequence_number).await;

                Some(proxy)
            },
            _ => {
                None
            }
        }
    }

    async fn find_alt(&mut self, n_1: Option<Node>, n_2: Option<Node>, sequence_number: U256) -> CloveNode {
        let alt_sequence_number = u256_random();
        let mut keep_trying = true;
        let mut alt = CloveNode {
            sequence_number: alt_sequence_number,
            node: Node { id: U256::from(0), address: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0) },
        };

        if n_1.is_none() && n_2.is_none() {
            return alt;
        }

        while keep_trying {
            // Basically just try the fuck out of some nodes until one responds with an IsAlive message
            let mut choose_list = self.known_nodes.clone();

            if let Some(n_1) = n_1.clone() {
                choose_list.retain(|n| *n != n_1.clone());
            }
            if let Some(n_2) = n_2.clone() {
                choose_list.retain(|n| *n != n_2.clone());
            }

            let forward_node = choose_list.remove(rand::random_range(0..choose_list.len()));

            let n_1_real;
            let n_2_real;
            if let Some(n_1) = n_1.clone() {
                n_1_real = n_1.clone();
            } else {
                n_1_real = choose_list.remove(rand::random_range(0..choose_list.len()));
            }
            if let Some(n_2) = n_2.clone() {
                n_2_real = n_2.clone();
            } else {
                n_2_real = choose_list.remove(rand::random_range(0..choose_list.len()));
            }

            let new_msg = GarlicMessage::RequestAlt {
                alt_sequence_number,
                next_hop: n_1_real.clone(),
                last_hop: n_2_real.clone(),
            };

            let socket = Arc::clone(&self.socket);

            {
                if let Err(e) = self.message_handler.send(&Arc::from(socket.clone()), self.local_node.clone(), &forward_node.address, &GarlicMessage::build_send(self.local_node.clone(), new_msg)).await {
                    eprintln!("Failed to send Forward to {}: {:?}", forward_node.address, e);
                }
            }

            let response;
            {
                response = self.message_handler.recv(200, &forward_node.address).await;
            }

            match response {
                Ok(gar_msg) => {
                    match gar_msg {
                        GarlemliaMessage::AgreeAlt { .. } => {
                            alt = CloveNode {
                                sequence_number: alt_sequence_number,
                                node: forward_node
                            };

                            self.cache.insert_my_alt_node(sequence_number, alt.clone());

                            keep_trying = false;
                        }
                        _ => {}
                    }
                }
                Err(_) => {}
            }
        }
        alt
    }

    async fn send_alt(&mut self, n_1: Option<CloveNode>, n_2: Option<CloveNode>, alt: CloveNode) {
        let socket = Arc::clone(&self.socket);
        let time = Utc::now();
        let mut n_1_success = false;

        if let Some(n_1) = n_1 {
            let new_msg = GarlicMessage::UpdateAlt {
                sequence_number: n_1.sequence_number,
                alt_node: alt.clone(),
            };

            {
                if let Err(e) = self.message_handler.send(&Arc::from(socket.clone()), self.local_node.clone(), &n_1.node.address, &GarlicMessage::build_send(self.local_node.clone(), new_msg.clone())).await {
                    eprintln!("Failed to send Forward to {}: {:?}", n_1.node.address, e);
                }
            }

            let response;
            {
                response = self.message_handler.recv(200, &n_1.node.address).await;
            }

            match response {
                Ok(_) => {
                    //println!("{} :: UPDATEALT {} :: {} -> {}", time, n_1.sequence_number, self.local_node.address, n_1.node.address);
                    n_1_success = true;
                }
                _ => {
                    println!("{} :: UPDATEALT {} :: FAILURE : OFFLINE :: {} -> {}", time, n_1.sequence_number, self.local_node.address, n_1.node.address);
                    n_1_success = self.replace_with_alt(n_1, new_msg.clone()).await.is_ok();
                }
            }
        }

        if !n_1_success {
            return;
        }

        if let Some(n_2) = n_2 {
            let new_msg = GarlicMessage::UpdateAlt {
                sequence_number: n_2.sequence_number,
                alt_node: alt.clone(),
            };

            {
                if let Err(e) = self.message_handler.send(&Arc::from(socket.clone()), self.local_node.clone(), &n_2.node.address, &GarlicMessage::build_send(self.local_node.clone(), new_msg.clone())).await {
                    eprintln!("Failed to send Forward to {}: {:?}", n_2.node.address, e);
                }
            }

            let response;
            {
                response = self.message_handler.recv(200, &n_2.node.address).await;
            }

            match response {
                Ok(_) => {
                    //println!("{} :: UPDATEALT {} :: {} -> {}", time, n_2.sequence_number, self.local_node.address, n_2.node.address);
                }
                _ => {
                    println!("{} :: UPDATEALT {} :: FAILURE : OFFLINE :: {} -> {}", time, n_2.sequence_number, self.local_node.address, n_2.node.address);
                    let _ = self.replace_with_alt(n_2, new_msg).await;
                }
            }
        }
    }

    async fn update_my_alt_next_or_last(&self, my_alt: CloveNode, node: Node, new_alt: Node) {
        let new_msg = GarlicMessage::UpdateAltNextOrLast {
            sequence_number: my_alt.sequence_number,
            old_node: node,
            new_node: new_alt.clone(),
        };

        let socket = Arc::clone(&self.socket);
        let time = Utc::now();

        {
            if let Err(e) = self.message_handler.send(&Arc::from(socket.clone()), self.local_node.clone(), &my_alt.node.address, &GarlicMessage::build_send(self.local_node.clone(), new_msg.clone())).await {
                eprintln!("Failed to send Forward to {}: {:?}", my_alt.node.address, e);
            }
        }

        let response;
        {
            response = self.message_handler.recv(200, &my_alt.node.address).await;
        }

        match response {
            Ok(_) => {
                //println!("{} :: UPDATEALTNEXTORLAST {} :: {} -> {}", time, my_alt.sequence_number, self.local_node.address, my_alt.node.address);
            }
            _ => {
                println!("{} :: UPDATEALTNEXTORLAST {} :: FAILURE : OFFLINE :: {} -> {}", time, my_alt.sequence_number, self.local_node.address, my_alt.node.address);
            }
        }
    }
    
    pub fn get_search_responses(&self) -> Vec<FileInfo> {
        let responses = self.requests_as_initiator.clone();
        
        let mut response_vec = vec![];
        for i in responses {
            for j in i.1.responses {
                match j {
                    CloveMessage::Response { data, .. } => {
                        match data {
                            GarlemliaResponse::FileName { name, file_type, size, categories, metadata_location, key_location } => {
                                response_vec.push(FileInfo::from(name, file_type, size, categories, metadata_location, key_location));
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
        
        response_vec
    }

    pub fn get_file_info_responses(&self) -> HashMap<U256, Vec<GarlemliaResponse>> {
        let responses = self.requests_as_initiator.clone();

        let mut response_hash = HashMap::new();
        for i in responses {
            response_hash.insert(i.0, vec![]);
            for j in i.1.responses {
                match j {
                    CloveMessage::Response { data, .. } => {
                        match data.clone() {
                            GarlemliaResponse::MetaData { .. } | GarlemliaResponse::FileKey { .. } => {
                                response_hash.get_mut(&i.0).unwrap().push(data);
                            }
                            _ => {}
                        }

                    }
                    _ => {}
                }
            }
        }

        response_hash
    }

    pub fn get_download_responses(&self) -> HashMap<U256, Vec<GarlemliaResponse>> {
        let responses = self.requests_as_initiator.clone();

        let mut response_hash = HashMap::new();
        for i in responses {
            response_hash.insert(i.0, vec![]);
            for j in i.1.responses {
                match j {
                    CloveMessage::Response { data, .. } => {
                        match data.clone() {
                            GarlemliaResponse::FileChunkInfo { .. } => {
                                response_hash.get_mut(&i.0).unwrap().push(data);
                            }
                            _ => {}
                        }

                    }
                    _ => {}
                }
            }
        }

        response_hash
    }
    
    async fn manage_proxy_message(&self, req: CloveMessage) -> Option<CloveMessage> {
        match req.clone() {
            CloveMessage::SearchOverlay { request_id, proxy_id, .. } => {
                println!("{} RECEIVED SEARCH REQUEST WITH ID {} PROXY ID: {}", self.local_node.address, request_id.request_id, proxy_id);
                Some(req)
            }
            CloveMessage::SearchGarlemlia { .. } => {
                Some(req)
            }
            CloveMessage::ResponseWithValidator { request_id, proxy_id, .. } => {
                // This only gets sent to the proxy of the responder to a request
                // The responder proxy uses ResponseDirect when sending the response
                // to the proxy of the initiator

                println!("{} RECEIVED RESPOND WITH VALIDATOR WITH ID {} PROXY ID: {}", self.local_node.address, request_id.request_id, proxy_id);
                Some(req)
            }
            CloveMessage::Store { .. } => {
                Some(req)
            }
            _ => {
                None
            }
        }
    }

    async fn send_search_to_known(&self, search_msg: GarlemliaMessage) {
        let known_nodes = self.known_nodes.clone();
        
        for node in known_nodes {
            {
                if let Err(e) = self.message_handler.send_no_recv(&Arc::clone(&self.socket), self.local_node.clone(), &node.address, &search_msg).await {
                    eprintln!("Failed to send SearchFile to {}: {:?}", node.address, e);
                }
            }
        }
    }

    // This gets called from Kademlia after it finishes processing potential
    // validator pool creations or searches
    pub async fn run_proxy_message(&mut self, req: CloveMessage, response: Option<GarlemliaResponse>) {
        match req.clone() {
            CloveMessage::SearchOverlay { request_id, proxy_id, public_key, search_term } => {
                let checked = self.searches_checked.contains(&request_id.request_id);

                if checked {
                    return;
                }

                let current_request = self.requests_as_proxy.get(&request_id.request_id).cloned();

                if response.is_some() {
                    let response_unwrapped = response.unwrap();
                    let proxy;
                    let cloves;

                    if current_request.is_some() {
                        proxy = current_request.unwrap().initiator.clone();

                        let msg = CloveMessage::Response {
                            request_id: request_id.clone(),
                            data: response_unwrapped
                        };

                        cloves = GarlicCast::generate_cloves_rsa(msg.clone(), RsaPublicKey::from_public_key_pem(&*public_key).unwrap(), 2, proxy.sequence_number, Some(CloveRequestID::new(request_id.request_id, 0)));
                    } else {
                        proxy = current_request.unwrap().initiator.clone();

                        let res_msg = CloveMessage::Response {
                            request_id: request_id.clone(),
                            data: response_unwrapped
                        };

                        let res_cloves = GarlicCast::generate_cloves_rsa(res_msg.clone(), RsaPublicKey::from_public_key_pem(&*public_key).unwrap(), 2, request_id.request_id, Some(CloveRequestID::new(request_id.request_id, 0)));

                        let msg = CloveMessage::ResponseWithValidator {
                            request_id: request_id.clone(),
                            proxy_id,
                            clove_1: res_cloves[0].clone(),
                            clove_2: res_cloves[1].clone()
                        };

                        cloves = GarlicCast::generate_cloves_rsa(msg.clone(), proxy.clone().public_key, 2, proxy.sequence_number, Some(CloveRequestID::new(u256_random(), 0)));
                    }

                    self.send_to_proxy(proxy, cloves).await;
                }

                let search_msg = GarlemliaMessage::SearchFile {
                    request_id: request_id.clone(),
                    proxy_id,
                    search_term,
                    public_key,
                    sender: self.local_node.clone(),
                };

                self.send_search_to_known(search_msg).await;

                self.searches_checked.insert(request_id.request_id);
            }
            CloveMessage::SearchGarlemlia { request_id, .. } => {
                let current_request = self.requests_as_proxy.get(&request_id.request_id).cloned();

                if current_request.is_some() {
                    let proxy = current_request.unwrap().initiator.clone();
                    
                    if response.is_none() {
                        return;
                    }
                    
                    let response_unwrapped = response.unwrap();

                    let msg = CloveMessage::Response {
                        request_id: request_id.clone(),
                        data: response_unwrapped
                    };

                    let cloves = GarlicCast::generate_cloves_rsa(msg.clone(), proxy.clone().public_key, 2, proxy.sequence_number, Some(CloveRequestID::new(request_id.request_id, 0)));
                    
                    self.send_to_proxy(proxy, cloves).await;
                }

                self.requests_as_proxy.remove(&request_id.request_id);
            }
            CloveMessage::ResponseWithValidator { request_id, clove_1, clove_2, .. } => {
                if response.is_none() {
                    return;
                }
                
                let msg = GarlicMessage::ResponseDirect {
                    request_id,
                    clove_1,
                    clove_2,
                };
                
                match response.unwrap() {
                    GarlemliaResponse::Validator { proxy } => {
                        println!("{} RECEIVED RESPOND WITH VALIDATOR AND SENDING TO {}", self.local_node.address, proxy.unwrap());
                        {
                            if let Err(e) = self.message_handler.send_no_recv(&Arc::clone(&self.socket), self.local_node.clone(), &proxy.unwrap(), &GarlicMessage::build_send(self.local_node.clone(), msg)).await {
                                eprintln!("Failed to send IsAlive to {}: {:?}", proxy.unwrap(), e);
                            }
                        }
                    }
                    _ => {}
                }
            }
            CloveMessage::Store { request_id, .. } => {
                self.requests_as_proxy.remove(&request_id.request_id);
            }
            _ => {}
        }
    }

    pub async fn recv(&mut self, node: Node, garlic_msg: GarlicMessage) -> Result<Option<CloveMessage>, MessageError> {
        let socket = Arc::clone(&self.socket);
        match garlic_msg.clone() {
            GarlicMessage::FindProxy { sequence_number, clove } => {
                {
                    if let Err(e) = self.message_handler.send_no_recv(&Arc::from(socket), self.local_node.clone(), &node.address, &GarlicMessage::build_send_is_alive(self.local_node.clone())).await {
                        eprintln!("Failed to send IsAlive to {}: {:?}", node.address, e);
                    }
                }

                //println!("{} :: FINDPROXY {}[{}] :: {} -> {}", Utc::now(), sequence_number, clove.index, node.address, self.local_node.address);

                let no_forward = self.do_not_forward.contains_key(&sequence_number);

                if no_forward {
                    //println!("{} :: NOT FORWARDING - INITIATOR OR PROXY {}[{}] :: {}", Utc::now(), sequence_number, clove.index, self.local_node.address);
                    return Ok(None);
                }

                let mut same_clove = false;
                let clove_data = self.cache.cloves.clone();
                let mut old_node = None;

                for item in clove_data {
                    if item.1.clove == clove {
                        same_clove = true;
                        old_node = Some(item.1.from.clone());
                        break;
                    }
                }

                let mut node_actual = node.clone();
                let msg = clove.clone();
                if same_clove {
                    // Received the exact same clove twice
                    // Set the 'from' node to the old node since it is a shorter path
                    //println!("{} :: SAME CLOVE {}[{}] :: {}", Utc::now(), sequence_number, clove.index, self.local_node.address);
                    node_actual = old_node.unwrap();
                }

                self.cache.seen(sequence_number);

                if self.cache.cloves.contains_key(&sequence_number) && !same_clove {
                    let new_proxy = self.accept_proxy(sequence_number, clove, node_actual).await.unwrap();

                    let new_alt = self.find_alt(Some(node.clone()), None, new_proxy.sequence_number).await;
                    self.send_alt(Some(CloveNode { node, sequence_number: new_proxy.sequence_number }), None, new_alt).await;
                } else if random_bool(FORWARD_P) {
                    // First time seeing this sequence number and forwarding it
                    self.forward_find_proxy(sequence_number, node_actual.clone(), msg.clone()).await;
                } else {
                    //println!("{} :: NOT FORWARDING {}[{}] :: {}", Utc::now(), sequence_number, clove.index, self.local_node.address);
                    // Not forwarding, but still add to own cache
                    let original_clove = CloveNode { sequence_number, node: node_actual.clone() };
                    self.cache.insert_next_hop(original_clove.clone(), None);
                    // Insert clove
                    self.cache.insert_clove(msg.clone(), node_actual.clone());
                    // Insert associations
                    self.cache.insert_association(sequence_number, original_clove.clone());
                    // Insert seen last
                    self.cache.seen(sequence_number);
                }
                Ok(None)
            }
            GarlicMessage::Forward { sequence_number, clove } => {
                {
                    if let Err(e) = self.message_handler.send_no_recv(&Arc::from(socket), self.local_node.clone(), &node.address, &GarlicMessage::build_send_is_alive(self.local_node.clone())).await {
                        eprintln!("Failed to send IsAlive to {}: {:?}", node.address, e);
                    }
                }

                println!("{} :: FORWARD {}[{}] :: {} -> {}", Utc::now(), sequence_number, clove.index, node.address, self.local_node.address);

                let msg = clove.clone();
                let mut next = self.cache.get_forward_node(CloveNode { sequence_number, node: node.clone() });
                let am_alt = self.cache.am_alt_for.contains(&sequence_number);
                self.cache.seen(sequence_number);

                if next.is_err() {
                    let try_clove_node = CloveNode { sequence_number, node: node.clone() };
                    let sequence_try = self.cache.alt_to_sequence.get(&try_clove_node).cloned();
                    if sequence_try.is_some() {
                        let old_node = self.cache.get_old_from_alt(&try_clove_node);

                        if old_node.is_some() {
                            let mut from_initiator = None;
                            let mut old_initiator = None;
                            let mut from_proxy = None;
                            let mut old_proxy = None;
                            {
                                let proxies = self.proxies.clone();
                                let initiators = self.initiators.clone();

                                for proxy in proxies {
                                    if proxy.sequence_number == sequence_try.unwrap() {
                                        let mut test_proxy = proxy.clone();
                                        if proxy.neighbor_1 == old_node.clone().unwrap() {
                                            test_proxy.neighbor_1 = try_clove_node.clone();
                                        } else if proxy.neighbor_2 == old_node.clone().unwrap() {
                                            test_proxy.neighbor_2 = try_clove_node.clone();
                                        }

                                        from_proxy = Some(test_proxy);
                                        old_proxy = Some(proxy.clone());
                                    }
                                }

                                for proxy in initiators {
                                    if proxy.sequence_number == sequence_try.unwrap() {
                                        let mut test_proxy = proxy.clone();
                                        if proxy.neighbor_1 == old_node.clone().unwrap() {
                                            test_proxy.neighbor_1 = try_clove_node.clone();
                                        } else if proxy.neighbor_2 == old_node.clone().unwrap() {
                                            test_proxy.neighbor_2 = try_clove_node.clone();
                                        }

                                        from_initiator = Some(test_proxy);
                                        old_initiator = Some(proxy.clone());
                                    }
                                }
                            }

                            if from_proxy.is_some() {
                                self.replace_proxy(&old_proxy.unwrap(), &from_proxy.unwrap());
                            }

                            if from_initiator.is_some() {
                                self.replace_proxy(&old_initiator.unwrap(), &from_initiator.unwrap());
                            }

                            self.cache.replace_with_alt_node(&old_node.clone().unwrap());
                            next = self.cache.get_forward_node(try_clove_node);

                            if next.is_ok() {
                                let my_alt_for_seq = self.cache.my_alt_nodes.get(&sequence_try.unwrap()).cloned();

                                if my_alt_for_seq.is_some() {
                                    self.send_alt(Some(CloveNode { node: node.clone(), sequence_number }), None, my_alt_for_seq.clone().unwrap()).await;
                                    self.update_my_alt_next_or_last(my_alt_for_seq.unwrap(), old_node.unwrap().node, node.clone()).await;
                                }
                            }
                        }
                    }
                }

                let mut sn_actual = sequence_number.clone();
                {
                    let check_sn = self.cache.get_sequence_from_alt(CloveNode { sequence_number, node: node.clone() });
                    match check_sn {
                        Some(new_sequence) => {
                            sn_actual = new_sequence.clone();
                        }
                        None => {}
                    }
                }

                match next {
                    Ok(info) => {
                        match info {
                            Some(next_node) => {
                                if am_alt {
                                    let new_alt = self.find_alt(Some(node.clone()), Some(next_node.node.clone()), sn_actual).await;
                                    self.send_alt(Some(CloveNode { node, sequence_number }), Some(next_node.clone()), new_alt).await;

                                    self.cache.am_alt_for.remove(&sequence_number);
                                }
                                self.forward(&next_node, &msg).await;
                                Ok(None)
                            }
                            None => {
                                // Receive message part from proxy or from initiator
                                let messages_from;
                                {
                                    let msg = self.collected_messages.get(&clove.request_id);

                                    if let Some(message) = msg {
                                        messages_from = vec![message.clone(), garlic_msg.clone()];
                                    } else {
                                        self.collected_messages.insert(clove.request_id.clone(), garlic_msg.clone());
                                        messages_from = vec![garlic_msg];
                                    }
                                }

                                if messages_from.len() == 2 {
                                    // Has second portion of the message already
                                    let cloves = vec![messages_from[0].clove().unwrap(), messages_from[1].clove().unwrap()];

                                    if cloves.len() == 2 {
                                        println!("{} :: UNWRAPPING", self.local_node.address);
                                        let msg_from_initiator = GarlicCast::message_from_cloves_rsa(cloves[0].clone(), cloves[1].clone(), self.private_key.clone().unwrap());

                                        if msg_from_initiator.is_request() {
                                            let request_info = self.requests_as_initiator.get_mut(&msg_from_initiator.request_id().unwrap().request_id);

                                            if request_info.is_some() {
                                                // THIS NODE IS THE INITIATOR, NOT THE PROXY
                                                let proxy_request = request_info.unwrap();

                                                let mut trimmed_msg = msg_from_initiator.clone();
                                                match msg_from_initiator.clone() {
                                                    CloveMessage::Response { data, .. } => {
                                                        match data {
                                                            GarlemliaResponse::FileChunk { chunk_id, chunk_size, .. } => {
                                                                trimmed_msg = CloveMessage::Response {
                                                                    request_id: msg_from_initiator.request_id().unwrap(),
                                                                    data: GarlemliaResponse::FileChunkInfo {
                                                                        chunk_id,
                                                                        chunk_size,
                                                                    }
                                                                }
                                                            }
                                                            _ => {}
                                                        }
                                                    }
                                                    _ => {}
                                                }

                                                proxy_request.responses.push(trimmed_msg.clone());

                                                self.collected_messages.remove(&clove.request_id);

                                                println!("{} :: CLOVEMESSAGE :: {} :: {:?}", Utc::now(), self.local_node.address, trimmed_msg.clone());
                                                return Ok(Some(msg_from_initiator));
                                            } else {
                                                // THIS NODE IS THE PROXY, NOT THE INITIATOR
                                                let initiator;
                                                {
                                                    let initiator_check = self.get_initiator(sn_actual);
                                                    if initiator_check.is_some() {
                                                        initiator = initiator_check.unwrap();
                                                    } else {
                                                        return Err(MessageError::MissingNode);
                                                    }
                                                }

                                                let self_proxy_id = msg_from_initiator.proxy_id();
                                                let mut validator_required = false;
                                                if self_proxy_id.is_some() {
                                                    validator_required = true;
                                                }

                                                self.requests_as_proxy.insert(msg_from_initiator.request_id().unwrap().request_id, ProxyRequest {
                                                    sequence_number: sn_actual,
                                                    request_id: msg_from_initiator.request_id().unwrap().request_id,
                                                    self_proxy_id,
                                                    validator_required,
                                                    initiator,
                                                    sent: Utc::now(),
                                                    request: msg_from_initiator.clone()
                                                });

                                                self.collected_messages.remove(&clove.request_id);
                                                
                                                //println!("{} :: CLOVEMESSAGE :: {} :: {:?}", Utc::now(), self.local_node.address, msg_from_initiator);
                                                return Ok(self.manage_proxy_message(msg_from_initiator).await);
                                            }
                                        } else {
                                            // Big failure
                                            println!("{}: This should not happen: GarlicCast::recv::Forward():1", self.local_node.address);
                                        }
                                    } else {
                                        // Big failure
                                        println!("{}: This should not happen: GarlicCast::recv::Forward():2", self.local_node.address);
                                    }
                                }
                                Ok(None)
                            }
                        }
                    }
                    Err(_) => {
                        println!("{} :: COULD NOT FIND ANYWHERE TO FORWARD THIS AND I AM NOT AN INITIATOR OR PROXY :: {}", Utc::now(), self.local_node.address);
                        Ok(None)
                    }
                }
            }
            GarlicMessage::ProxyAgree { sequence_number, updated_sequence_number, hops, clove } => {
                {
                    if let Err(e) = self.message_handler.send_no_recv(&Arc::from(socket.clone()), self.local_node.clone(), &node.address, &GarlicMessage::build_send_is_alive(self.local_node.clone())).await {
                        eprintln!("Failed to send IsAlive to {}: {:?}", node.address, e);
                    }
                }

                //println!("{} :: PROXYAGREE {}[{}] :: {} -> {}", Utc::now(), updated_sequence_number, clove.index, node.address, self.local_node.address);

                //println!("{} GOT ProxyAgree FROM {}", self.local_node.address, node.address);

                let old_clove_node = CloveNode { sequence_number, node: node.clone() };

                self.cache.update_sequence_number(updated_sequence_number, old_clove_node.clone());

                let new_proxy_agree = GarlicMessage::ProxyAgree {
                    sequence_number,
                    updated_sequence_number,
                    hops: hops + 1,
                    clove: clove.clone(),
                };

                let next = self.cache.get_forward_node(CloveNode { sequence_number: updated_sequence_number, node: node.clone() });
                self.cache.seen(sequence_number);
                self.cache.seen(updated_sequence_number);

                match next {
                    Ok(info) => {
                        match info {
                            Some(next_node) => {
                                // Has next node
                                {
                                    if let Err(e) = self.message_handler.send(&Arc::from(socket), self.local_node.clone(), &next_node.node.address, &GarlicMessage::build_send(self.local_node.clone(), new_proxy_agree)).await {
                                        eprintln!("Failed to send Forward to {}: {:?}", next_node.node.address, e);
                                    }
                                }

                                let response;
                                {
                                    response = self.message_handler.recv(200, &next_node.node.address).await;
                                }

                                match response {
                                    Ok(_) => {
                                        let new_alt = self.find_alt(Some(node.clone()), Some(next_node.node.clone()), updated_sequence_number).await;
                                        self.send_alt(Some(CloveNode { node, sequence_number: updated_sequence_number }), Some(next_node), new_alt).await;
                                    }
                                    _ => {
                                        println!("{} FAILED TO SEND TO {}", self.local_node.address, next_node.node.address);
                                        // Failed to send to forward node, remove all content
                                        self.cache.remove_sequence(sequence_number);
                                        self.cache.remove_sequence(updated_sequence_number);
                                    }
                                }
                            }
                            _ => {
                                let new_alt;
                                {
                                    new_alt = self.find_alt(Some(node.clone()), None, updated_sequence_number).await;
                                    self.send_alt(Some(CloveNode { node: node.clone(), sequence_number: updated_sequence_number }), None, new_alt).await;
                                }

                                let messages_from;
                                let msg = self.collected_messages.get(&clove.request_id);

                                if let Some(message) = msg {
                                    messages_from = vec![message.clone(), garlic_msg.clone()];
                                } else {
                                    self.collected_messages.insert(clove.request_id.clone(), garlic_msg.clone());
                                    messages_from = vec![garlic_msg];
                                }

                                if messages_from.len() == 2 {
                                    // Has second portion of the ProxyAgree already
                                    let mut cloves = vec![clove.clone()];
                                    let mut neighbor_1_hops = 0;
                                    match messages_from[0].clone() {
                                        GarlicMessage::ProxyAgree { hops, clove, .. } => {
                                            neighbor_1_hops = hops;
                                            cloves.push(clove);
                                        }
                                        _ => {}
                                    }

                                    if cloves.len() == 2 {
                                        let pp_removed = self.partial_proxies.remove(&updated_sequence_number);
                                        if let Some(neighbor_1) = pp_removed {
                                            let msg_from_initiator = GarlicCast::message_from_cloves_rsa(cloves[0].clone(), cloves[1].clone(), self.private_key.clone().unwrap());

                                            match msg_from_initiator {
                                                CloveMessage::ProxyInfo { public_key, starting_hops} => {
                                                    let proxy = Proxy {
                                                        sequence_number: updated_sequence_number,
                                                        neighbor_1: CloveNode { sequence_number: updated_sequence_number, node: neighbor_1 },
                                                        neighbor_2: CloveNode { sequence_number: updated_sequence_number, node: node.clone() },
                                                        neighbor_1_hops: neighbor_1_hops - starting_hops,
                                                        neighbor_2_hops: hops - starting_hops,
                                                        public_key: RsaPublicKey::from_public_key_pem(&*public_key).unwrap(),
                                                        used_last: Utc::now(),
                                                    };

                                                    self.proxies.push(proxy.clone());
                                                    self.collected_messages.remove(&clove.request_id);

                                                    //println!("{} :: PROXY RECEIVED :: {} :: #{} -> #{} :: n_1: {}, n_2: {}", Utc::now(), self.local_node.address, sequence_number, updated_sequence_number, proxy.neighbor_1_hops, proxy.neighbor_2_hops);
                                                }
                                                _ => {
                                                    // Big failure
                                                    println!("{}: This should not happen: GarlicCast::recv::ProxyAgree():1", self.local_node.address);
                                                }
                                            }
                                        } else {
                                            // Big failure
                                            println!("{}: This should not happen: GarlicCast::recv::ProxyAgree():2", self.local_node.address);
                                        }

                                    } else {
                                        // Big failure
                                        println!("{}: This should not happen: GarlicCast::recv::ProxyAgree():3", self.local_node.address);
                                    }
                                } else {
                                    self.partial_proxies.insert(updated_sequence_number, node);
                                }
                            }
                        }
                    }
                    _ => {
                        // Big failure
                        println!("{} FOR {}: This should not happen: GarlicCast::recv::ProxyAgree():4", self.local_node.address, sequence_number);
                    }
                }

                Ok(None)
            }
            GarlicMessage::RequestAlt { alt_sequence_number, last_hop, next_hop } => {
                // TODO: Include some logic so that this node can decide to be an alternate or backup node
                // For now, just add it

                let lh_clove = CloveNode { sequence_number: alt_sequence_number, node: last_hop.clone() };
                let nh_clove = CloveNode { sequence_number: alt_sequence_number, node: next_hop.clone() };

                self.cache.insert_next_hop(lh_clove.clone(), Some(nh_clove.clone()));
                self.cache.insert_next_hop(nh_clove.clone(), Some(lh_clove.clone()));
                // Insert associations
                self.cache.insert_association(alt_sequence_number, lh_clove.clone());
                self.cache.insert_association(alt_sequence_number, nh_clove.clone());
                // Insert am alt for
                self.cache.insert_am_alt(alt_sequence_number);
                // Insert seen last
                self.cache.seen(alt_sequence_number);

                let agree_alt = GarlemliaMessage::AgreeAlt {
                    alt_sequence_number,
                    sender: self.local_node.clone(),
                };

                {
                    if let Err(e) = self.message_handler.send_no_recv(&Arc::from(socket), self.local_node.clone(), &node.address, &agree_alt).await {
                        eprintln!("Failed to send Forward to {}: {:?}", node.address, e);
                    }
                }

                Ok(None)
            }
            GarlicMessage::RefreshAlt { sequence_number } => {
                {
                    if let Err(e) = self.message_handler.send_no_recv(&Arc::from(socket.clone()), self.local_node.clone(), &node.address, &GarlicMessage::build_send_is_alive(self.local_node.clone())).await {
                        eprintln!("Failed to send IsAlive to {}: {:?}", node.address, e);
                    }
                }

                self.cache.seen(sequence_number);

                Ok(None)
            }
            GarlicMessage::UpdateAlt { sequence_number, alt_node } => {
                {
                    if let Err(e) = self.message_handler.send_no_recv(&Arc::from(socket.clone()), self.local_node.clone(), &node.address, &GarlicMessage::build_send_is_alive(self.local_node.clone())).await {
                        eprintln!("Failed to send IsAlive to {}: {:?}", node.address, e);
                    }
                }

                let clove_node = CloveNode { sequence_number, node };

                self.cache.insert_alt_node(clove_node.clone(), alt_node.clone());

                Ok(None)
            }
            GarlicMessage::UpdateAltNextOrLast { sequence_number, old_node, new_node } => {
                {
                    if let Err(e) = self.message_handler.send_no_recv(&Arc::from(socket.clone()), self.local_node.clone(), &node.address, &GarlicMessage::build_send_is_alive(self.local_node.clone())).await {
                        eprintln!("Failed to send IsAlive to {}: {:?}", node.address, e);
                    }
                }

                self.cache.seen(sequence_number);

                let old_clove_node = CloveNode { sequence_number, node: old_node.clone() };
                let new_clove_node = CloveNode { sequence_number, node: new_node.clone() };

                if self.cache.am_alt_for.contains(&sequence_number) {
                    self.cache.insert_alt_node(old_clove_node.clone(), new_clove_node.clone());
                    self.cache.replace_with_alt_node(&old_clove_node);
                }

                Ok(None)
            }
            GarlicMessage::ResponseDirect { request_id, clove_1, clove_2 } => {
                let current_request = self.requests_as_proxy.get(&request_id.request_id).cloned();

                if current_request.is_some() {
                    let proxy = current_request.unwrap().initiator.clone();

                    self.send_to_proxy(proxy, vec![clove_1, clove_2]).await;
                }
                
                Ok(None)
            }
        }
    }
}