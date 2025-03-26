use crate::garlemlia_structs::garlemlia_structs;
use crate::simulator::simulator::{get_global_socket, SimulatedMessageHandler};
use aes::Aes256;
use bincode;
use chrono::{DateTime, Utc};
use cipher::generic_array::GenericArray;
use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use garlemlia_structs::{Clove, CloveData, CloveMessage, CloveNode, GMessage, GarlemliaMessage, GarlicMessage, MessageError, Node};
use rand::random_bool;
use rand::seq::IndexedRandom;
use rand::{rng, RngCore};
use reed_solomon_erasure::galois_8::ReedSolomon;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::sha2::Digest;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::cmp::PartialEq;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use primitive_types::U256;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use crate::garlemlia_structs::garlemlia_structs::u256_random;

pub const FORWARD_P: f64 = 0.95;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CloveCache {
    cloves: HashMap<U256, CloveData>,
    next_hop: HashMap<CloveNode, Option<CloveNode>>,
    alt_nodes: HashMap<CloveNode, CloveNode>,
    alt_to_sequence: HashMap<CloveNode, U256>,
    associations: HashMap<U256, Vec<CloveNode>>,
    seen_last: HashMap<U256, DateTime<Utc>>,
    my_alt_nodes: HashMap<U256, CloveNode>
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
            my_alt_nodes: HashMap::new()
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

    pub fn insert_alt_node(&mut self, node: CloveNode, alt_node: CloveNode) {
        self.alt_nodes.insert(node.clone(), alt_node.clone());
        self.alt_to_sequence.insert(alt_node.clone(), node.sequence_number);

        self.insert_association(node.sequence_number, alt_node);
    }

    pub fn remove_alt_node(&mut self, node: CloveNode) {
        self.alt_nodes.remove(&node);
        self.alt_to_sequence.remove(&node);
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

    pub fn replace_with_alt_node(&mut self, sequence_number: U256, node: Node) -> Option<CloveNode> {
        let old_clove_node = CloveNode { sequence_number, node };
        let new_clove_node = self.alt_nodes.remove(&old_clove_node);

        match new_clove_node {
            Some(new_clove_node) => {
                let forward_clove_node = self.next_hop.remove(&old_clove_node).unwrap();

                self.next_hop.insert(new_clove_node.clone(), forward_clove_node.clone());

                match forward_clove_node {
                    Some(forward_clove_node) => {
                        self.next_hop.insert(forward_clove_node, Some(new_clove_node.clone()));
                    }
                    _ => {}
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
pub struct SerializableProxyRequest {
    request_id: U256,
    validator_required: bool,
    proxies: Vec<SerializableProxy>,
    proxy_id_associations: HashMap<U256, SerializableProxy>,
    responses: Vec<CloveMessage>
}

impl SerializableProxyRequest {
    pub fn from(proxy_request: ProxyRequest) -> SerializableProxyRequest {
        SerializableProxyRequest {
            request_id: proxy_request.request_id,
            validator_required: proxy_request.validator_required,
            proxies: SerializableProxy::vec_to_serializable(proxy_request.proxies),
            proxy_id_associations: SerializableProxy::hashmap_to_serializable(proxy_request.proxy_id_associations),
            responses: proxy_request.responses
        }
    }

    pub fn to_proxy_request(self) -> ProxyRequest {
        ProxyRequest {
            request_id: self.request_id,
            validator_required: self.validator_required,
            proxies: SerializableProxy::vec_to_proxy(self.proxies),
            proxy_id_associations: SerializableProxy::hashmap_to_proxy(self.proxy_id_associations),
            responses: self.responses
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyRequest {
    request_id: U256,
    validator_required: bool,
    proxies: Vec<Proxy>,
    proxy_id_associations: HashMap<U256, Proxy>,
    responses: Vec<CloveMessage>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableGarlicCast {
    local_node: Node,
    pub known_nodes: Vec<Node>,
    proxies: Vec<SerializableProxy>,
    initiators: Vec<SerializableProxy>,
    partial_proxies: HashMap<U256, Node>,
    cache: CloveCache,
    collected_messages: HashMap<U256, Vec<GarlicMessage>>,
    requests: HashMap<U256, SerializableProxyRequest>,
    pub starting_hops: HashMap<U256, u8>,
    pub public_key: String,
    pub private_key: String
}

impl SerializableGarlicCast {
    pub async fn from(garlic: GarlicCast) -> SerializableGarlicCast {
        SerializableGarlicCast {
            local_node: garlic.local_node.clone(),
            known_nodes: garlic.known_nodes.lock().await.clone(),
            proxies: SerializableProxy::vec_to_serializable(garlic.proxies.lock().await.clone()),
            initiators: SerializableProxy::vec_to_serializable(garlic.initiators.lock().await.clone()),
            partial_proxies: garlic.partial_proxies.lock().await.clone(),
            cache: garlic.cache.lock().await.clone(),
            collected_messages: garlic.collected_messages.lock().await.clone(),
            requests: SerializableProxyRequest::hashmap_to_serializable(garlic.requests.lock().await.clone()),
            starting_hops: garlic.starting_hops.clone(),
            public_key: garlic.public_key.unwrap().to_public_key_pem(rsa::pkcs8::LineEnding::LF).unwrap(),
            private_key: garlic.private_key.unwrap().to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap().to_string()
        }
    }

    pub fn to_garlic(self) -> GarlicCast {
        GarlicCast {
            socket: get_global_socket().unwrap(),
            local_node: self.local_node,
            message_handler: Arc::new(SimulatedMessageHandler::create(0)),
            known_nodes: Arc::new(Mutex::new(self.known_nodes)),
            proxies: Arc::new(Mutex::new(SerializableProxy::vec_to_proxy(self.proxies.clone()))),
            initiators: Arc::new(Mutex::new(SerializableProxy::vec_to_proxy(self.initiators.clone()))),
            partial_proxies: Arc::new(Mutex::new(self.partial_proxies)),
            cache: Arc::new(Mutex::new(self.cache)),
            collected_messages: Arc::new(Mutex::new(self.collected_messages)),
            requests: Arc::new(Mutex::new(SerializableProxyRequest::hashmap_to_proxy_request(self.requests))),
            starting_hops: self.starting_hops,
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
    known_nodes: Arc<Mutex<Vec<Node>>>,
    proxies: Arc<Mutex<Vec<Proxy>>>,
    initiators: Arc<Mutex<Vec<Proxy>>>,
    partial_proxies: Arc<Mutex<HashMap<U256, Node>>>,
    cache: Arc<Mutex<CloveCache>>,
    collected_messages: Arc<Mutex<HashMap<U256, Vec<GarlicMessage>>>>,
    requests: Arc<Mutex<HashMap<U256, ProxyRequest>>>,
    starting_hops: HashMap<U256, u8>,
    public_key: Option<RsaPublicKey>,
    private_key: Option<RsaPrivateKey>
}

impl GarlicCast {
    pub fn new(socket: Arc<UdpSocket>, local_node: Node, message_handler: Arc<Box<dyn GMessage>>, known_nodes: Vec<Node>, public_key: Option<RsaPublicKey>, private_key: Option<RsaPrivateKey>) -> GarlicCast {
        GarlicCast {
            socket,
            local_node,
            message_handler,
            known_nodes: Arc::new(Mutex::new(known_nodes)),
            proxies: Arc::new(Mutex::new(Vec::new())),
            initiators: Arc::new(Mutex::new(Vec::new())),
            partial_proxies: Arc::new(Mutex::new(HashMap::new())),
            cache: Arc::new(Mutex::new(CloveCache::new())),
            collected_messages: Arc::new(Mutex::new(HashMap::new())),
            requests: Arc::new(Mutex::new(HashMap::new())),
            starting_hops: HashMap::new(),
            public_key,
            private_key
        }
    }

    pub async fn set_public_key(&mut self, public_key: RsaPublicKey) {
        self.public_key = Some(public_key);
    }

    pub async fn set_private_key(&mut self, private_key: RsaPrivateKey) {
        self.private_key = Some(private_key);
    }

    pub async fn update_from(&mut self, gc: GarlicCast) {
        self.socket =  gc.socket.clone();
        self.local_node = gc.local_node.clone();
        self.message_handler = gc.message_handler.clone();
        self.known_nodes = gc.known_nodes.clone();
        self.proxies = gc.proxies.clone();
        self.cache = gc.cache.clone();
        self.collected_messages = gc.collected_messages.clone();
        self.public_key = gc.public_key.clone();
        self.private_key = gc.private_key.clone();
        self.starting_hops = gc.starting_hops.clone();
    }

    pub async fn update_known(&self, nodes: Vec<Node>) {
        let mut known_nodes = self.known_nodes.lock().await;
        known_nodes.extend(nodes);
        known_nodes.sort_by_key(|n| n.id);
        known_nodes.dedup();
        known_nodes.retain(|n| *n != self.local_node);
    }

    pub async fn set_known(&self, nodes: Vec<Node>) {
        let mut known_nodes = self.known_nodes.lock().await;
        known_nodes.clear();
        known_nodes.extend(nodes);
    }

    async fn in_cache(&self, sequence_number: U256) -> bool {
        let cache = self.cache.lock().await;
        let cache_info = cache.cloves.get(&sequence_number);

        if let Some(_) = cache_info {
            return true;
        }

        false
    }

    pub async fn get_proxies(&self) -> Vec<Proxy> {
        self.proxies.lock().await.clone()
    }

    pub async fn discover_proxies(&self, count: u8) {
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
            known_nodes = self.known_nodes.lock().await.clone();
        }

        let cloves = Arc::new(Mutex::new(GarlicCast::generate_cloves_no_rsa(msg, count_actual, sequence_number)));

        let mut total_sent = 0;
        while total_sent < count_actual {
            let mut tasks = Vec::new();

            for _ in 0..count_actual - total_sent {
                let socket = Arc::clone(&self.socket);
                let message_handler = Arc::clone(&self.message_handler);
                let local_node = self.local_node.clone();
                let temp_node = known_nodes.remove(rand::random_range(0..known_nodes.len()));
                let cloves_inside = Arc::clone(&cloves);
                let clove = cloves.lock().await.pop().unwrap();

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
                            cloves_inside.lock().await.insert(0, clove);
                            Err(temp_node)
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

                                let mut cache = self.cache.lock().await;
                                cache.insert_next_hop(new_clove.clone(), None);
                                // Insert associations
                                cache.insert_association(sequence_number, new_clove.clone());
                                // Insert seen last
                                cache.seen(sequence_number);
                                total_sent += 1;
                            }
                            Err(e) => {
                                self.known_nodes.lock().await.retain(|x| *x != e);
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

    fn clove_generator(msg_serialized: Vec<u8>, count: u8, sequence_number: U256, recipient_pub_key: Option<RsaPublicKey>) -> Vec<Clove> {
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

    pub fn generate_cloves_no_rsa(msg: CloveMessage, count: u8, sequence_number: U256) -> Vec<Clove> {
        // Serialize message into bytes
        let msg_serialized = bincode::serialize(&msg).unwrap();

        GarlicCast::clove_generator(msg_serialized, count, sequence_number, None)
    }

    pub fn generate_cloves_rsa(msg: CloveMessage, recipient_pub_k: RsaPublicKey, count: u8, sequence_number: U256) -> Vec<Clove> {
        // Serialize message into bytes
        let msg_serialized = bincode::serialize(&msg).unwrap();

        GarlicCast::clove_generator(msg_serialized, count, sequence_number, Some(recipient_pub_k))
    }

    async fn use_alternate_proxy_node(cache: Arc<Mutex<CloveCache>>,
                                      proxies: Arc<Mutex<Vec<Proxy>>>,
                                      message_handler:  Arc<Box<dyn GMessage>>,
                                      socket: Arc<UdpSocket>,
                                      local_node: Node,
                                      difficult_node: Node,
                                      proxy: Proxy,
                                      mut msg: GarlicMessage) -> Result<Proxy, ()> {
        let alt_info;
        {
            alt_info = cache.lock().await.replace_with_alt_node(proxy.clone().sequence_number, difficult_node.clone());
        }

        let alt;
        let alt_clove_node;
        match alt_info {
            Some(alt_node) => {
                alt = alt_node.clone().node;
                msg.update_sequence_number(alt_node.sequence_number);
                alt_clove_node = alt_node;
            }
            None => {
                return Err(());
            }
        }

        {
            if let Err(e) = message_handler.send(&Arc::from(socket.clone()), local_node.clone(), &alt.address, &GarlicMessage::build_send(local_node.clone(), msg)).await {
                eprintln!("Failed to send Forward to {}: {:?}", alt.address, e);
            }
        }

        let response;
        {
            response = message_handler.recv(200, &alt.address).await;
        }

        match response {
            Ok(_) => {
                let mut new_proxy = proxy.clone();

                if new_proxy.neighbor_1.node.id == difficult_node.id {
                    new_proxy.neighbor_1 = alt_clove_node;
                } else if new_proxy.neighbor_2.node.id == difficult_node.id {
                    new_proxy.neighbor_2 = alt_clove_node;
                } else {
                    return Err(());
                }

                {
                    let mut proxies = proxies.lock().await;
                    proxies.retain(|p| p != &proxy);
                    proxies.push(new_proxy.clone());
                }

                Ok(new_proxy)
            }
            _ => {
                Err(())
            }
        }
    }

    pub async fn send_search_overlay(&self, req: String, proxy_id_pool: Vec<U256>, count: u8) {
        let mut count_actual = count;
        if  count < 2 {
            count_actual = 2;
        }

        let request_id = u256_random();
        let mut proxy_request = ProxyRequest {
            request_id,
            validator_required: true,
            proxies: vec![],
            proxy_id_associations: HashMap::new(),
            responses: vec![],
        };

        let proxies_init;
        {
            proxies_init = self.proxies.lock().await.clone();
        }

        let mut proxies = vec![];
        for proxy in proxies_init {
            if proxy_id_pool.contains(&proxy.sequence_number) {
                proxies.push(proxy);
            }
        }

        let mut total_sent = 0;
        while total_sent < count_actual {
            let mut tasks = Vec::new();

            for _ in 0..count_actual - total_sent {
                let proxy_id = u256_random();
                let msg = CloveMessage::SearchOverlay {
                    request_id,
                    proxy_id,
                    search_term: req.clone(),
                    public_key: self.public_key.clone().unwrap().to_public_key_pem(rsa::pkcs8::LineEnding::LF).unwrap()
                };

                let socket = Arc::clone(&self.socket);
                let cache = Arc::clone(&self.cache);
                let all_proxies = Arc::clone(&self.proxies);
                let message_handler = Arc::clone(&self.message_handler);
                let local_node = self.local_node.clone();
                let msg_clone = msg.clone();
                let mut temp_proxy = proxies.remove(rand::random_range(0..proxies.len()));

                let task = tokio::spawn(async move {

                    let n_1 = temp_proxy.neighbor_1.node.clone();
                    let n_2 = temp_proxy.neighbor_2.node.clone();

                    let cloves = GarlicCast::generate_cloves_rsa(msg_clone.clone(), temp_proxy.clone().public_key, 2, temp_proxy.sequence_number);

                    let n_1_msg = GarlicMessage::Forward {
                        sequence_number: temp_proxy.neighbor_1.sequence_number,
                        clove: cloves[0].clone()
                    };
                    let n_2_msg = GarlicMessage::Forward {
                        sequence_number: temp_proxy.neighbor_2.sequence_number,
                        clove: cloves[1].clone()
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

                    match response {
                        Ok(_) => {}
                        _ => {
                            let info = GarlicCast::use_alternate_proxy_node(Arc::clone(&cache), Arc::clone(&all_proxies), Arc::clone(&message_handler), Arc::clone(&socket), local_node.clone(), n_1.clone(), temp_proxy.clone(), n_1_msg).await;

                            match info {
                                Ok(new_proxy) => {
                                    temp_proxy = new_proxy;
                                }
                                Err(_) => {
                                    return Err(temp_proxy.clone());
                                }
                            }
                        }
                    }

                    match response2 {
                        Ok(_) => {
                            Ok((proxy_id, temp_proxy.clone()))
                        }
                        _ => {
                            let info = GarlicCast::use_alternate_proxy_node(cache, all_proxies, Arc::clone(&message_handler), Arc::clone(&socket), local_node.clone(), n_2.clone(), temp_proxy.clone(), n_2_msg).await;

                            match info {
                                Ok(new_proxy) => {
                                    Ok((proxy_id, new_proxy.clone()))
                                }
                                Err(_) => {
                                    Err(temp_proxy.clone())
                                }
                            }
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
                                self.proxies.lock().await.retain(|x| *x != e);
                                self.cache.lock().await.remove_sequence(e.sequence_number);
                            }
                        }
                    }
                    Err(e) => {
                        println!("{}: This should not happen: GarlicCast::send_search_overlay():1 : {}", self.local_node.address, e);
                    }
                }
            }
        }

        self.requests.lock().await.insert(request_id, proxy_request);
    }
    
    pub async fn send_search_kademlia(&self, proxy_id_pool: Vec<U256>, key: U256) {
        let request_id = u256_random();
        let proxy_request = ProxyRequest {
            request_id,
            validator_required: false,
            proxies: vec![],
            proxy_id_associations: HashMap::new(),
            responses: vec![],
        };

        let proxies_init;
        {
            proxies_init = self.proxies.lock().await.clone();
        }

        let mut proxies = vec![];
        for proxy in proxies_init {
            if proxy_id_pool.contains(&proxy.sequence_number) {
                proxies.push(proxy);
            }
        }

        let mut sent = false;
        let socket = Arc::clone(&self.socket);
        let cache = Arc::clone(&self.cache);
        let all_proxies = Arc::clone(&self.proxies);
        let message_handler = Arc::clone(&self.message_handler);
        let local_node = self.local_node.clone();

        while !sent {
            let mut temp_proxy = proxies.remove(rand::random_range(0..proxies.len()));

            //let proxy_id = rand::random::<U256>();
            let msg = CloveMessage::SearchGarlemlia {
                request_id,
                key,
                public_key: self.public_key.clone().unwrap().to_public_key_pem(rsa::pkcs8::LineEnding::LF).unwrap()
            };

            let n_1 = temp_proxy.neighbor_1.node.clone();
            let n_2 = temp_proxy.neighbor_2.node.clone();

            let cloves = GarlicCast::generate_cloves_rsa(msg.clone(), temp_proxy.clone().public_key, 2, temp_proxy.sequence_number);

            let n_1_msg = GarlicMessage::Forward {
                sequence_number: temp_proxy.neighbor_1.sequence_number,
                clove: cloves[0].clone()
            };
            let n_2_msg = GarlicMessage::Forward {
                sequence_number: temp_proxy.neighbor_2.sequence_number,
                clove: cloves[1].clone()
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

            match response {
                Ok(_) => {}
                _ => {
                    let info = GarlicCast::use_alternate_proxy_node(Arc::clone(&cache), Arc::clone(&all_proxies), Arc::clone(&message_handler), Arc::clone(&socket), local_node.clone(), n_1.clone(), temp_proxy.clone(), n_1_msg).await;

                    match info {
                        Ok(new_proxy) => {
                            temp_proxy = new_proxy;
                        }
                        Err(_) => {
                            all_proxies.lock().await.retain(|x| *x != temp_proxy);
                            cache.lock().await.remove_sequence(temp_proxy.sequence_number);
                            continue;
                        }
                    }
                }
            }

            match response2 {
                Ok(_) => {}
                _ => {
                    let info = GarlicCast::use_alternate_proxy_node(Arc::clone(&cache), Arc::clone(&all_proxies), Arc::clone(&message_handler), Arc::clone(&socket), local_node.clone(), n_2.clone(), temp_proxy.clone(), n_2_msg).await;

                    match info {
                        Ok(_) => {
                            sent = true;
                        }
                        Err(_) => {
                            all_proxies.lock().await.retain(|x| *x != temp_proxy);
                            cache.lock().await.remove_sequence(temp_proxy.sequence_number);
                        }
                    }
                }
            }
        }

        self.requests.lock().await.insert(request_id, proxy_request);
    }

    async fn replace_with_alt(&self, next_node: CloveNode, mut alt_msg: GarlicMessage) -> bool {
        let mut try_update: Option<CloveNode> = None;
        {
            let mut cache = self.cache.lock().await;
            try_update = cache.replace_with_alt_node(next_node.sequence_number, next_node.node);
        }

        match try_update {
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
                        true
                    }
                    _ => {
                        // Big failure
                        self.cache.lock().await.remove_sequence(updated.sequence_number);
                        self.cache.lock().await.remove_sequence(next_node.sequence_number);
                        println!("{} :: REPLACEALT {} :: FAILURE : OFFLINE :: {} -> {}", Utc::now(), updated.sequence_number, self.local_node.address, updated.node.address);
                        false
                    }
                }
            }
            None => {
                // Big failure
                self.cache.lock().await.remove_sequence(next_node.sequence_number);
                println!("{} :: REPLACEALT {} :: FAILURE : NONEXISTENT :: {}", Utc::now(), alt_msg.sequence_number(), self.local_node.address);
                false
            }
        }
    }

    async fn forward(&self, next_node_hop: CloveNode, msg: Clove) {
        let mut replaced = false;
        loop {
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
                    return;
                }
                _ => {
                    if !replaced {
                        self.replace_with_alt(next_node, new_msg).await;
                        replaced = true;
                    } else {
                        self.cache.lock().await.remove_sequence(next_node.sequence_number);
                        return;
                    }
                }
            }
        }
    }

    async fn forward_find_proxy(&self, sequence_number: U256, node: Node, msg: Clove) {
        let mut keep_trying = true;
        while keep_trying {
            // Basically just try the fuck out of some nodes until one responds with an IsAlive message
            let known_nodes;
            let mut choose_list = vec![];
            {
                known_nodes = self.known_nodes.lock().await.clone();
                choose_list.extend(known_nodes.clone());
            }

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
                    {
                        let mut cache = self.cache.lock().await;
                        cache.insert_next_hop(original_clove.clone(), Some(forward_clove.clone()));
                        cache.insert_next_hop(forward_clove.clone(), Some(original_clove.clone()));
                        // Insert clove
                        cache.insert_clove(msg.clone(), node.clone());
                        // Insert associations
                        cache.insert_association(sequence_number, original_clove.clone());
                        cache.insert_association(sequence_number, forward_clove.clone());
                        // Insert seen last
                        cache.seen(sequence_number);
                    }

                    keep_trying = false;
                }
                Err(_) => {}
            }
        }
    }

    async fn forward_proxy_accept(&self, proxy: Proxy, old_sequence: U256) {
        let hops_start = rand::random::<u16>() & 0b1111;
        
        let proxy_info = CloveMessage::ProxyInfo {
            public_key: self.public_key.clone().unwrap().to_public_key_pem(rsa::pkcs8::LineEnding::LF).unwrap(),
            starting_hops: hops_start,
        };

        let cloves = GarlicCast::generate_cloves_rsa(proxy_info, proxy.public_key, 2, proxy.sequence_number);

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
                        println!("{} SENT ProxyAgree TO {} AND {}", self.local_node.address, n_2.address, n_1.address);
                    }
                    _ => {
                        println!("{} FAILED TO SEND ProxyAgree TO {} BUT SENT TO {}", self.local_node.address, n_2.address, n_1.address);
                        self.cache.lock().await.remove_sequence(proxy.sequence_number);
                        self.cache.lock().await.remove_sequence(old_sequence);
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
                self.cache.lock().await.remove_sequence(proxy.sequence_number);
                self.cache.lock().await.remove_sequence(old_sequence);
            }
        }
    }

    async fn accept_proxy(&self, cache: CloveCache, sequence_number: U256, second_clove: Clove, node: Node) -> Option<Proxy> {
        let first_clove = cache.cloves.get(&sequence_number).unwrap().clone();
        let msg_from_initiator = GarlicCast::message_from_cloves_no_rsa(first_clove.clone().clove, second_clove.clone());

        if first_clove.from.id == node.id {
            println!("COULD NOT ACCEPT PROXY, RECEIVED FROM SAME NODE {}", node.address);
            self.cache.lock().await.remove_clove(sequence_number);
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

                {
                    self.initiators.lock().await.push(proxy.clone());
                    let mut cache = self.cache.lock().await;
                    cache.insert_next_hop(CloveNode { sequence_number: new_sequence, node: node.clone() }, None);
                    cache.insert_next_hop(CloveNode { sequence_number: new_sequence, node: first_clove.clone().from}, None);
                    // Insert associations
                    cache.insert_association(new_sequence, CloveNode { sequence_number: new_sequence, node: node.clone() });
                    cache.insert_association(new_sequence, CloveNode { sequence_number: new_sequence, node: first_clove.from});
                    // Insert seen last
                    cache.seen(new_sequence);
                    // Remove old clove
                    cache.remove_clove(sequence_number);
                }

                println!("{} :: PROXY :: {}", Utc::now(), self.local_node.address);
                self.forward_proxy_accept(proxy.clone(), sequence_number).await;

                Some(proxy)
            },
            _ => {
                None
            }
        }
    }

    pub async fn find_alt(&self, n_1: Option<Node>, n_2: Option<Node>, sequence_number: U256) -> CloveNode {
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
            let known_nodes;
            let mut choose_list = vec![];
            {
                known_nodes = self.known_nodes.lock().await.clone();
                choose_list.extend(known_nodes.clone());
            }

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

                            {
                                self.cache.lock().await.insert_my_alt_node(sequence_number, alt.clone());
                            }

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

    pub async fn send_alt(&self, n_1: Option<Node>, n_2: Option<Node>, sequence_number: U256, alt: CloveNode) {
        let new_msg = GarlicMessage::UpdateAlt {
            sequence_number,
            alt_node: alt.clone(),
        };

        let socket = Arc::clone(&self.socket);
        let time = Utc::now();
        let mut n_1_success = false;

        if let Some(n_1) = n_1 {
            {
                if let Err(e) = self.message_handler.send(&Arc::from(socket.clone()), self.local_node.clone(), &n_1.address, &GarlicMessage::build_send(self.local_node.clone(), new_msg.clone())).await {
                    eprintln!("Failed to send Forward to {}: {:?}", n_1.address, e);
                }
            }

            let response;
            {
                response = self.message_handler.recv(200, &n_1.address).await;
            }

            match response {
                Ok(_) => {
                    println!("{} :: UPDATEALT {} :: {} -> {}", time, sequence_number, self.local_node.address, n_1.address);
                    n_1_success = true;
                }
                _ => {
                    println!("{} :: UPDATEALT {} :: FAILURE : OFFLINE :: {} -> {}", time, sequence_number, self.local_node.address, n_1.address);
                    n_1_success = self.replace_with_alt(CloveNode { sequence_number, node: n_1 }, new_msg.clone()).await;
                }
            }
        }

        if !n_1_success {
            return;
        }

        if let Some(n_2) = n_2 {
            {
                if let Err(e) = self.message_handler.send(&Arc::from(socket.clone()), self.local_node.clone(), &n_2.address, &GarlicMessage::build_send(self.local_node.clone(), new_msg.clone())).await {
                    eprintln!("Failed to send Forward to {}: {:?}", n_2.address, e);
                }
            }

            let response;
            {
                response = self.message_handler.recv(200, &n_2.address).await;
            }

            match response {
                Ok(_) => {
                    println!("{} :: UPDATEALT {} :: {} -> {}", time, sequence_number, self.local_node.address, n_2.address);
                }
                _ => {
                    println!("{} :: UPDATEALT {} :: FAILURE : OFFLINE :: {} -> {}", time, sequence_number, self.local_node.address, n_2.address);
                    self.replace_with_alt(CloveNode { sequence_number, node: n_2 }, new_msg).await;
                }
            }
        }
    }
    
    pub async fn manage_proxy_message(&self, req: CloveMessage) {
        match req {
            CloveMessage::SearchOverlay { request_id, proxy_id, search_term, public_key } => {
                
            }
            CloveMessage::SearchGarlemlia { request_id, key, public_key } => {
                
            }
            CloveMessage::ResponseDirect { request_id, address, data, public_key } => {
                
            }
            CloveMessage::ResponseWithValidator { request_id, proxy_id, data, public_key } => {
                
            }
            _ => {}
        }
    }

    pub async fn recv(&self, node: Node, garlic_msg: GarlicMessage) -> Result<Option<GarlemliaMessage>, MessageError> {
        let socket = Arc::clone(&self.socket);
        match garlic_msg.clone() {
            GarlicMessage::FindProxy { sequence_number, clove } => {
                {
                    if let Err(e) = self.message_handler.send_no_recv(&Arc::from(socket), self.local_node.clone(), &node.address, &GarlicMessage::build_send_is_alive(self.local_node.clone())).await {
                        eprintln!("Failed to send IsAlive to {}: {:?}", node.address, e);
                    }
                }

                println!("{} :: FINDPROXY {}[{}] :: {} -> {}", Utc::now(), sequence_number, clove.index, node.address, self.local_node.address);

                let mut same_clove = false;
                let clove_data;
                let mut old_node = None;
                {
                    let cache = self.cache.lock().await;
                    clove_data = cache.cloves.clone();
                }

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
                    println!("{} :: SAME CLOVE {}[{}] :: {}", Utc::now(), sequence_number, clove.index, self.local_node.address);
                    node_actual = old_node.unwrap();
                }

                let cache;
                {
                    let mut cache_lock = self.cache.lock().await;
                    cache_lock.seen(sequence_number);
                    cache = cache_lock.clone();
                }

                if cache.cloves.contains_key(&sequence_number) && !same_clove {
                    let new_proxy = self.accept_proxy(cache, sequence_number, clove, node_actual).await.unwrap();

                    let new_alt = self.find_alt(Some(node.clone()), None, new_proxy.sequence_number).await;
                    self.send_alt(Some(node), None, new_proxy.sequence_number, new_alt).await;
                } else if random_bool(FORWARD_P) {
                    // First time seeing this sequence number and forwarding it
                    self.forward_find_proxy(sequence_number, node_actual.clone(), msg.clone()).await;
                } else {
                    println!("{} :: NOT FORWARDING {}[{}] :: {}", Utc::now(), sequence_number, clove.index, self.local_node.address);
                    // Not forwarding, but still add to own cache
                    let original_clove = CloveNode { sequence_number, node: node_actual.clone() };
                    {
                        let mut cache = self.cache.lock().await;
                        cache.insert_next_hop(original_clove.clone(), None);
                        // Insert clove
                        cache.insert_clove(msg.clone(), node_actual.clone());
                        // Insert associations
                        cache.insert_association(sequence_number, original_clove.clone());
                        // Insert seen last
                        cache.seen(sequence_number);
                    }
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
                let next;
                {
                    let mut cache = self.cache.lock().await;
                    next = cache.get_forward_node(CloveNode { sequence_number, node: node.clone() });
                    cache.seen(sequence_number);
                }

                match next {
                    Ok(info) => {
                        match info {
                            Some(next_node) => {
                                self.forward(next_node, msg).await;
                                Ok(None)
                            }
                            None => {
                                let mut sn_actual = sequence_number.clone();
                                {
                                    let check_sn = self.cache.lock().await.get_sequence_from_alt(CloveNode { sequence_number, node: node.clone() });
                                    match check_sn {
                                        Some(new_sequence) => {
                                            sn_actual = new_sequence.clone();
                                        }
                                        None => {}
                                    }
                                }

                                // Receive message part from proxy or from initiator
                                let messages_from;
                                {
                                    let mut collected_messages = self.collected_messages.lock().await;
                                    let msgs = collected_messages.get_mut(&sn_actual);

                                    if let Some(msg_vec) = msgs {
                                        msg_vec.push(garlic_msg);
                                        messages_from = msg_vec.clone();
                                    } else {
                                        collected_messages.insert(sn_actual, vec![garlic_msg.clone()]);
                                        messages_from = vec![garlic_msg];
                                    }
                                }

                                if messages_from.len() == 2 {
                                    // Has second portion of the message already
                                    let cloves = vec![messages_from[0].clove().unwrap(), messages_from[1].clove().unwrap()];

                                    if cloves.len() == 2 {
                                        let msg_from_initiator = GarlicCast::message_from_cloves_rsa(cloves[0].clone(), cloves[1].clone(), self.private_key.clone().unwrap());

                                        if msg_from_initiator.is_request() {
                                            let mut requests_info = self.requests.lock().await;
                                            let request_info = requests_info.get_mut(&msg_from_initiator.request_id());

                                            if request_info.is_some() {
                                                // THIS NODE IS THE INITIATOR, NOT THE PROXY
                                                let proxy_request = request_info.unwrap();

                                                proxy_request.responses.push(msg_from_initiator.clone());

                                                self.collected_messages.lock().await.remove(&sn_actual);

                                                println!("{} :: CLOVEMESSAGE :: {} :: {:?}", Utc::now(), self.local_node.address, msg_from_initiator);
                                            } else {
                                                // THIS NODE IS THE PROXY, NOT THE INITIATOR
                                                println!("{} :: CLOVEMESSAGE :: {} :: {:?}", Utc::now(), self.local_node.address, msg_from_initiator);
                                                self.manage_proxy_message(msg_from_initiator).await;
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

                println!("{} :: PROXYAGREE {}[{}] :: {} -> {}", Utc::now(), updated_sequence_number, clove.index, node.address, self.local_node.address);

                //println!("{} GOT ProxyAgree FROM {}", self.local_node.address, node.address);

                let old_clove_node = CloveNode { sequence_number, node: node.clone() };

                {
                    self.cache.lock().await.update_sequence_number(updated_sequence_number, old_clove_node.clone());
                }

                let new_proxy_agree = GarlicMessage::ProxyAgree {
                    sequence_number,
                    updated_sequence_number,
                    hops: hops + 1,
                    clove: clove.clone(),
                };

                let next;
                {
                    let mut cache = self.cache.lock().await;
                    next = cache.get_forward_node(CloveNode { sequence_number: updated_sequence_number, node: node.clone() });
                    cache.seen(sequence_number);
                    cache.seen(updated_sequence_number);
                }

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
                                        self.send_alt(Some(node), Some(next_node.node), updated_sequence_number, new_alt).await;
                                    }
                                    _ => {
                                        println!("{} FAILED TO SEND TO {}", self.local_node.address, next_node.node.address);
                                        // Failed to send to forward node, remove all content
                                        self.cache.lock().await.remove_sequence(sequence_number);
                                        self.cache.lock().await.remove_sequence(updated_sequence_number);
                                    }
                                }
                            }
                            _ => {
                                let messages_from;
                                {
                                    let mut collected_messages = self.collected_messages.lock().await;
                                    let msgs = collected_messages.get_mut(&updated_sequence_number);

                                    if let Some(msg_vec) = msgs {
                                        msg_vec.push(garlic_msg);
                                        messages_from = msg_vec.clone();
                                    } else {
                                        collected_messages.insert(updated_sequence_number, vec![garlic_msg.clone()]);
                                        messages_from = vec![garlic_msg];
                                    }
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
                                        if let Some(neighbor_1) = self.partial_proxies.lock().await.remove(&updated_sequence_number) {
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

                                                    {
                                                        self.proxies.lock().await.push(proxy.clone());
                                                        self.collected_messages.lock().await.remove(&updated_sequence_number);
                                                    }

                                                    println!("{} :: PROXY RECEIVED :: {} :: #{} -> #{} :: n_1: {}, n_2: {}", Utc::now(), self.local_node.address, sequence_number, updated_sequence_number, proxy.neighbor_1_hops, proxy.neighbor_2_hops);

                                                    let new_alt = self.find_alt(Some(node.clone()), None, updated_sequence_number).await;
                                                    self.send_alt(Some(node), None, updated_sequence_number, new_alt).await;
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
                                    self.partial_proxies.lock().await.insert(updated_sequence_number, node.clone());

                                    let new_alt = self.find_alt(Some(node.clone()), None, updated_sequence_number).await;
                                    self.send_alt(Some(node), None, updated_sequence_number, new_alt).await;
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
                {
                    let mut cache = self.cache.lock().await;
                    cache.insert_next_hop(lh_clove.clone(), Some(nh_clove.clone()));
                    cache.insert_next_hop(lh_clove.clone(), Some(nh_clove.clone()));
                    // Insert associations
                    cache.insert_association(alt_sequence_number, lh_clove.clone());
                    cache.insert_association(alt_sequence_number, nh_clove.clone());
                    // Insert seen last
                    cache.seen(alt_sequence_number);
                }

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

                {
                    let mut cache = self.cache.lock().await;
                    cache.seen(sequence_number);
                }

                Ok(None)
            }
            GarlicMessage::UpdateAlt { sequence_number, alt_node } => {
                {
                    if let Err(e) = self.message_handler.send_no_recv(&Arc::from(socket.clone()), self.local_node.clone(), &node.address, &GarlicMessage::build_send_is_alive(self.local_node.clone())).await {
                        eprintln!("Failed to send IsAlive to {}: {:?}", node.address, e);
                    }
                }

                self.cache.lock().await.insert_alt_node(CloveNode { sequence_number, node }, alt_node);

                Ok(None)
            }
        }
    }
}