use crate::garlemlia_structs::garlemlia_structs;
use aes::Aes256;
use bincode;
use chrono::{DateTime, Utc};
use cipher::generic_array::GenericArray;
use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use garlemlia_structs::{Clove, CloveData, CloveNode, GMessage, GarlemliaMessage, GarlicMessage, CloveMessage, MessageError, Node};
use rand::random_bool;
use rand::seq::IndexedRandom;
use rand::{rng, RngCore};
use reed_solomon_erasure::galois_8::ReedSolomon;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::cmp::PartialEq;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use crate::simulator::simulator::{get_global_socket, SimulatedMessageHandler};

pub const FORWARD_P: f64 = 0.95;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableCloveCache {
    cloves: HashMap<u128, CloveData>,
    next_hop_key: HashMap<u32, CloveNode>,
    next_hop_val: HashMap<u32, Option<CloveNode>>,
    alt_nodes_key: HashMap<u32, CloveNode>,
    alt_nodes_val: HashMap<u32, CloveNode>,
    associations: HashMap<u128, Vec<CloveNode>>,
    seen_last: HashMap<u128, DateTime<Utc>>,
    my_alt_nodes: HashMap<u128, CloveNode>
}

impl SerializableCloveCache {
    pub fn from(cache: CloveCache) -> SerializableCloveCache {
        let mut next_hop_key = HashMap::new();
        let mut next_hop_val = HashMap::new();
        let mut alt_nodes_key = HashMap::new();
        let mut alt_nodes_val = HashMap::new();

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

        SerializableCloveCache {
            cloves: cache.cloves,
            next_hop_key,
            next_hop_val,
            alt_nodes_key,
            alt_nodes_val,
            associations: cache.associations,
            seen_last: cache.seen_last,
            my_alt_nodes: cache.my_alt_nodes,
        }
    }

    pub fn to_clove_cache(self) -> CloveCache {
        let mut next_hop = HashMap::new();
        let mut alt_nodes = HashMap::new();

        for entry in self.next_hop_key.iter() {
            let val = self.next_hop_val.get(entry.0).unwrap().clone();
            next_hop.insert(entry.1.clone(), val);
        }

        for entry in self.alt_nodes_key.iter() {
            let val = self.alt_nodes_val.get(entry.0).unwrap().clone();
            alt_nodes.insert(entry.1.clone(), val);
        }

        CloveCache {
            cloves: self.cloves,
            next_hop,
            alt_nodes,
            associations: self.associations,
            seen_last: self.seen_last,
            my_alt_nodes: self.my_alt_nodes,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CloveCache {
    cloves: HashMap<u128, CloveData>,
    next_hop: HashMap<CloveNode, Option<CloveNode>>,
    alt_nodes: HashMap<CloveNode, CloveNode>,
    associations: HashMap<u128, Vec<CloveNode>>,
    seen_last: HashMap<u128, DateTime<Utc>>,
    my_alt_nodes: HashMap<u128, CloveNode>
}

impl CloveCache {
    pub fn new() -> CloveCache {
        CloveCache {
            cloves: HashMap::new(),
            next_hop: HashMap::new(),
            alt_nodes: HashMap::new(),
            associations: HashMap::new(),
            seen_last: HashMap::new(),
            my_alt_nodes: HashMap::new()
        }
    }

    pub fn remove_sequence(&mut self, sequence_number: u128) {
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

    pub fn remove_clove(&mut self, sequence_number: u128) {
        self.cloves.remove(&sequence_number);
    }

    pub fn insert_association(&mut self, sequence_number: u128, node: CloveNode) {
        if self.associations.contains_key(&sequence_number) {
            self.associations.get_mut(&sequence_number).unwrap().push(node);
            self.associations.get_mut(&sequence_number).unwrap().dedup();
        } else {
            self.associations.insert(sequence_number, vec![node]);
        }
    }

    pub fn insert_updated_association(&mut self, sequence_number: u128, new_sequence_number: u128) {
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

    pub fn remove_association(&mut self, sequence_number: u128) {
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

        self.insert_association(node.sequence_number, alt_node);
    }

    pub fn remove_alt_node(&mut self, node: CloveNode) {
        self.alt_nodes.remove(&node);
    }

    pub fn insert_my_alt_node(&mut self, sequence_number: u128, my_alt_node: CloveNode) {
        self.my_alt_nodes.insert(sequence_number, my_alt_node.clone());

        self.insert_association(sequence_number, my_alt_node);
    }

    pub fn remove_my_alt_node(&mut self, sequence_number: u128) {
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

    pub fn update_sequence_number(&mut self, new_sequence_number: u128, clove_node: CloveNode) {
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

    pub fn replace_with_alt_node(&mut self, sequence_number: u128, node: Node) -> Option<CloveNode> {
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

    pub fn seen(&mut self, sequence_number: u128) {
        self.seen_last.insert(sequence_number, Utc::now());
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableProxy {
    sequence_number: u128,
    neighbor_1: Node,
    neighbor_2: Node,
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
    sequence_number: u128,
    neighbor_1: Node,
    neighbor_2: Node,
    neighbor_1_hops: u16,
    neighbor_2_hops: u16,
    public_key: RsaPublicKey,
    used_last: DateTime<Utc>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableGarlicCast {
    local_node: Node,
    pub known_nodes: Vec<Node>,
    proxies: Vec<SerializableProxy>,
    partial_proxies: HashMap<u128, Node>,
    cache: SerializableCloveCache,
    collected_messages: HashMap<u128, Vec<GarlicMessage>>,
    pub public_key: String,
    pub private_key: String,
    pub starting_hops: HashMap<u128, u8>,
}

impl SerializableGarlicCast {
    pub async fn from(garlic: GarlicCast) -> SerializableGarlicCast {
        SerializableGarlicCast {
            local_node: garlic.local_node.clone(),
            known_nodes: garlic.known_nodes.lock().await.clone(),
            proxies: SerializableProxy::vec_to_serializable(garlic.proxies.lock().await.clone()),
            partial_proxies: garlic.partial_proxies.lock().await.clone(),
            cache: SerializableCloveCache::from(garlic.cache.lock().await.clone()),
            collected_messages: garlic.collected_messages.lock().await.clone(),
            public_key: garlic.public_key.unwrap().to_public_key_pem(rsa::pkcs8::LineEnding::LF).unwrap(),
            private_key: garlic.private_key.unwrap().to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap().to_string(),
            starting_hops: garlic.starting_hops.clone(),
        }
    }

    pub fn to_garlic(self) -> GarlicCast {
        GarlicCast {
            socket: get_global_socket().unwrap(),
            local_node: self.local_node,
            message_handler: Arc::new(SimulatedMessageHandler::create(0)),
            known_nodes: Arc::new(Mutex::new(self.known_nodes)),
            proxies: Arc::new(Mutex::new(SerializableProxy::vec_to_proxy(self.proxies.clone()))),
            partial_proxies: Arc::new(Mutex::new(self.partial_proxies)),
            cache: Arc::new(Mutex::new(self.cache.to_clove_cache())),
            collected_messages: Arc::new(Mutex::new(self.collected_messages)),
            public_key: Some(RsaPublicKey::from_public_key_pem(&*self.public_key).unwrap()),
            private_key: Some(RsaPrivateKey::from_pkcs8_pem(&*self.private_key).unwrap()),
            starting_hops: self.starting_hops
        }
    }
}

#[derive(Clone, Debug)]
pub struct GarlicCast {
    socket: Arc<UdpSocket>,
    local_node: Node,
    message_handler: Arc<Box<dyn GMessage>>,
    pub known_nodes: Arc<Mutex<Vec<Node>>>,
    proxies: Arc<Mutex<Vec<Proxy>>>,
    partial_proxies: Arc<Mutex<HashMap<u128, Node>>>,
    cache: Arc<Mutex<CloveCache>>,
    collected_messages: Arc<Mutex<HashMap<u128, Vec<GarlicMessage>>>>,
    public_key: Option<RsaPublicKey>,
    private_key: Option<RsaPrivateKey>,
    starting_hops: HashMap<u128, u8>,
}

impl GarlicCast {
    pub fn new(socket: Arc<UdpSocket>, local_node: Node, message_handler: Arc<Box<dyn GMessage>>, known_nodes: Vec<Node>, public_key: Option<RsaPublicKey>, private_key: Option<RsaPrivateKey>) -> GarlicCast {
        GarlicCast {
            socket,
            local_node,
            message_handler,
            known_nodes: Arc::new(Mutex::new(known_nodes)),
            proxies: Arc::new(Mutex::new(Vec::new())),
            partial_proxies: Arc::new(Mutex::new(HashMap::new())),
            cache: Arc::new(Mutex::new(CloveCache::new())),
            collected_messages: Arc::new(Mutex::new(HashMap::new())),
            public_key,
            private_key,
            starting_hops: HashMap::new(),
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

    async fn in_cache(&self, sequence_number: u128) -> bool {
        let cache = self.cache.lock().await;
        let cache_info = cache.cloves.get(&sequence_number);

        if let Some(_) = cache_info {
            return true;
        }

        false
    }

    pub async fn discover_proxies(&self, count: u8) {
        let mut count_actual = count;
        if  count < 2 {
            count_actual = 2;
        }

        let sequence_number = rand::random::<u128>();

        let msg = CloveMessage::RequestProxy {
            msg: "Will proxy?".to_string(),
            public_key: self.public_key.clone().unwrap().to_public_key_pem(rsa::pkcs8::LineEnding::LF).unwrap()
        };

        let mut known_nodes;
        {
            known_nodes = self.known_nodes.lock().await.clone();
        }

        let cloves = Arc::new(Mutex::new(GarlicCast::generate_cloves(msg, count_actual, sequence_number).await));

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

                    let send_msg = GarlicMessage::Forward {
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

    pub async fn get_message_from_cloves(clove_1: Clove, clove_2: Clove) -> CloveMessage {
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

        let key_bytes: Vec<u8> = key_shards.iter()
            .take(2)
            .filter_map(|s| s.as_ref())
            .flatten()
            .cloned()
            .collect();

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

    pub async fn generate_cloves(msg: CloveMessage, count: u8, sequence_number: u128) -> Vec<Clove> {
        let mut cloves = vec![];

        let mut count_actual = count;
        if count < 3 {
            count_actual = 3;
        }

        let mut key = [0u8; 32];
        rng().fill_bytes(&mut key);

        // Serialize message into bytes
        let msg_serialized = bincode::serialize(&msg).unwrap();

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
        let key_data = key.to_vec();

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

    pub async fn send_search_overlay(&self, req: String, count: u8) {
        let mut count_actual = count;
        if  count < 2 {
            count_actual = 2;
        }

        let msg = CloveMessage::SearchOverlay {
            search_term: req.clone(),
        };

        let mut proxies;
        {
            proxies = self.proxies.lock().await.clone();
        }

        let mut total_sent = 0;
        while total_sent < count_actual {
            let mut tasks = Vec::new();

            for _ in 0..count_actual - total_sent {
                let socket = Arc::clone(&self.socket);
                let message_handler = Arc::clone(&self.message_handler);
                let local_node = self.local_node.clone();
                let msg_clone = msg.clone();
                let temp_proxy = proxies.remove(rand::random_range(0..proxies.len()));

                let task = tokio::spawn(async move {

                    let n_1 = temp_proxy.neighbor_1.clone();
                    let n_2 = temp_proxy.neighbor_2.clone();

                    let cloves = GarlicCast::generate_cloves(msg_clone, 2, temp_proxy.sequence_number).await;

                    let n_1_msg = GarlicMessage::Forward {
                        sequence_number: temp_proxy.sequence_number,
                        clove: cloves[0].clone()
                    };
                    let n_2_msg = GarlicMessage::Forward {
                        sequence_number: temp_proxy.sequence_number,
                        clove: cloves[1].clone()
                    };

                    {
                        if let Err(e) = message_handler.send(&Arc::from(socket.clone()), local_node.clone(), &n_1.address, &GarlicMessage::build_send(local_node.clone(), n_1_msg)).await {
                            eprintln!("Failed to send Forward to {}: {:?}", n_1.address, e);
                        }
                    }

                    let response;
                    {
                        response = message_handler.recv(200, &n_1.address).await;
                    }

                    {
                        if let Err(e) = message_handler.send(&Arc::from(socket.clone()), local_node.clone(), &n_2.address, &GarlicMessage::build_send(local_node.clone(), n_2_msg)).await {
                            eprintln!("Failed to send Forward to {}: {:?}", n_2.address, e);
                        }
                    }

                    let response2;
                    {
                        response2 = message_handler.recv(200, &n_2.address).await;
                    }

                    return match response {
                        Ok(_) => {
                            match response2 {
                                Ok(_) => {
                                    Ok(true)
                                }
                                _ => {
                                    Err(temp_proxy)
                                }
                            }
                        }
                        _ => {
                            Err(temp_proxy)
                        }
                    }
                });
                tasks.push(task);
            }

            for task in tasks {
                match task.await {
                    Ok(val) => {
                        match val {
                            Ok(_) => {
                                total_sent += 1;
                            }
                            Err(e) => {
                                self.proxies.lock().await.retain(|x| *x != e);
                            }
                        }
                    }
                    Err(e) => {
                        println!("{}: This should not happen: GarlicCast::send_search_overlay():1 : {}", self.local_node.address, e);
                    }
                }
            }
        }
    }
    
    pub async fn send_search_kademlia(&self, key: u128) {
        let msg = CloveMessage::SearchGarlemlia {
            key
        };

        let mut proxies;
        {
            proxies = self.proxies.lock().await.clone();
        }

        let mut sent = false;
        let socket = Arc::clone(&self.socket);
        let message_handler = Arc::clone(&self.message_handler);
        let local_node = self.local_node.clone();
        let msg_clone = msg.clone();

        while !sent {
            let temp_proxy = proxies.remove(rand::random_range(0..proxies.len()));

            let n_1 = temp_proxy.neighbor_1.clone();
            let n_2 = temp_proxy.neighbor_2.clone();

            let cloves = GarlicCast::generate_cloves(msg_clone, 2, temp_proxy.sequence_number).await;

            let n_1_msg = GarlicMessage::Forward {
                sequence_number: temp_proxy.sequence_number,
                clove: cloves[0].clone()
            };
            let n_2_msg = GarlicMessage::Forward {
                sequence_number: temp_proxy.sequence_number,
                clove: cloves[1].clone()
            };

            {
                if let Err(e) = message_handler.send(&Arc::from(socket.clone()), local_node.clone(), &n_1.address, &GarlicMessage::build_send(local_node.clone(), n_1_msg)).await {
                    eprintln!("Failed to send Forward to {}: {:?}", n_1.address, e);
                }
            }

            let response;
            {
                response = message_handler.recv(200, &n_1.address).await;
            }

            {
                if let Err(e) = message_handler.send(&Arc::from(socket.clone()), local_node.clone(), &n_2.address, &GarlicMessage::build_send(local_node.clone(), n_2_msg)).await {
                    eprintln!("Failed to send Forward to {}: {:?}", n_2.address, e);
                }
            }

            let response2;
            {
                response2 = message_handler.recv(200, &n_2.address).await;
            }

            return match response {
                Ok(_) => {
                    match response2 {
                        Ok(_) => {
                            sent = true;
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }

    async fn forward(&self, next_node: CloveNode, msg: Clove) {
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
            if let Err(e) = self.message_handler.send(&Arc::from(socket.clone()), self.local_node.clone(), &next_node.node.address, &GarlicMessage::build_send(self.local_node.clone(), new_msg)).await {
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
                let mut try_update: Option<CloveNode> = None;
                {
                    let mut cache = self.cache.lock().await;
                    try_update = cache.replace_with_alt_node(next_node.sequence_number, next_node.node);
                }

                match try_update {
                    Some(updated) => {
                        new_clove.sequence_number = updated.sequence_number;

                        let new_alt_msg = GarlicMessage::Forward {
                            sequence_number: updated.sequence_number,
                            clove: new_clove
                        };

                        {
                            if let Err(e) = self.message_handler.send(&Arc::from(socket), self.local_node.clone(), &updated.node.address, &GarlicMessage::build_send(self.local_node.clone(), new_alt_msg)).await {
                                eprintln!("Failed to send Forward to {}: {:?}", updated.node.address, e);
                            }
                        }

                        let response2;
                        {
                            response2 = self.message_handler.recv(200, &updated.node.address).await;
                        }

                        match response2 {
                            Ok(_) => {
                                return;
                            }
                            _ => {
                                // Big failure
                                self.cache.lock().await.remove_sequence(updated.sequence_number);
                                println!("{}: This should not happen: GarlicCast::forward():1", self.local_node.address);
                            }
                        }
                    }
                    None => {
                        // Big failure
                        self.cache.lock().await.remove_sequence(next_node.sequence_number);
                        println!("{}: This should not happen: GarlicCast::forward():2", self.local_node.address);
                    }
                }
            }
        }
    }

    async fn forward_to_new(&self, sequence_number: u128, node: Node, msg: Clove) {
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

            let new_msg = GarlicMessage::Forward {
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

    async fn forward_proxy_accept(&self, proxy: Proxy, old_sequence: u128) {
        let hops_start = rand::random::<u16>() & 0b1111;
        
        let proxy_info = CloveMessage::ProxyInfo {
            public_key: self.public_key.clone().unwrap().to_public_key_pem(rsa::pkcs8::LineEnding::LF).unwrap(),
            starting_hops: hops_start,
        };

        let cloves = GarlicCast::generate_cloves(proxy_info, 2, proxy.sequence_number).await;

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

        let n_1 = proxy.neighbor_1;
        let n_2 = proxy.neighbor_2;

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

    async fn accept_proxy(&self, cache: CloveCache, sequence_number: u128, second_clove: Clove, node: Node) {
        let first_clove = cache.cloves.get(&sequence_number).unwrap().clone();
        let msg_from_initiator = GarlicCast::get_message_from_cloves(first_clove.clone().clove, second_clove.clone()).await;

        if first_clove.from.id == node.id {
            println!("COULD NOT ACCEPT PROXY, RECEIVED FROM SAME NODE {}", node.address);
            self.cache.lock().await.remove_clove(sequence_number);
            return;
        }

        match msg_from_initiator {
            CloveMessage::RequestProxy { msg, public_key } => {
                let new_sequence = rand::random::<u128>();
                let proxy = Proxy {
                    sequence_number: new_sequence,
                    neighbor_1: first_clove.from.clone(),
                    neighbor_2: node.clone(),
                    neighbor_1_hops: 0,
                    neighbor_2_hops: 0,
                    public_key: RsaPublicKey::from_public_key_pem(&*public_key).unwrap(),
                    used_last: Utc::now(),
                };

                {
                    self.proxies.lock().await.push(proxy.clone());
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
            },
            _ => {
                // TODO: Manage other message types
            }
        }
    }

    pub async fn recv(&self, node: Node, garlic_msg: GarlicMessage) -> Result<Option<GarlemliaMessage>, MessageError> {
        let socket = Arc::clone(&self.socket);
        match garlic_msg.clone() {
            GarlicMessage::Forward { sequence_number, clove } => {
                {
                    if let Err(e) = self.message_handler.send_no_recv(&Arc::from(socket), self.local_node.clone(), &node.address, &GarlicMessage::build_send_is_alive(self.local_node.clone())).await {
                        eprintln!("Failed to send IsAlive to {}: {:?}", node.address, e);
                    }
                }

                println!("{} :: FORWARD {}[{}] :: {} -> {}", Utc::now(), sequence_number, clove.index, node.address, self.local_node.address);

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
                let next;
                if same_clove {
                    // Received the exact same clove twice
                    // Set the 'from' node to the old node since it is a shorter path
                    println!("{} :: SAME CLOVE {}[{}] :: {}", Utc::now(), sequence_number, clove.index, self.local_node.address);
                    node_actual = old_node.unwrap();
                    next = Err(());
                    {
                        let mut cache = self.cache.lock().await;
                        cache.seen(sequence_number);
                    }
                } else {
                    {
                        let mut cache = self.cache.lock().await;
                        next = cache.get_forward_node(CloveNode { sequence_number, node: node_actual.clone() });
                        cache.seen(sequence_number);
                    }
                }

                match next {
                    Ok(info) => {
                        match info {
                            Some(next_node) => {
                                let cache;
                                {
                                    cache = self.cache.lock().await.clone();
                                }
                                if cache.cloves.contains_key(&sequence_number) {
                                    self.accept_proxy(cache, sequence_number, clove, node_actual).await;
                                } else {
                                    self.forward(next_node, msg).await;
                                }
                                Ok(None)
                            }
                            None => {
                                let cache;
                                {
                                    cache = self.cache.lock().await.clone();
                                }
                                if cache.cloves.contains_key(&sequence_number) {
                                    self.accept_proxy(cache, sequence_number, clove, node_actual).await;
                                } else {
                                    // Receive message part from proxy or from initiator
                                    let mut collected_messages = self.collected_messages.lock().await;
                                    let msgs = collected_messages.get_mut(&sequence_number);

                                    let messages_from;
                                    if let Some(msg_vec) = msgs {
                                        msg_vec.push(garlic_msg);
                                        messages_from = msg_vec.clone();
                                    } else {
                                        collected_messages.insert(sequence_number, vec![garlic_msg.clone()]);
                                        messages_from = vec![garlic_msg];
                                    }
                                    // TODO: Check if has second part of message already
                                    // TODO: Put message together if it has the second part already
                                    println!("{} GarlicCast::recv():Completed Clove Received", self.local_node.address);
                                }
                                Ok(None)
                            }
                        }
                    }
                    Err(_) => {
                        let cache;
                        {
                            cache = self.cache.lock().await.clone();
                        }
                        if cache.cloves.contains_key(&sequence_number) && !same_clove {
                            self.accept_proxy(cache, sequence_number, clove, node_actual).await;
                        } else if random_bool(FORWARD_P) {
                            // First time seeing this sequence number and forwarding it
                            self.forward_to_new(sequence_number, node_actual.clone(), msg.clone()).await;
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
                                        // TODO: Begin to find alt node for this sequence number
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
                                            let msg_from_initiator = GarlicCast::get_message_from_cloves(cloves[0].clone(), cloves[1].clone()).await;

                                            match msg_from_initiator {
                                                CloveMessage::ProxyInfo { public_key, starting_hops} => {
                                                    let proxy = Proxy {
                                                        sequence_number: updated_sequence_number,
                                                        neighbor_1,
                                                        neighbor_2: node.clone(),
                                                        neighbor_1_hops: neighbor_1_hops - starting_hops,
                                                        neighbor_2_hops: hops - starting_hops,
                                                        public_key: RsaPublicKey::from_public_key_pem(&*public_key).unwrap(),
                                                        used_last: Utc::now(),
                                                    };

                                                    {
                                                        self.proxies.lock().await.push(proxy.clone());
                                                        self.collected_messages.lock().await.remove(&updated_sequence_number);
                                                    }

                                                    println!("{} RECEIVED A PROXY FOR #{} -> #{}", self.local_node.address, sequence_number, updated_sequence_number);

                                                    // TODO: Send back ProxyRouteInfo to proxy
                                                    // TODO: Begin to find alt node for this sequence number
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
                                    self.partial_proxies.lock().await.insert(updated_sequence_number, node);
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
            GarlicMessage::RequestAlt { .. } => {
                Ok(None)
            }
            GarlicMessage::RefreshAlt { .. } => {
                Ok(None)
            }
            GarlicMessage::UpdateAlt { .. } => {
                Ok(None)
            }
            GarlicMessage::AgreeAlt { .. } => {
                Ok(None)
            }
            _ => {
                Ok(None)
            }
        }
    }
}