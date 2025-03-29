use crate::time_hash::time_based_hash::{HashLocation, RotatingHash};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use primitive_types::U256;
use rand::{rng, RngCore};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{HashMap, VecDeque};
use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{mpsc, mpsc::UnboundedReceiver, Mutex};
use tokio::time::{timeout, Duration};

pub fn u256_random() -> U256 {
    let mut rng = rng();
    let mut buf = [0u8; 32];
    rng.fill_bytes(&mut buf);
    U256::from_big_endian(&buf)
}

/// Custom error type for messaging operations.
#[derive(Debug, Clone)]
pub enum MessageError {
    IoError(String),
    NoRX,
    NoTX,
    TXDropped,
    TXSendError,
    Timeout,
    MissingResponse,
    MissingNode,
    SerializationError(String),
}

impl From<std::io::Error> for MessageError {
    fn from(err: std::io::Error) -> Self {
        MessageError::IoError(err.to_string())
    }
}

/// Helper struct for a min-heap (using reverse ordering)
#[derive(Eq)]
pub struct HeapNode {
    pub distance: U256,
    pub node: Node,
}

impl Ord for HeapNode {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering to simulate a min-heap.
        other.distance.cmp(&self.distance)
    }
}

impl PartialOrd for HeapNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for HeapNode {
    fn eq(&self, other: &Self) -> bool {
        self.distance == other.distance
    }
}

pub const DEFAULT_K: usize = 20;
pub const MAX_K: usize = 40;

pub const LOOKUP_ALPHA: usize = 3;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Node {
    pub id: U256,
    pub address: SocketAddr,
}

impl Node {
    pub fn update(&mut self, other: &Node) {
        self.id = other.id;
        self.address = other.address;
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq)]
pub struct KBucket {
    pub nodes: VecDeque<Node>,
    max_size: usize,
}

impl KBucket {
    pub fn new() -> Self {
        Self {
            nodes: VecDeque::with_capacity(DEFAULT_K),
            max_size: DEFAULT_K,
        }
    }

    pub fn new_with_node(node: Node) -> Self {
        let mut bucket = Self::new();
        bucket.nodes.push_back(node);
        bucket
    }

    pub fn insert(&mut self, node: Node) {
        self.nodes.push_back(node);
    }

    pub fn remove(&mut self, node: &Node) {
        if let Some(pos) = self.nodes.iter().position(|n| n.id == node.id) {
            self.nodes.remove(pos);
        }
    }

    pub fn update_node(&mut self, node: Node) {
        self.remove(&node);
        self.insert(node);
    }

    pub fn contains(&self, node_id: U256) -> bool {
        self.nodes.iter().any(|n| n.id == node_id)
    }

    pub fn is_full(&self) -> bool {
        self.nodes.len() >= self.max_size
    }

    pub fn try_increase_capacity(&mut self) {
        if self.max_size < MAX_K {
            self.max_size += 5;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableRoutingTable {
    pub local_node: Node,
    pub buckets: HashMap<u8, KBucket>
}

impl SerializableRoutingTable {
    pub async fn from(routing_table: RoutingTable) -> SerializableRoutingTable {
        SerializableRoutingTable {
            local_node: routing_table.local_node,
            buckets: routing_table.buckets.lock().await.clone(),
        }
    }

    pub fn to_routing_table(self) -> RoutingTable {
        RoutingTable {
            local_node: self.local_node,
            buckets: Arc::new(Mutex::new(self.buckets))
        }
    }
}

// TODO: Implement last_seen information for nodes in routing table
#[derive(Debug, Clone)]
pub struct RoutingTable {
    local_node: Node,
    buckets: Arc<Mutex<HashMap<u8, KBucket>>>
}

impl RoutingTable {
    pub fn new(local_node: Node) -> Self {
        Self {
            local_node,
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn update_from(&mut self, other: RoutingTable) {
        self.local_node = other.local_node().clone();
        let mut self_buckets = self.buckets.lock().await;
        self_buckets.clear();

        let other_buckets = other.buckets.lock().await;
        for bucket in other_buckets.iter() {
            self_buckets.insert(*bucket.0, bucket.1.clone());
        }
    }

    fn local_node(&self) -> &Node {
        &self.local_node
    }

    pub async fn buckets(&self) -> HashMap<u8, KBucket> {
        self.buckets.lock().await.clone()
    }

    pub fn bucket_index(&self, node_id: U256) -> u8 {
        let xor_distance = self.local_node.id ^ node_id;

        if xor_distance == U256::from(0) {
            return 0;
        }

        (255 - xor_distance.leading_zeros()) as u8
    }

    pub async fn flat_nodes(&self) -> Vec<Node> {
        self.buckets
            .lock()
            .await
            .values()
            .flat_map(|bucket| bucket.nodes.iter().cloned())
            .collect()
    }

    pub async fn insert_direct(&mut self, node: Node) {
        let index = self.bucket_index(node.id);
        self.buckets
            .lock()
            .await
            .entry(index)
            .or_insert_with(KBucket::new)
            .insert(node);
    }

    pub async fn check_and_update_bucket(&mut self, node: Node, index: u8) -> bool {
        let mut self_buckets = self.buckets.lock().await;
        if let Some(bucket) = self_buckets.get_mut(&index) {
            if bucket.contains(node.clone().id) {
                bucket.update_node(node);
                return true;
            } else {
                if !bucket.is_full() {
                    bucket.insert(node);
                    return true;
                }
            }
            false
        } else {
            self_buckets.insert(index, KBucket::new());
            self_buckets.get_mut(&index).unwrap().insert(node);
            true
        }
    }

    pub async fn add_node_from_responder(&mut self, message_handler: Arc<Box<dyn GMessage>>, node: Node, socket: Arc<UdpSocket>) {
        if self.local_node.id == node.id {
            return;
        }

        let index = self.bucket_index(node.id);
        if self.check_and_update_bucket(node.clone(), index).await {
            return;
        }

        let self_buckets = Arc::clone(&self.buckets);
        let mh = Arc::clone(&message_handler);
        let local_node = self.local_node.clone();
        let node_clone = node.clone();
        let socket_clone = Arc::clone(&socket);
        tokio::spawn(async move {
            let bucket_clone;
            {
                bucket_clone = self_buckets.lock().await.get_mut(&index).unwrap().clone();
            }

            if let Some(lru_node) = bucket_clone.nodes.front().cloned() {
                let ping_msg = GarlemliaMessage::Ping {
                    sender: local_node.clone(),
                };

                {
                    // If sending fails, log the error and continue.
                    if let Err(e) = mh.send(&socket_clone, local_node.clone(), &lru_node.address, &ping_msg).await {
                        eprintln!("Failed to send ping to {}: {:?}", lru_node.address, e);
                        let mut locked_buckets = self_buckets.lock().await;
                        let bucket = locked_buckets.get_mut(&index).unwrap();
                        bucket.remove(&lru_node);
                        bucket.insert(node_clone);
                        return;
                    }
                }

                {
                    match mh.recv(300, &lru_node.address).await {
                        Ok(GarlemliaMessage::Pong { sender, .. }) if sender.id == lru_node.id => {
                            let mut locked_buckets = self_buckets.lock().await;
                            let bucket = locked_buckets.get_mut(&index).unwrap();
                            bucket.update_node(lru_node);
                        }
                        Ok(_) | Err(_) => {
                            let mut locked_buckets = self_buckets.lock().await;
                            let bucket = locked_buckets.get_mut(&index).unwrap();
                            bucket.remove(&lru_node);
                            bucket.insert(node_clone);
                        }
                    }
                }
            }
        });
    }

    pub async fn add_node(&mut self, message_handler: Arc<Box<dyn GMessage>>, node: Node, socket: &UdpSocket) {
        if self.local_node.id == node.id {
            return;
        }

        let index = self.bucket_index(node.id);
        if self.check_and_update_bucket(node.clone(), index).await {
            return;
        }

        let mut locked_buckets = self.buckets.lock().await;
        let bucket = locked_buckets.get_mut(&index).unwrap();
        if let Some(lru_node) = bucket.nodes.front().cloned() {
            let ping_msg = GarlemliaMessage::Ping {
                sender: self.local_node.clone(),
            };

            if let Err(e) = message_handler.send(socket, self.local_node.clone(), &lru_node.address, &ping_msg).await {
                eprintln!("Failed to send ping to {}: {:?}", lru_node.address, e);
                bucket.remove(&lru_node);
                bucket.insert(node);
                return;
            }

            match message_handler.recv(300, &lru_node.address).await {
                Ok(GarlemliaMessage::Pong { sender, .. }) if sender.id == lru_node.id => {
                    bucket.update_node(lru_node);
                }
                Ok(_) | Err(_) => {
                    bucket.remove(&lru_node);
                    bucket.insert(node);
                }
            }
        }
    }

    pub async fn find_closest_nodes(&self, target_id: U256, count: usize) -> Vec<Node> {
        // Always include self
        let mut candidates = vec![self.local_node.clone()];

        // Lock the buckets and extract a sorted list of bucket indices.
        let buckets = self.buckets.lock().await;
        let mut bucket_indices: Vec<u8> = buckets.keys().cloned().collect();
        bucket_indices.sort();

        // Determine the bucket index for the target.
        let target_bucket = self.bucket_index(target_id);

        // Find the position in the sorted bucket list.
        // If no bucket has an index >= target_bucket, start with the last one.
        let pos = bucket_indices
            .iter()
            .position(|&i| i >= target_bucket)
            .unwrap_or(bucket_indices.len().saturating_sub(1));

        // Add nodes from the bucket that contains the target (if it exists)
        if let Some(bucket) = buckets.get(&bucket_indices[pos]) {
            candidates.extend(bucket.nodes.iter().cloned());
        }

        // Expand outwards from the target bucket.
        let mut left: isize = pos as isize - 1;
        let mut right: isize = pos as isize + 1;

        while candidates.len() < count && (left >= 0 || (right as usize) < bucket_indices.len()) {
            if right < bucket_indices.len() as isize {
                if let Some(bucket) = buckets.get(&bucket_indices[right as usize]) {
                    candidates.extend(bucket.nodes.iter().cloned());
                }
                right += 1;
            }
            if candidates.len() >= count {
                break;
            }
            if left >= 0 {
                if let Some(bucket) = buckets.get(&bucket_indices[left as usize]) {
                    candidates.extend(bucket.nodes.iter().cloned());
                }
                left -= 1;
            }
        }

        // Sort the gathered nodes by XOR distance to target_id.
        candidates.sort_by_key(|node| node.id ^ target_id);
        candidates.truncate(count);
        candidates
    }

    pub async fn to_string(&self) -> String {
        let mut last: String = "ROUTING TABLE {\n".to_string();

        let mut bucket_strings = HashMap::new();
        let mut bucket_ids = vec![];
        for bucket in self.buckets.lock().await.iter() {
            let mut temp: String = "".to_string();
            temp.push_str("\t{\n");
            temp.push_str(format!("\t\tID: {},\n\t\tCOUNT: {},\n", bucket.0, bucket.1.nodes.len()).as_str());
            temp.push_str("\t\t{\n");
            temp.push_str("\t\t\t");

            for node in bucket.1.nodes.clone() {
                temp.push_str("{ ");
                temp.push_str(format!("id: {}, address: {}", node.id, node.address).as_str());
                temp.push_str(" }, ");
            }

            temp.push_str("\n\t\t},\n");
            temp.push_str("\t},\n");

            bucket_strings.insert(bucket.0.clone(), temp.clone());
            bucket_ids.push(bucket.0.clone());
        }
        bucket_ids.sort();

        for bucket_id in bucket_ids {
            last.push_str(bucket_strings.get(&bucket_id).unwrap().as_str());
        }

        last.push_str("}");

        last
    }

    pub fn random_id_for_bucket(self_id: U256, bucket_index: u8) -> U256 {
        // The bit we want to differ at (counting from the left,
        // where 0 = top bit, 255 = bottom bit):
        let bit_pos = 255 - bucket_index;

        // 1. Flip that bit from self_id.
        //    We'll construct a mask that has only that bit set:
        let flip_mask = U256::from(1) << bit_pos;
        let mut candidate = self_id ^ flip_mask;

        // 2. Now randomize all the bits below `bit_pos`.
        //    That means the `bit_pos` least significant bits can be anything.
        //    We can generate a random 256-bit number, but then zero out
        //    all bits except the lower `bit_pos`.
        //
        //    If bit_pos is 0, that means we only flipped the top bit
        //    and there's no "lower bits" to randomize, so handle that case:
        if bit_pos > 0 {
            // e.g. for bit_pos=5, we want to keep only bits [0..4].
            let mask_below = (U256::from(1) << bit_pos) - 1;  // e.g. (1 << 5) - 1 = 0b11111

            // A random U256 from the standard RNG:
            let random_lower: U256 = u256_random();

            // Keep only the lower bit_pos bits:
            let random_bits = random_lower & mask_below;

            // Combine these random bits into candidate:
            // First, zero out the bits below bit_pos (they might already be zero, but let's be explicit)
            candidate &= !mask_below;  // not strictly needed since we already matched above bit
            // Then OR in the random bits
            candidate |= random_bits;
        }

        candidate
    }
}

/// A simple channel message that carries identifying information.
#[derive(Debug, Clone)]
pub struct MessageChannel {
    pub node_id: U256,
    pub msg: GarlemliaMessage,
}

#[async_trait]
pub trait GMessage: Send + Sync {
    fn create(channel_count: u8) -> Box<dyn GMessage> where Self: Sized;
    async fn send_tx(&self, addr: SocketAddr, msg: MessageChannel) -> Result<(), MessageError>;
    async fn send_no_recv(&self, socket: &UdpSocket, from_node: Node, target: &SocketAddr, msg: &GarlemliaMessage) -> Result<Option<GarlemliaMessage>, MessageError>;
    async fn send(&self, socket: &UdpSocket, from_node: Node, target: &SocketAddr, msg: &GarlemliaMessage) -> Result<Option<GarlemliaMessage>, MessageError>;
    async fn recv(&self, timeout_ms: u64, src: &SocketAddr) -> Result<GarlemliaMessage, MessageError>;
    fn clone_box(&self) -> Box<dyn GMessage>;

    fn debug_fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "GMessage Trait Object")
    }
}

impl Clone for Box<dyn GMessage> {
    fn clone(&self) -> Box<dyn GMessage> {
        self.clone_box()
    }
}

impl Debug for dyn GMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        self.debug_fmt(f)
    }
}

#[derive(Debug, Clone)]
pub struct HandlerChannelReceiver {
    id: u8,
    rx: Arc<Mutex<UnboundedReceiver<MessageChannel>>>,
}

#[derive(Debug, Clone)]
pub struct HandlerChannelSender {
    id: u8,
    pub tx: Arc<Mutex<UnboundedSender<MessageChannel>>>,
}

#[derive(Debug, Default, Clone)]
pub struct GarlemliaMessageHandler {
    available_rx: Arc<Mutex<Vec<HandlerChannelReceiver>>>,
    unavailable_rx: Arc<Mutex<HashMap<String, HandlerChannelReceiver>>>,
    available_tx: Arc<Mutex<Vec<HandlerChannelSender>>>,
    unavailable_tx: Arc<Mutex<HashMap<String, HandlerChannelSender>>>,
}

#[async_trait]
impl GMessage for GarlemliaMessageHandler {
    fn create(channel_count: u8) -> Box<dyn GMessage> {
        // Build up our “available” pools:
        let mut rx_pool = Vec::with_capacity(channel_count as usize);
        let mut tx_pool = Vec::with_capacity(channel_count as usize);

        for i in 0..channel_count {
            let (tx, rx) = mpsc::unbounded_channel::<MessageChannel>();
            rx_pool.push(HandlerChannelReceiver {
                id: i,
                rx: Arc::new(Mutex::new(rx)),
            });
            tx_pool.push(HandlerChannelSender {
                id: i,
                tx: Arc::new(Mutex::new(tx)),
            });
        }

        Box::new(GarlemliaMessageHandler {
            available_rx: Arc::new(Mutex::new(rx_pool)),
            available_tx: Arc::new(Mutex::new(tx_pool)),
            unavailable_rx: Arc::new(Mutex::new(HashMap::new())),
            unavailable_tx: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Look up the “unavailable” TX for this address. (i.e., a TX currently assigned to that address)
    async fn send_tx(&self, addr: SocketAddr, msg: MessageChannel) -> Result<(), MessageError> {
        let map = self.unavailable_tx.lock().await;
        let tx_info = map.get(&addr.to_string());

        match tx_info {
            Some(tx_good) => {
                let tx = tx_good.tx.lock().await;
                if tx.is_closed() {
                    Err(MessageError::TXDropped)
                } else {
                    let send_info = tx.send(msg);

                    if send_info.is_err() {
                        Err(MessageError::TXSendError)
                    } else {
                        Ok(())
                    }
                }
            }
            None => {
                Err(MessageError::NoTX)
            }
        }
    }

    async fn send_no_recv(&self, socket: &UdpSocket, _from_node: Node, target: &SocketAddr, msg: &GarlemliaMessage) -> Result<Option<GarlemliaMessage>, MessageError> {
        // Now actually send the UDP message
        let bytes = serde_json::to_vec(msg)
            .map_err(|e| MessageError::SerializationError(e.to_string()))?;
        socket.send_to(&bytes, target).await?;
        Ok(None)
    }

    /// Takes an RX/TX from the “available” pool, assigns it to the `target`, and sends the given message.
    async fn send(&self, socket: &UdpSocket, _from_node: Node, target: &SocketAddr, msg: &GarlemliaMessage) -> Result<Option<GarlemliaMessage>, MessageError> {
        let mut need_rx = true;

        // Try once outside the loop
        {
            let mut rx_pool = self.available_rx.lock().await;
            if !rx_pool.is_empty() {
                need_rx = false;
                let mut tx_pool = self.available_tx.lock().await;

                // Pop one receiver
                let receiver = rx_pool.pop().unwrap();
                // Find a matching TX with the same ID
                if let Some(index) = tx_pool.iter().position(|tx| tx.id == receiver.id) {
                    let sender = tx_pool.remove(index);

                    // Move them to “unavailable”
                    println!("Setting used RX/TX at {}", target.to_string());
                    self.unavailable_rx.lock().await.insert(target.to_string(), receiver);
                    self.unavailable_tx.lock().await.insert(target.to_string(), sender);
                } else {
                    println!("Error: Could not find a matching TX for RX ID {}", receiver.id);
                }
            }
        }

        // If none were available, wait until something is freed
        while need_rx {
            println!("WAITING FOR RX TO BECOME AVAILABLE...");
            tokio::time::sleep(Duration::from_millis(10)).await;

            let mut rx_pool = self.available_rx.lock().await;
            if !rx_pool.is_empty() {
                need_rx = false;
                let mut tx_pool = self.available_tx.lock().await;

                // Pop one receiver
                let receiver = rx_pool.pop().unwrap();
                // Find a matching TX with the same ID
                if let Some(index) = tx_pool.iter().position(|tx| tx.id == receiver.id) {
                    let sender = tx_pool.remove(index);

                    // Move them to “unavailable”
                    println!("Setting used RX/TX at {}", target.to_string());
                    self.unavailable_rx.lock().await.insert(target.to_string(), receiver);
                    self.unavailable_tx.lock().await.insert(target.to_string(), sender);
                } else {
                    println!("Error: Could not find a matching TX for RX ID {}", receiver.id);
                }
            }
        }

        println!("Sent to {}", target);

        // Now actually send the UDP message
        let bytes = serde_json::to_vec(msg)
            .map_err(|e| MessageError::SerializationError(e.to_string()))?;
        socket.send_to(&bytes, target).await?;
        Ok(None)
    }

    /// Receives a message from the “unavailable” RX assigned to `src`, then returns that RX/TX pair to the pool.
    async fn recv(&self, timeout_ms: u64, src: &SocketAddr) -> Result<GarlemliaMessage, MessageError> {
        // Attempt to find the assigned RX for this address
        let maybe_rx = {
            let mut rx_map = self.unavailable_rx.lock().await;
            rx_map.get_mut(&src.to_string()).cloned()
        };

        let channel_receiver = match maybe_rx {
            Some(rx) => rx,
            None => {
                println!("No RX found for address {:?}", src);
                return Err(MessageError::NoRX);
            }
        };

        // Actually receive from that channel with a timeout
        let msg_result = {
            let mut guard = channel_receiver.rx.lock().await;
            match timeout(Duration::from_millis(timeout_ms), guard.recv()).await {
                Ok(Some(msg_channel)) => Ok(msg_channel),
                Ok(None) => Err(MessageError::MissingResponse),
                Err(_) => Err(MessageError::Timeout),
            }
        };

        // Move the assigned TX/RX back to “available”
        let mut tx_map = self.unavailable_tx.lock().await;
        let maybe_tx = tx_map.remove(&src.to_string());

        // Also remove the RX from the unavailable set
        let mut rx_map = self.unavailable_rx.lock().await;
        let maybe_rx2 = rx_map.remove(&src.to_string());

        if let Some(tx) = maybe_tx {
            self.available_tx.lock().await.push(tx);
        } else {
            println!("Warning: Could not find matching TX for {:?}", src);
        }

        if let Some(rx) = maybe_rx2 {
            self.available_rx.lock().await.push(rx);
        } else {
            println!("Warning: Could not find matching RX for {:?}", src);
        }

        // Return the final GarlemliaMessage or an error
        match msg_result {
            Ok(channel) => Ok(channel.msg),
            Err(e) => {
                println!("Error: Did not receive message due to {:?}", e);
                Err(e)
            }
        }
    }

    fn clone_box(&self) -> Box<dyn GMessage> {
        Box::new(self.clone())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChunkInfo {
    pub index: usize,
    pub chunk_id: U256,
    pub size: usize
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum GarlemliaData {
    Value { id: U256, value: String },
    Validator { id: U256, proxy_ids: Vec<U256>, proxies: HashMap<U256, SocketAddr> },
    FileName { id: U256, name: String, file_type: String, size: usize, categories: Vec<String>, metadata_location: RotatingHash, key_location: RotatingHash },
    MetaData { id: U256, file_id: U256, chunk_info: Vec<ChunkInfo>, downloads: usize, availability: f64, metadata_location: RotatingHash },
    FileKey { id: U256, enc_file_id: U256, decryption_key: String, key_location: RotatingHash },
    FileChunk { id: U256, size: usize }
}

impl GarlemliaData {
    pub fn get_id(&self) -> U256 {
        match self {
            GarlemliaData::Value { id, .. } => *id,
            GarlemliaData::Validator { id, .. } => *id,
            GarlemliaData::FileName { id, .. } => *id,
            GarlemliaData::MetaData { id, .. } => *id,
            GarlemliaData::FileKey { id, .. } => *id,
            GarlemliaData::FileChunk { id, .. } => *id,
        }
    }

    pub fn get_response(&self, request: GarlemliaFindRequest) -> Option<GarlemliaResponse> {
        match self {
            GarlemliaData::Value { value, .. } => {
                Some(GarlemliaResponse::Value {
                    value: value.to_string()
                })
            }
            GarlemliaData::Validator { proxy_ids, proxies, .. } => {
                let mut res = GarlemliaResponse::Validator {
                    proxy: None
                };

                match request {
                    GarlemliaFindRequest::Validator { proxy_id, .. } => {
                        let mut ids = proxy_ids.clone();
                        while ids.len() > 0 {
                            let check_id = ids.remove(rand::random_range(0..ids.len()));

                            if check_id != proxy_id {
                                res = GarlemliaResponse::Validator {
                                    proxy: proxies.get(&check_id).cloned()
                                };
                                break;
                            }
                        }
                    }
                    _ => {}
                }

                Some(res)
            }
            GarlemliaData::FileName { name, file_type, size, categories, metadata_location, key_location, .. } => {
                Some(GarlemliaResponse::FileName {
                    name: name.clone(),
                    file_type: file_type.clone(),
                    size: size.clone(),
                    categories: categories.clone(),
                    metadata_location: metadata_location.get_next(24, 1.0).unwrap(),
                    key_location: key_location.get_next(24, 1.0).unwrap()
                })
            }
            GarlemliaData::MetaData { file_id, chunk_info, downloads, availability, .. } => {
                Some(GarlemliaResponse::MetaData {
                    file_id: file_id.clone(),
                    chunk_info: chunk_info.clone(),
                    downloads: downloads.clone(),
                    availability: availability.clone()
                })
            }
            GarlemliaData::FileKey { enc_file_id, decryption_key, .. } => {
                Some(GarlemliaResponse::FileKey {
                    enc_file_id: enc_file_id.clone(),
                    decryption_key: decryption_key.clone()
                })
            }
            _ => {
                None
            }
        }
    }

    pub fn get_chunk_response(&self, data: Vec<u8>) -> Option<GarlemliaResponse> {
        match self {
            GarlemliaData::FileChunk { id, size } => {
                Some(GarlemliaResponse::FileChunk {
                    chunk_id: id.clone(),
                    chunk_size: size.clone(),
                    data,
                })
            },
            _ => None
        }
    }

    pub fn is_chunk(&self) -> bool {
        match self {
            GarlemliaData::FileChunk { .. } => true,
            _ => false
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum GarlemliaStoreRequest {
    Value { id: U256, value: String },
    Validator { id: U256, proxy_id: U256 },
    FileName { id: U256, name: String, file_type: String, size: usize, categories: Vec<String>, metadata_location: RotatingHash, key_location: RotatingHash },
    MetaData { id: U256, file_id: U256, chunk_info: Vec<ChunkInfo>, downloads: usize, availability: f64, metadata_location: RotatingHash },
    FileKey { id: U256, enc_file_id: U256, decryption_key: String, key_location: RotatingHash },
    FileChunk { id: U256, chunk_size: usize, data: Vec<u8> }
}

impl GarlemliaStoreRequest {
    pub fn get_id(&self) -> U256 {
        match self {
            GarlemliaStoreRequest::Value { id, .. } => *id,
            GarlemliaStoreRequest::Validator { id, .. } => *id,
            GarlemliaStoreRequest::FileName { id, .. } => *id,
            GarlemliaStoreRequest::MetaData { id, .. } => *id,
            GarlemliaStoreRequest::FileKey { id, .. } => *id,
            GarlemliaStoreRequest::FileChunk { id, .. } => *id,
        }
    }

    pub fn to_store_data(&self) -> Option<GarlemliaData> {
        match self {
            GarlemliaStoreRequest::Value { id, value } => {
                Some(GarlemliaData::Value {
                    id: id.clone(),
                    value: value.to_string()
                })
            }
            GarlemliaStoreRequest::FileName { id, name, file_type, size, categories, metadata_location, key_location } => {
                Some(GarlemliaData::FileName {
                    id: id.clone(),
                    name: name.clone(),
                    file_type: file_type.clone(),
                    size: size.clone(),
                    categories: categories.clone(),
                    metadata_location: metadata_location.clone(),
                    key_location: key_location.clone()
                })
            }
            GarlemliaStoreRequest::MetaData { id, file_id, chunk_info, downloads, availability, metadata_location } => {
                Some(GarlemliaData::MetaData {
                    id: id.clone(),
                    file_id: file_id.clone(),
                    chunk_info: chunk_info.clone(),
                    downloads: downloads.clone(),
                    availability: availability.clone(),
                    metadata_location: metadata_location.clone()
                })
            }
            GarlemliaStoreRequest::FileKey { id, enc_file_id, decryption_key, key_location } => {
                Some(GarlemliaData::FileKey {
                    id: id.clone(),
                    enc_file_id: enc_file_id.clone(),
                    decryption_key: decryption_key.clone(),
                    key_location: key_location.clone()
                })
            }
            GarlemliaStoreRequest::FileChunk { id, chunk_size, .. } => {
                Some(GarlemliaData::FileChunk {
                    id: id.clone(),
                    size: chunk_size.clone()
                })
            }
            _ => {
                None
            }
        }
    }

    pub fn validator_get_proxy_id(&self) -> Option<U256> {
        match self {
            GarlemliaStoreRequest::Validator { proxy_id, .. } => Some(*proxy_id),
            _ => None
        }
    }

    pub fn is_validator(&self) -> bool {
        match self {
            GarlemliaStoreRequest::Validator { .. } => true,
            _ => false
        }
    }

    pub fn chunk_get_data(&self) -> Option<Vec<u8>> {
        match self {
            GarlemliaStoreRequest::FileChunk { data, .. } => Some(data.clone()),
            _ => None
        }
    }

    pub fn is_chunk(&self) -> bool {
        match self {
            GarlemliaStoreRequest::FileChunk { .. } => true,
            _ => false
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum GarlemliaFindRequest {
    Key { id: U256 },
    Validator { id: U256, proxy_id: U256 }
}

impl GarlemliaFindRequest {
    pub fn get_id(&self) -> U256 {
        match self {
            GarlemliaFindRequest::Key { id } => *id,
            GarlemliaFindRequest::Validator { id, .. } => *id,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum GarlemliaResponse {
    Value { value: String },
    Validator { proxy: Option<SocketAddr> },
    FileName { name: String, file_type: String, size: usize, categories: Vec<String>, metadata_location: Vec<HashLocation>, key_location: Vec<HashLocation> },
    MetaData { file_id: U256, chunk_info: Vec<ChunkInfo>, downloads: usize, availability: f64 },
    FileKey { enc_file_id: U256, decryption_key: String },
    FileChunk { chunk_id: U256, chunk_size: usize, data: Vec<u8> }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum GarlemliaMessage {
    FindNode { id: U256, sender: Node },
    Store { key: U256, value: GarlemliaStoreRequest, sender: Node },
    FindValue { request: GarlemliaFindRequest, sender: Node },
    Response { nodes: Vec<Node>, value: Option<GarlemliaResponse>, sender: Node },
    Garlic { msg: GarlicMessage, sender: Node },
    Ping { sender: Node },
    Pong { sender: Node },
    SearchFile { search_id: U256, proxy_id: U256, search_term: String, sender: Node },
    AgreeAlt { alt_sequence_number: U256, sender: Node },
    Stop { }
}

impl GarlemliaMessage {
    pub fn sender_id(&self) -> U256 {
        match self {
            GarlemliaMessage::FindNode { sender, .. } => sender.id.clone(),
            GarlemliaMessage::Store { sender, .. } => sender.id.clone(),
            GarlemliaMessage::FindValue { sender, .. } => sender.id.clone(),
            GarlemliaMessage::Response { sender, .. } => sender.id.clone(),
            GarlemliaMessage::Garlic { sender, .. } => sender.id.clone(),
            GarlemliaMessage::Ping { sender} => sender.id.clone(),
            GarlemliaMessage::Pong { sender, .. } => sender.id.clone(),
            GarlemliaMessage::SearchFile { sender, ..} => sender.id.clone(),
            GarlemliaMessage::AgreeAlt { sender, .. } => sender.id.clone(),
            GarlemliaMessage::Stop {} => U256::from(0)
        }
    }

    pub fn sender(&self) -> Option<Node> {
        match self {
            GarlemliaMessage::FindNode { sender, .. } => Some(sender.clone()),
            GarlemliaMessage::Store { sender, .. } => Some(sender.clone()),
            GarlemliaMessage::FindValue { sender, .. } => Some(sender.clone()),
            GarlemliaMessage::Response { sender, .. } => Some(sender.clone()),
            GarlemliaMessage::Garlic { sender, .. } => Some(sender.clone()),
            GarlemliaMessage::Ping { sender} => Some(sender.clone()),
            GarlemliaMessage::Pong { sender, .. } => Some(sender.clone()),
            GarlemliaMessage::SearchFile { sender, ..} => Some(sender.clone()),
            GarlemliaMessage::AgreeAlt { sender, .. } => Some(sender.clone()),
            GarlemliaMessage::Stop {} => None
        }
    }
}

/// GARLIC CAST STRUCTS

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Clove {
    pub sequence_number: U256,
    pub request_id: U256,
    pub msg_fragment: Vec<u8>,
    pub key_fragment: Vec<u8>,
    pub sent: DateTime<Utc>,
    pub index: u8,
    pub ida_count: u8
}

impl Clove {
    pub fn update_sequence(&mut self, new_sequence_number: U256) -> Clove {
        self.sequence_number = new_sequence_number;
        self.clone()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CloveData {
    pub clove: Clove,
    pub from: Node
}

#[derive(Clone, Debug, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub struct CloveNode {
    // The sequence number used when sending to this node
    // Most of the time it will be the chain sequence number, but if it is an alt node
    // then it will be the randomly generated sequence number
    pub sequence_number: U256,
    pub node: Node
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum CloveMessage {
    RequestProxy {
        msg: String,
        public_key: String,
    },
    ProxyInfo {
        public_key: String,
        starting_hops: u16
    },
    Store {
        request_id: U256,
        data: GarlemliaStoreRequest
    },
    SearchOverlay {
        request_id: U256,
        proxy_id: U256,
        search_term: String,
        public_key: String
    },
    SearchGarlemlia {
        request_id: U256,
        key: U256,
        public_key: String
    },
    ResponseDirect {
        request_id: U256,
        address: SocketAddr,
        data: Vec<u8>,
        public_key: String
    },
    ResponseWithValidator {
        request_id: U256,
        proxy_id: U256,
        data: Vec<u8>,
        public_key: String
    }
}

impl CloveMessage {
    pub fn request_id(&self) -> U256 {
        match self {
            CloveMessage::RequestProxy { .. } => {U256::from(0)}
            CloveMessage::ProxyInfo { .. } => {U256::from(0)}
            CloveMessage::Store { request_id, .. } => {request_id.clone()}
            CloveMessage::SearchOverlay { request_id, .. } => {request_id.clone()}
            CloveMessage::SearchGarlemlia { request_id, .. } => {request_id.clone()}
            CloveMessage::ResponseDirect { request_id, .. } => {request_id.clone()}
            CloveMessage::ResponseWithValidator { request_id, .. } => {request_id.clone()}
        }
    }

    pub fn proxy_id(&self) -> Option<U256> {
        match self {
            CloveMessage::RequestProxy { .. } => {None}
            CloveMessage::ProxyInfo { .. } => {None}
            CloveMessage::Store { .. } => {None}
            CloveMessage::SearchOverlay { proxy_id, .. } => {Some(proxy_id.clone())}
            CloveMessage::SearchGarlemlia { .. } => {None}
            CloveMessage::ResponseDirect { .. } => {None}
            CloveMessage::ResponseWithValidator { proxy_id, .. } => {Some(proxy_id.clone())}
        }
    }

    pub fn is_request(&self) -> bool {
        match self {
            CloveMessage::RequestProxy { .. } => {false}
            CloveMessage::ProxyInfo { .. } => {false}
            CloveMessage::Store { .. } => {true}
            CloveMessage::SearchOverlay { .. } => {true}
            CloveMessage::SearchGarlemlia { .. } => {true}
            CloveMessage::ResponseDirect { .. } => {true}
            CloveMessage::ResponseWithValidator { .. } => {true}
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum GarlicMessage {
    FindProxy {
        sequence_number: U256,
        clove: Clove
    },
    Forward {
        sequence_number: U256,
        clove: Clove
    },
    ProxyAgree {
        sequence_number: U256,
        updated_sequence_number: U256,
        hops: u16,
        clove: Clove
    },
    RequestAlt {
        alt_sequence_number: U256,
        next_hop: Node,
        last_hop: Node
    },
    RefreshAlt {
        sequence_number: U256
    },
    UpdateAlt {
        sequence_number: U256,
        alt_node: CloveNode
    },
    UpdateAltNextOrLast {
        sequence_number: U256,
        old_node: Node,
        new_node: Node
    }
}

impl GarlicMessage {
    pub fn sequence_number(&self) -> U256 {
        match self {
            GarlicMessage::FindProxy { sequence_number, .. } => {sequence_number.clone()}
            GarlicMessage::Forward { sequence_number, .. } => {sequence_number.clone()}
            GarlicMessage::ProxyAgree { sequence_number, .. } => {sequence_number.clone()}
            GarlicMessage::RequestAlt { .. } => {U256::from(0)}
            GarlicMessage::RefreshAlt { .. } => {U256::from(0)}
            GarlicMessage::UpdateAlt { .. } => {U256::from(0)}
            GarlicMessage::UpdateAltNextOrLast { .. } => {U256::from(0)}
        }
    }

    pub fn update_sequence_number(&mut self, new_sequence_number: U256) {
        match self {
            GarlicMessage::Forward { clove, .. } => {
                *self = GarlicMessage::Forward {
                    sequence_number: new_sequence_number,
                    clove: clove.update_sequence(new_sequence_number)
                };
            }
            GarlicMessage::UpdateAlt { alt_node, .. } => {
                *self = GarlicMessage::UpdateAlt {
                    sequence_number: new_sequence_number,
                    alt_node: alt_node.clone(),
                };
            }
            _ => {}
        }
    }

    pub fn clove(&self) -> Option<Clove> {
        match self {
            GarlicMessage::FindProxy { clove, .. } => {Some(clove.clone().clone())}
            GarlicMessage::Forward { clove, .. } => {Some(clove.clone().clone())}
            GarlicMessage::ProxyAgree { clove, .. } => {Some(clove.clone())}
            GarlicMessage::RequestAlt { .. } => {None}
            GarlicMessage::RefreshAlt { .. } => {None}
            GarlicMessage::UpdateAlt { .. } => {None}
            GarlicMessage::UpdateAltNextOrLast { .. } => {None}
        }
    }

    pub fn build_send_is_alive(sender: Node) -> GarlemliaMessage {
        GarlemliaMessage::Pong {
            sender,
        }
    }

    pub fn build_send(sender: Node, msg: GarlicMessage) -> GarlemliaMessage {
        GarlemliaMessage::Garlic {
            msg,
            sender
        }
    }
}