use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc::UnboundedReceiver, mpsc};
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::{timeout, Duration};

/// Custom error type for messaging operations.
#[derive(Debug)]
pub enum MessageError {
    IoError(std::io::Error),
    NoRX,
    NoTX,
    TXDropped,
    TXSendError,
    Timeout,
    MissingResponse,
    SerializationError(String),
}

impl From<std::io::Error> for MessageError {
    fn from(err: std::io::Error) -> Self {
        MessageError::IoError(err)
    }
}

/// Helper struct for a min-heap (using reverse ordering)
#[derive(Eq)]
pub struct HeapNode {
    pub distance: u128,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Node {
    pub id: u128,
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

    pub fn contains(&self, node_id: u128) -> bool {
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

#[derive(Debug, Clone)]
pub struct RoutingTable {
    local_node: Node,
    buckets: Arc<Mutex<HashMap<u8, KBucket>>>,
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

    pub fn bucket_index(&self, node_id: u128) -> u8 {
        let xor_distance = self.local_node.id ^ node_id;
        (128 - xor_distance.leading_zeros()) as u8
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

    async fn check_and_update_bucket(&mut self, node: Node, index: u8) -> bool {
        let mut self_buckets = self.buckets.lock().await;
        if let Some(bucket) = self_buckets.get_mut(&index) {
            if !bucket.is_full() {
                bucket.update_node(node);
                return true;
            }
            false
        } else {
            self_buckets.insert(index, KBucket::new());
            self_buckets.get_mut(&index).unwrap().insert(node);
            true
        }
    }

    pub async fn add_node_from_responder(&mut self, message_handler: Arc<Box<dyn KMessage>>, node: Node, socket: Arc<UdpSocket>) {
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
                let ping_msg = KademliaMessage::FindNode {
                    id: lru_node.id,
                    sender_id: local_node.id,
                };

                {
                    // If sending fails, log the error and continue.
                    if let Err(e) = mh.send(&socket_clone, &lru_node.address, &ping_msg).await {
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
                        Ok(KademliaMessage::Response { sender_id, .. }) if sender_id == lru_node.id => {
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

    pub async fn add_node(&mut self, mut message_handler: Arc<Box<dyn KMessage>>, node: Node, socket: &UdpSocket) {
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
            let ping_msg = KademliaMessage::FindNode {
                id: lru_node.id,
                sender_id: self.local_node.id,
            };

            if let Err(e) = message_handler.send(socket, &lru_node.address, &ping_msg).await {
                eprintln!("Failed to send ping to {}: {:?}", lru_node.address, e);
                bucket.remove(&lru_node);
                bucket.insert(node);
                return;
            }

            match message_handler.recv(300, &lru_node.address).await {
                Ok(KademliaMessage::Response { sender_id, .. }) if sender_id == lru_node.id => {
                    bucket.update_node(lru_node);
                }
                Ok(_) | Err(_) => {
                    bucket.remove(&lru_node);
                    bucket.insert(node);
                }
            }
        }
    }

    pub async fn find_closest_nodes(&self, target_id: u128, count: usize) -> Vec<Node> {
        let mut heap = BinaryHeap::new();
        heap.push(HeapNode {
            distance: target_id ^ self.local_node.id,
            node: self.local_node.clone(),
        });

        let self_buckets = self.buckets.lock().await;

        let mut bucket_indices: Vec<u8> = self_buckets.keys().cloned().collect();
        bucket_indices.sort();
        let start_index = self.bucket_index(target_id);
        let closest_index_pos = bucket_indices
            .binary_search(&start_index)
            .unwrap_or_else(|pos| pos.min(bucket_indices.len().saturating_sub(1)));
        let mut left = closest_index_pos as isize;
        let mut right = closest_index_pos as isize + 1;
        let mut searched = 0;

        while searched < bucket_indices.len() {
            if left >= 0 {

                if let Some(bucket) = self_buckets.get(&bucket_indices[left as usize]) {
                    for node in &bucket.nodes {
                        heap.push(HeapNode {
                            distance: target_id ^ node.id,
                            node: node.clone(),
                        });
                        if heap.len() > count {
                            heap.pop();
                        }
                    }
                    searched += 1;
                }
                left -= 1;
            }
            if right < bucket_indices.len() as isize {
                if let Some(bucket) = self_buckets.get(&bucket_indices[right as usize]) {
                    for node in &bucket.nodes {
                        heap.push(HeapNode {
                            distance: target_id ^ node.id,
                            node: node.clone(),
                        });
                        if heap.len() > count {
                            heap.pop();
                        }
                    }
                    searched += 1;
                }
                right += 1;
            }
            if heap.len() >= count && searched > 3 {
                break;
            }
        }

        heap.into_sorted_vec().into_iter().map(|hn| hn.node).collect()
    }
}

/// A simple channel message that carries identifying information.
#[derive(Debug, Clone)]
pub struct MessageChannel {
    pub node_id: u128,
    pub msg: KademliaMessage,
}

#[async_trait]
pub trait KMessage: Send + Sync {
    fn create(channel_count: u8) -> Box<dyn KMessage> where Self: Sized;
    async fn send_tx(&self, addr: SocketAddr, msg: MessageChannel) -> Result<(), MessageError>;
    async fn send_no_recv(&self, socket: &UdpSocket, target: &SocketAddr, msg: &KademliaMessage) -> Result<(), MessageError>;
    async fn send(&self, socket: &UdpSocket, target: &SocketAddr, msg: &KademliaMessage) -> Result<(), MessageError>;
    async fn recv(&self, timeout_ms: u64, src: &SocketAddr) -> Result<KademliaMessage, MessageError>;
    fn clone_box(&self) -> Box<dyn KMessage>;
}

impl Clone for Box<dyn KMessage> {
    fn clone(&self) -> Box<dyn KMessage> {
        self.clone_box()
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
pub struct MessageHandler {
    available_rx: Arc<Mutex<Vec<HandlerChannelReceiver>>>,
    unavailable_rx: Arc<Mutex<HashMap<String, HandlerChannelReceiver>>>,
    available_tx: Arc<Mutex<Vec<HandlerChannelSender>>>,
    unavailable_tx: Arc<Mutex<HashMap<String, HandlerChannelSender>>>,
}

#[async_trait]
impl KMessage for MessageHandler {
    fn create(channel_count: u8) -> Box<dyn KMessage> {
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

        Box::new(MessageHandler {
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

    async fn send_no_recv(&self, socket: &UdpSocket, target: &SocketAddr, msg: &KademliaMessage) -> Result<(), MessageError> {
        // Now actually send the UDP message
        let bytes = serde_json::to_vec(msg)
            .map_err(|e| MessageError::SerializationError(e.to_string()))?;
        socket.send_to(&bytes, target).await?;
        Ok(())
    }

    /// Takes an RX/TX from the “available” pool, assigns it to the `target`, and sends the given message.
    async fn send(&self, socket: &UdpSocket, target: &SocketAddr, msg: &KademliaMessage) -> Result<(), MessageError> {
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
        Ok(())
    }

    /// Receives a message from the “unavailable” RX assigned to `src`, then returns that RX/TX pair to the pool.
    async fn recv(&self, timeout_ms: u64, src: &SocketAddr) -> Result<KademliaMessage, MessageError> {
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

        // Return the final KademliaMessage or an error
        match msg_result {
            Ok(channel) => Ok(channel.msg),
            Err(e) => {
                println!("Error: Did not receive message due to {:?}", e);
                Err(e)
            }
        }
    }

    fn clone_box(&self) -> Box<dyn KMessage> {
        Box::new(self.clone())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum KademliaMessage {
    FindNode { id: u128, sender_id: u128 },
    Store { key: u128, value: String, sender_id: u128 },
    FindValue { key: u128, sender_id: u128 },
    Response {
        nodes: Vec<Node>,
        value: Option<String>,
        sender_id: u128,
    },
    Stop {},
}

impl KademliaMessage {
    pub fn sender_id(&self) -> u128 {
        match self {
            KademliaMessage::FindNode { sender_id, .. } => *sender_id,
            KademliaMessage::Store { sender_id, .. } => *sender_id,
            KademliaMessage::FindValue { sender_id, .. } => *sender_id,
            KademliaMessage::Response { sender_id, .. } => *sender_id,
            KademliaMessage::Stop {} => 0,
        }
    }
}
