use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc::UnboundedReceiver};
use tokio::time::{timeout, Duration};

/// Custom error type for messaging operations.
#[derive(Debug)]
pub enum MessageError {
    IoError(std::io::Error),
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

#[async_trait]
pub trait KademliaRoutingTable: Send + Sync + Debug {
    fn new(local_node: Node) -> Self
    where
        Self: Sized;
    fn update_from(&mut self, other: &dyn KademliaRoutingTable);
    fn local_node(&self) -> &Node;
    fn buckets(&self) -> &HashMap<u8, KBucket>;
    fn bucket_index(&self, node_id: u128) -> u8;
    fn flat_nodes(&self) -> Vec<Node>;
    fn insert_direct(&mut self, node: Node);
    fn check_and_update_bucket(&mut self, node: Node, index: u8) -> bool;
    async fn add_node_from_responder(&mut self, node: Node, socket: &UdpSocket);
    async fn add_node(
        &mut self,
        response_queue: Arc<Mutex<HashMap<u128, Vec<KademliaMessage>>>>,
        rx: Arc<Mutex<UnboundedReceiver<MessageChannel>>>,
        node: Node,
        socket: &UdpSocket,
    );
    fn find_closest_nodes(&self, target_id: u128, count: usize) -> Vec<Node>;
    fn clone_box(&self) -> Box<dyn KademliaRoutingTable>;
}

impl Clone for Box<dyn KademliaRoutingTable> {
    fn clone(&self) -> Box<dyn KademliaRoutingTable> {
        self.clone_box()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RoutingTable {
    local_node: Node,
    buckets: HashMap<u8, KBucket>,
}

#[async_trait]
impl KademliaRoutingTable for RoutingTable {
    fn new(local_node: Node) -> Self {
        Self {
            local_node,
            buckets: HashMap::new(),
        }
    }

    fn update_from(&mut self, other: &dyn KademliaRoutingTable) {
        self.local_node = other.local_node().clone();
        self.buckets = other.buckets().clone();
    }

    fn local_node(&self) -> &Node {
        &self.local_node
    }

    fn buckets(&self) -> &HashMap<u8, KBucket> {
        &self.buckets
    }

    fn bucket_index(&self, node_id: u128) -> u8 {
        let xor_distance = self.local_node.id ^ node_id;
        (128 - xor_distance.leading_zeros()) as u8
    }

    fn flat_nodes(&self) -> Vec<Node> {
        self.buckets
            .values()
            .flat_map(|bucket| bucket.nodes.iter().cloned())
            .collect()
    }

    fn insert_direct(&mut self, node: Node) {
        let index = self.bucket_index(node.id);
        self.buckets
            .entry(index)
            .or_insert_with(KBucket::new)
            .insert(node);
    }

    fn check_and_update_bucket(&mut self, node: Node, index: u8) -> bool {
        if let Some(bucket) = self.buckets.get_mut(&index) {
            if !bucket.is_full() {
                bucket.update_node(node);
                return true;
            }
            false
        } else {
            self.buckets.insert(index, KBucket::new());
            self.buckets.get_mut(&index).unwrap().insert(node);
            true
        }
    }

    async fn add_node_from_responder(&mut self, node: Node, socket: &UdpSocket) {
        let index = self.bucket_index(node.id);
        if self.check_and_update_bucket(node.clone(), index) {
            return;
        }
        let bucket = self.buckets.get_mut(&index).unwrap();
        if let Some(lru_node) = bucket.nodes.front().cloned() {
            let ping_msg = KademliaMessage::FindNode {
                id: lru_node.id,
                sender_id: self.local_node.id,
            };

            // If sending fails, log the error and continue.
            if let Err(e) = MessageHandler::create().send(socket, &lru_node.address, &ping_msg).await {
                eprintln!("Failed to send ping to {}: {:?}", lru_node.address, e);
                bucket.remove(&lru_node);
                bucket.insert(node);
                return;
            }

            // Wait for a short duration to check lru_node's response.
            let mut buf = [0; 4096];
            let is_alive = timeout(Duration::from_millis(300), async {
                if let Ok((_, src)) = socket.recv_from(&mut buf).await {
                    src == lru_node.address
                } else {
                    false
                }
            })
                .await
                .unwrap_or(false);

            if !is_alive {
                bucket.remove(&lru_node);
                bucket.insert(node);
            } else {
                bucket.update_node(lru_node);
            }
        }
    }

    async fn add_node(
        &mut self,
        response_queue: Arc<Mutex<HashMap<u128, Vec<KademliaMessage>>>>,
        rx: Arc<Mutex<UnboundedReceiver<MessageChannel>>>,
        node: Node,
        socket: &UdpSocket,
    ) {
        if self.local_node.id == node.id {
            return;
        }
        let index = self.bucket_index(node.id);
        if self.check_and_update_bucket(node.clone(), index) {
            return;
        }
        let bucket = self.buckets.get_mut(&index).unwrap();
        if let Some(lru_node) = bucket.nodes.front().cloned() {
            let ping_msg = KademliaMessage::FindNode {
                id: lru_node.id,
                sender_id: self.local_node.id,
            };

            if let Err(e) = MessageHandler::create().send(socket, &lru_node.address, &ping_msg).await {
                eprintln!("Failed to send ping to {}: {:?}", lru_node.address, e);
                bucket.remove(&lru_node);
                bucket.insert(node);
                return;
            }

            match MessageHandler::create()
                .recv(response_queue, rx, 300, &lru_node.address)
                .await
            {
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

    fn find_closest_nodes(&self, target_id: u128, count: usize) -> Vec<Node> {
        let mut heap = BinaryHeap::new();
        heap.push(HeapNode {
            distance: target_id ^ self.local_node.id,
            node: self.local_node.clone(),
        });

        let mut bucket_indices: Vec<u8> = self.buckets.keys().cloned().collect();
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
                if let Some(bucket) = self.buckets.get(&bucket_indices[left as usize]) {
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
                if let Some(bucket) = self.buckets.get(&bucket_indices[right as usize]) {
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

    fn clone_box(&self) -> Box<dyn KademliaRoutingTable> {
        Box::new(self.clone())
    }
}

/// A simple channel message that carries identifying information.
#[derive(Debug)]
pub struct MessageChannel {
    pub node_id: u128,
    pub msg_id: u128,
}

#[async_trait]
pub trait KMessage: Send + Sync {
    fn create() -> Box<dyn KMessage>
    where
        Self: Sized;
    async fn send(
        &self,
        socket: &UdpSocket,
        target: &SocketAddr,
        msg: &KademliaMessage,
    ) -> Result<(), MessageError>;
    async fn recv(
        &self,
        response_queue: Arc<Mutex<HashMap<u128, Vec<KademliaMessage>>>>,
        rx: Arc<Mutex<UnboundedReceiver<MessageChannel>>>,
        timeout_ms: u64,
        _src: &SocketAddr,
    ) -> Result<KademliaMessage, MessageError>;
    fn clone_box(&self) -> Box<dyn KMessage>;
}

impl Clone for Box<dyn KMessage> {
    fn clone(&self) -> Box<dyn KMessage> {
        self.clone_box()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct MessageHandler {}

#[async_trait]
impl KMessage for MessageHandler {
    fn create() -> Box<dyn KMessage> {
        Box::new(MessageHandler::default())
    }

    async fn send(
        &self,
        socket: &UdpSocket,
        target: &SocketAddr,
        msg: &KademliaMessage,
    ) -> Result<(), MessageError> {
        let message_bytes = serde_json::to_vec(msg)
            .map_err(|e| MessageError::SerializationError(e.to_string()))?;
        socket.send_to(&message_bytes, target).await?;
        Ok(())
    }

    async fn recv(
        &self,
        response_queue: Arc<Mutex<HashMap<u128, Vec<KademliaMessage>>>>,
        rx: Arc<Mutex<UnboundedReceiver<MessageChannel>>>,
        timeout_ms: u64,
        _src: &SocketAddr,
    ) -> Result<KademliaMessage, MessageError> {
        // Lock the receiver briefly to await a channel message.
        let channel_msg = {
            let mut rx_locked = rx.lock().await;
            timeout(Duration::from_millis(timeout_ms), rx_locked.recv())
                .await
                .map_err(|_| MessageError::Timeout)?
                .ok_or(MessageError::MissingResponse)?
        };

        // Lock the response queue briefly to extract the matching message.
        let kad_msg = {
            let mut queue = response_queue.lock().await;
            let messages = queue.get_mut(&channel_msg.node_id)
                .ok_or(MessageError::MissingResponse)?;
            if let Some(pos) = messages.iter().position(|m| {
                if let KademliaMessage::Response { msg_id, .. } = m {
                    *msg_id == Some(channel_msg.msg_id)
                } else {
                    false
                }
            }) {
                messages.remove(pos)
            } else {
                return Err(MessageError::MissingResponse);
            }
        };

        Ok(kad_msg)
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
        msg_id: Option<u128>,
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
