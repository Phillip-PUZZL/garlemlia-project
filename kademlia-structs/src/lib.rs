use std::cmp::PartialEq;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::fmt::Debug;
use std::net::{SocketAddr};
use std::sync::{Arc};
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time::{timeout, Duration};

/// Helper struct to use a max-heap for closest node selection
#[derive(Eq)]
pub struct HeapNode {
    pub distance: u128,
    pub node: Node,
}

impl Ord for HeapNode {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.distance.cmp(&self.distance) // Reverse order for min-heap behavior
    }
}

impl PartialOrd for HeapNode {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for HeapNode {
    fn eq(&self, other: &Self) -> bool {
        self.distance == other.distance
    }
}

// Default bucket size
pub const DEFAULT_K: usize = 20;
// Maximum bucket size for high-traffic buckets
pub const MAX_K: usize = 40;

// Node Struct
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Node {
    pub id: u128,
    pub address: SocketAddr,
}

impl Node {
    pub fn set(&mut self, new: &mut Node) {
        self.id = new.id;
        self.address = new.address;
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[derive(Default)]
#[derive(PartialEq)]
pub struct KBucket {
    pub nodes: VecDeque<Node>,
    max_size: usize,
}

impl KBucket {
    pub fn new() -> KBucket {
        KBucket {
            nodes: VecDeque::with_capacity(DEFAULT_K),
            max_size: DEFAULT_K,
        }
    }

    fn new_with_node(node: Node) -> KBucket {
        let mut k = KBucket {
            nodes: VecDeque::with_capacity(DEFAULT_K),
            max_size: DEFAULT_K,
        };
        k.nodes.push_back(node);

        k
    }

    pub fn insert(&mut self, node: Node) {
        self.nodes.push_back(node);
    }

    pub fn remove(&mut self, node: Node) {
        if let Some(pos) = self.nodes.iter().position(|n| n.id == node.id) {
            self.nodes.remove(pos).unwrap();
        }
    }

    pub fn update_node(&mut self, node: Node) {
        self.remove(node.clone());
        self.insert(node);
    }

    pub fn contains(&self, node_id: u128) -> bool {
        self.nodes.iter().any(|n| n.id == node_id)
    }

    pub fn is_full(&self) -> bool {
        self.nodes.len() >= self.max_size
    }

    fn increase_capacity(&mut self) {
        if self.max_size < MAX_K {
            // Incrementally increase size
            self.max_size += 5;
        }
    }
}

#[async_trait]
pub trait KademliaRoutingTable: Send + Sync + Debug {
    fn new(local_node: Node) -> Self where Self: Sized;
    fn set(&mut self, new: &dyn KademliaRoutingTable);
    fn get_local_node(&self) -> &Node;
    fn get_buckets(&self) -> &HashMap<u8, KBucket>;
    fn bucket_index(&self, node_id: u128) -> u8;
    fn flat(&self) -> Vec<Node>;
    fn insert_direct(&mut self, node: Node);
    fn check_buckets(&mut self, node: Node, index: u8) -> bool;
    async fn add_node_from_responder(&mut self, node: Node, socket: &UdpSocket);
    async fn add_node(
        &mut self,
        response_queue: Arc<Mutex<HashMap<u128, Vec<KademliaMessage>>>>,
        rx: Arc<Mutex<UnboundedReceiver<MessageChannel>>>,
        node: Node,
        socket: &UdpSocket,
    );
    fn find_closest_nodes(&mut self, target_id: u128, count: usize) -> Vec<Node>;
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

    fn set(&mut self, new: &dyn KademliaRoutingTable) {
        self.local_node = new.get_local_node().clone();
        self.buckets = new.get_buckets().clone();
    }

    fn get_local_node(&self) -> &Node {
        &self.local_node
    }

    fn get_buckets(&self) -> &HashMap<u8, KBucket> {
        &self.buckets
    }

    fn bucket_index(&self, node_id: u128) -> u8 {
        let xor_distance = self.local_node.id ^ node_id;

        (128 - xor_distance.leading_zeros()) as u8
    }

    fn flat(&self) -> Vec<Node> {
        self.buckets
            .iter()
            .flat_map(|bucket| bucket.1.nodes.iter().cloned())
            .collect()
    }

    fn insert_direct(&mut self, node: Node) {
        let index = self.bucket_index(node.id);
        if let Some(bucket) = self.buckets.get_mut(&index) {
            bucket.insert(node);
        } else {
            self.buckets.insert(index, KBucket::new());
            if let Some(bucket_new) = self.buckets.get_mut(&index) {
                bucket_new.insert(node);
            }
        }
    }

    fn check_buckets(&mut self, node: Node, index: u8) -> bool {
        // If node already exists, move it to the back (most recently seen)
        let bucket = self.buckets.get_mut(&index);

        match bucket {
            Some(bucket) => {
                if !bucket.is_full() {
                    bucket.update_node(node.clone());
                    return true
                }
                false
            }
            None => {
                self.buckets.insert(index, KBucket::new());
                if let Some(bucket_new) = self.buckets.get_mut(&index) {
                    bucket_new.insert(node);
                }
                true
            }
        }
    }

    // Add a node to the routing table from Kademlia Responder
    async fn add_node_from_responder(&mut self, node: Node, socket: &UdpSocket) {
        let index = self.bucket_index(node.id);

        if self.check_buckets(node.clone(), index) {
            return;
        }

        let bucket = self.buckets.get_mut(&index).unwrap();

        // Query the LRU node before evicting it
        if let Some(lru_node) = bucket.nodes.clone().front() {
            let lru_address = lru_node.address;

            // Send a ping message to check if LRU node is alive
            let ping_message = KademliaMessage::FindNode {
                id: lru_node.id,
                sender_id: self.local_node.id,
            };

            MessageHandler::create().send(socket, &lru_address, &ping_message).await;

            // Buffer to store the response
            let mut buf = [0; 1024];

            // Wait up to 300ms for a response asynchronously
            let response = timeout(Duration::from_millis(300), async {
                // Try to receive a response
                match socket.recv_from(&mut buf).await {
                    Ok((_size, src)) => {
                        if src == lru_address {
                            // The LRU node responded, so keep it in the bucket and push to the front
                            bucket.update_node(lru_node.clone());
                            return true;
                        } else {
                            false
                        }
                    }
                    _ => {
                        false
                    }
                }
            }).await.unwrap_or(false);

            if !response {
                // No response, replace it with the new node
                // No valid response from the LRU node → Remove it
                bucket.remove(lru_node.clone());
                // Add the new node after LRU eviction
                bucket.insert(node);
            }
        }
    }

    // Add a node to the routing table
    async fn add_node(&mut self,
                      response_queue: Arc<Mutex<HashMap<u128, Vec<KademliaMessage>>>>,
                      rx: Arc<Mutex<UnboundedReceiver<MessageChannel>>>,
                      node: Node, socket: &UdpSocket) {
        if self.local_node.id == node.id {
            return;
        }

        let index = self.bucket_index(node.id);

        if self.check_buckets(node.clone(), index) {
            return;
        }

        let bucket = self.buckets.get_mut(&index).unwrap();

        // Query the LRU node before evicting it
        if let Some(lru_node) = bucket.nodes.clone().front() {
            let lru_address = lru_node.address;

            // Send a ping message to check if LRU node is alive
            let ping_message = KademliaMessage::FindNode {
                id: lru_node.id,
                sender_id: self.local_node.id,
            };

            MessageHandler::create().send(socket, &lru_address, &ping_message).await;

            // Wait up to 300ms for a response asynchronously
            let response = MessageHandler::create().recv(response_queue, rx, 300, &lru_address).await;

            match response {
                Some(msg) => {
                    match msg {
                        KademliaMessage::Response { sender_id, .. } => {
                            if sender_id == lru_node.id {
                                bucket.update_node(lru_node.clone());
                            }
                        }
                        _ => {}
                    }
                }
                None => {
                    // No response, replace it with the new node
                    // No valid response from the LRU node → Remove it
                    bucket.remove(lru_node.clone());
                    // Add the new node after LRU eviction
                    bucket.insert(node);
                }
            }
        }
    }

    // Find the closest nodes based on XOR distance
    fn find_closest_nodes(&mut self, target_id: u128, count: usize) -> Vec<Node> {
        let mut heap = BinaryHeap::new();
        heap.push(HeapNode { distance: target_id ^ self.local_node.id, node: self.local_node.clone() });

        let mut searched_buckets = 0;
        let start_index = self.bucket_index(target_id);

        // Get all existing bucket indices in sorted order
        let mut bucket_indices: Vec<u8> = self.buckets.keys().cloned().collect();
        bucket_indices.sort();

        // Find the closest bucket index to start searching from
        let closest_index_pos = bucket_indices
            .binary_search(&start_index)
            .unwrap_or_else(|pos| pos.min(bucket_indices.len().saturating_sub(1))); // If not found, returns where it should be inserted

        let mut left = closest_index_pos as isize;
        let mut right = closest_index_pos as isize + 1;

        // Expand search outward from the closest bucket index
        while searched_buckets < bucket_indices.len() {
            if left >= 0 && (left as usize) < bucket_indices.len() {
                if let Some(bucket) = self.buckets.get(&bucket_indices[left as usize]) {
                    for node in &bucket.nodes {
                        let distance = target_id ^ node.id;
                        heap.push(HeapNode { distance, node: node.clone() });

                        if heap.len() > count {
                            heap.pop();
                        }
                    }
                    searched_buckets += 1;
                }
                left -= 1;
            }

            if right < bucket_indices.len() as isize {
                if let Some(bucket) = self.buckets.get(&bucket_indices[right as usize]) {
                    for node in &bucket.nodes {
                        let distance = target_id ^ node.id;
                        heap.push(HeapNode { distance, node: node.clone() });

                        if heap.len() > count {
                            heap.pop();
                        }
                    }
                    searched_buckets += 1;
                }
                right += 1;
            }

            if heap.len() >= count && searched_buckets > 3 {
                break;
            }
        }

        // Extract and return the closest nodes
        heap.into_sorted_vec()
            .into_iter()
            .map(|heap_node| heap_node.node)
            .collect()
    }

    fn clone_box(&self) -> Box<dyn KademliaRoutingTable> {
        Box::new(self.clone())
    }
}

#[derive(Debug)]
pub struct MessageChannel {
    pub node_id: u128,
    pub msg_id: u128,
}

#[async_trait]
pub trait KMessage: Send + Sync {
    fn create() -> Box<dyn KMessage> where Self: Sized;
    async fn send(&self, socket: &UdpSocket, target: &SocketAddr, msg: &KademliaMessage);
    async fn recv(&self, response_queue: Arc<Mutex<HashMap<u128, Vec<KademliaMessage>>>>,
                  rx: Arc<Mutex<UnboundedReceiver<MessageChannel>>>, time: u64, src: &SocketAddr) -> Option<KademliaMessage>;

    fn clone_box(&self) -> Box<dyn KMessage>;
}

impl Clone for Box<dyn KMessage> {
    fn clone(&self) -> Box<dyn KMessage> {
        self.clone_box()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MessageHandler {}

#[async_trait]
impl KMessage for MessageHandler {
    fn create() -> Box<dyn KMessage> {
        Box::new(MessageHandler {})
    }

    async fn send(&self, socket: &UdpSocket, target: &SocketAddr, msg: &KademliaMessage) {
        println!("send - real");
        let message_bytes = serde_json::to_vec(msg).unwrap();
        socket.send_to(&message_bytes, target).await.unwrap();
    }

    async fn recv(&self, response_queue: Arc<Mutex<HashMap<u128, Vec<KademliaMessage>>>>,
                  rx: Arc<Mutex<UnboundedReceiver<MessageChannel>>>, time: u64, _src: &SocketAddr) -> Option<KademliaMessage> {
        println!("recv - real");
        // Lock before entering timeout
        let mut rx_locked = rx.lock().await;
        let response = match timeout(Duration::from_millis(time), async {
            if !rx_locked.is_closed() {
                rx_locked.recv().await
            } else {
                println!("tx is closed");
                None
            }
        }).await {
            Ok(Some(node_id)) => Some(node_id),
            Ok(None) => {
                println!("Received None from channel.");
                None
            },
            Err(_) => {
                println!("Timeout occurred while waiting for response.");
                None
            }
        };

        let mut position = -1;
        let message_info;
        let mut kad_msg = KademliaMessage::Response {
            msg_id: None,
            nodes: vec![],
            value: None,
            sender_id: 0,
        };

        let mut res_queue = response_queue.lock().await;
        match response {
            Some(mc) => {
                if let Some(pos) = res_queue.get(&mc.node_id).unwrap().iter().position(|n|
                    match n {
                        &KademliaMessage::Response { msg_id, .. } => { msg_id == Option::from(mc.msg_id) }
                        _ => { false }
                    }) {
                    position = pos as i32;
                }
                message_info = Some(mc);
            },
            None => {
                return None;
            }
        };

        let km = match message_info {
            Some(mc) => {
                let response_msg = res_queue.get(&mc.node_id).unwrap().get(position as usize).unwrap();
                match response_msg {
                    KademliaMessage::Response { msg_id, nodes, value, sender_id } => {
                        kad_msg = KademliaMessage::Response {
                            msg_id: *msg_id,
                            nodes: nodes.clone(),
                            value: value.clone(),
                            sender_id: *sender_id,
                        }
                    },
                    _ => {}
                }
                res_queue.get_mut(&mc.node_id).unwrap().remove(position as usize);
                Some(kad_msg)
            }
            None => None
        };

        km
    }

    fn clone_box(&self) -> Box<dyn KMessage> {
        Box::new(self.clone())
    }
}

// Kademlia Messages
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum KademliaMessage {
    FindNode { id: u128, sender_id: u128 },
    Store { key: u128, value: String, sender_id: u128 },
    FindValue { key: u128, sender_id: u128 },
    Response { msg_id: Option<u128>, nodes: Vec<Node>, value: Option<String>, sender_id: u128 },
    Stop {},
}

impl KademliaMessage {
    // Extract sender ID from the message
    pub fn get_sender_id(&self) -> u128 {
        match self {
            KademliaMessage::FindNode { sender_id, .. } => *sender_id,
            KademliaMessage::Store { sender_id, .. } => *sender_id,
            KademliaMessage::FindValue { sender_id, .. } => *sender_id,
            KademliaMessage::Response {sender_id, .. } => *sender_id,
            KademliaMessage::Stop {} => 0,
        }
    }
}