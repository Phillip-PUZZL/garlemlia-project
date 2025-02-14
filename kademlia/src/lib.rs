use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use serde::{Serialize, Deserialize};

pub const K_BUCKET_SIZE: usize = 20;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RoutingTable {
    pub buckets: Vec<VecDeque<Node>>,
}

impl RoutingTable {
    pub fn new() -> Self {
        Self {
            // Kademlia uses 160-bit space
            buckets: vec![VecDeque::new(); 160],
        }
    }

    // Add a node to the routing table (ensuring K-bucket limits)
    pub fn add_node(&mut self, self_id: u64, node: Node, socket: &UdpSocket) {
        let index = (node.id % 160) as usize;

        // If node already exists, move it to the back (most recently seen)
        if self.buckets[index].contains(&node) {
            self.buckets[index].retain(|n| n != &node);
            self.buckets[index].push_back(node);
            return;
        }

        // If bucket is not full, simply add the node
        if self.buckets[index].len() < K_BUCKET_SIZE {
            self.buckets[index].push_back(node);
            return;
        }

        // Query the LRU node before evicting it
        if let Some(lru_node) = self.buckets[index].front() {
            let lru_address = lru_node.address;

            // Send a ping message to check if LRU node is alive
            let ping_message = KademliaMessage::FindNode {
                id: lru_node.id,
                sender_id: self_id,
            };

            let message_bytes = serde_json::to_vec(&ping_message).unwrap();
            socket.send_to(&message_bytes, &lru_address).unwrap();

            // Wait briefly for a response
            let mut buf = [0; 1024];
            socket.set_read_timeout(Some(Duration::from_millis(300))).unwrap();

            // Try to receive a response
            if let Ok((_size, src)) = socket.recv_from(&mut buf) {
                if src == lru_address {
                    // The LRU node responded, so keep it in the bucket
                    return;
                }
            }

            // No valid response from the LRU node → Remove it
            self.buckets[index].pop_front();
            // Add the new node after LRU eviction
            self.buckets[index].push_back(node);
        }
    }

    // Find closest nodes based on XOR distance
    pub fn find_closest_nodes(&self, target_id: u64, count: usize) -> Vec<Node> {
        let mut nodes: Vec<Node> = self.buckets.iter().flatten().cloned().collect();
        nodes.sort_by_key(|n| n.id ^ target_id);
        nodes.into_iter().take(count).collect()
    }
}

// Node Struct
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Node {
    pub id: u64,
    pub address: SocketAddr,
}

// Kademlia Messages
#[derive(Debug, Serialize, Deserialize)]
pub enum KademliaMessage {
    FindNode { id: u64, sender_id: u64 },
    Store { key: u64, value: String, sender_id: u64 },
    FindValue { key: u64, sender_id: u64 },
    Response { nodes: Vec<Node>, value: Option<String> },
}

impl KademliaMessage {
    // Extract sender ID from the message
    pub fn get_sender_id(&self) -> u64 {
        match self {
            KademliaMessage::FindNode { sender_id, .. } => *sender_id,
            KademliaMessage::Store { sender_id, .. } => *sender_id,
            KademliaMessage::FindValue { sender_id, .. } => *sender_id,
            // Responses don't contain sender_id
            KademliaMessage::Response { .. } => 0,
        }
    }
}

// Kademlia Struct
pub struct Kademlia {
    pub node: Node,
    pub routing_table: Arc<Mutex<RoutingTable>>,
    pub data_store: Arc<Mutex<HashMap<u64, String>>>,
    pub stop_signal: Arc<AtomicBool>,
}

impl Kademlia {
    pub fn new(id: u64, address: &str, port: u32) -> Self {
        Self {
            node: Node { id, address: format!("{address}:{port}").parse().unwrap() },
            routing_table: Arc::new(Mutex::new(RoutingTable::new())),
            data_store: Arc::new(Mutex::new(HashMap::new())),
            stop_signal: Arc::new(AtomicBool::new(false)),
        }
    }

    // Start listening for messages
    pub fn start(&mut self, socket: UdpSocket) {
        let self_ref = self.node.clone();
        let routing_table = Arc::clone(&self.routing_table);
        let data_store = Arc::clone(&self.data_store);
        let stop_clone = Arc::clone(&self.stop_signal);

        let _ = Option::from(thread::spawn(move || {
            let mut buf = [0; 1024];
            while !stop_clone.load(Ordering::Relaxed) {
                if let Ok((size, src)) = socket.recv_from(&mut buf) {
                    let msg: KademliaMessage = serde_json::from_slice(&buf[..size]).unwrap();

                    // Extract sender Node info
                    let sender_node = Node {
                        id: msg.get_sender_id(),
                        address: src,
                    };

                    // Add the sender to the routing table
                    routing_table.lock().unwrap().add_node(self_ref.id, sender_node.clone(), &socket);

                    match msg {
                        KademliaMessage::FindNode { id, .. } => {
                            let response = if id == self_ref.id {
                                // If the search target is this node itself, return only this node
                                KademliaMessage::Response {
                                    nodes: vec![self_ref.clone()],
                                    value: None,
                                }
                            } else {
                                // Return the closest known nodes
                                let closest_nodes = routing_table.lock().unwrap().find_closest_nodes(id, K_BUCKET_SIZE);
                                KademliaMessage::Response {
                                    nodes: closest_nodes,
                                    value: None,
                                }
                            };

                            let response_bytes = serde_json::to_vec(&response).unwrap();
                            socket.send_to(&response_bytes, src).unwrap();
                        }

                        // Store a key-value pair
                        KademliaMessage::Store { key, value, .. } => {
                            data_store.lock().unwrap().insert(key, value);
                        }

                        // Use find_closest_nodes() if value is not found
                        KademliaMessage::FindValue { key, .. } => {
                            let value = data_store.lock().unwrap().get(&key).cloned();

                            let response = if let Some(val) = value {
                                KademliaMessage::Response {
                                    nodes: vec![],
                                    value: Some(val),
                                }
                            } else {
                                let closest_nodes = routing_table.lock().unwrap().find_closest_nodes(key, K_BUCKET_SIZE);

                                KademliaMessage::Response {
                                    nodes: closest_nodes,
                                    value: None,
                                }
                            };

                            let response_bytes = serde_json::to_vec(&response).unwrap();
                            socket.send_to(&response_bytes, src).unwrap();
                        }

                        _ => {}
                    }
                }
            }
        }));
    }

    pub fn stop(&self) {
        self.stop_signal.store(true, Ordering::Relaxed);
    }

    pub fn iterative_find_node(&self, socket: &UdpSocket, target_id: u64) -> Vec<Node> {
        let mut queried_nodes = HashSet::new();
        let mut closest_nodes = self.routing_table.lock().unwrap().find_closest_nodes(target_id, K_BUCKET_SIZE);
        let mut best_known_distance = u64::MAX;
        let mut new_nodes_found = true;

        while new_nodes_found {
            new_nodes_found = false;
            let mut new_closest_nodes = Vec::new();

            for node in closest_nodes.iter() {
                if queried_nodes.contains(&node.address) {
                    continue;
                }

                queried_nodes.insert(node.address);
                self.send_message(socket, &node.address, KademliaMessage::FindNode {
                    id: target_id,
                    sender_id: self.node.id,
                });

                // Wait briefly for responses
                thread::sleep(Duration::from_millis(100));

                // Collect responses
                let received_nodes = self.routing_table.lock().unwrap().find_closest_nodes(target_id, K_BUCKET_SIZE);
                for n in received_nodes {
                    let distance = n.id ^ target_id;

                    self.routing_table.lock().unwrap().add_node(self.node.id, n.clone(), socket);

                    if distance < best_known_distance {
                        best_known_distance = distance;
                        new_closest_nodes.push(n.clone());
                        new_nodes_found = true;
                    }
                }
            }

            if new_nodes_found {
                closest_nodes.extend(new_closest_nodes);
                closest_nodes.sort_by_key(|n| n.id ^ target_id);
                closest_nodes.truncate(K_BUCKET_SIZE);
            }
        }

        closest_nodes
    }

    // Perform an iterative lookup for a value in the DHT
    pub fn iterative_find_value(&self, socket: &UdpSocket, key: u64) -> Option<String> {
        let mut queried_nodes = HashSet::new();
        let mut closest_nodes = self.routing_table.lock().unwrap().find_closest_nodes(key, K_BUCKET_SIZE);
        let mut best_known_distance = u64::MAX;
        let mut new_nodes_found = true;

        while new_nodes_found {
            new_nodes_found = false;
            let mut new_closest_nodes = Vec::new();

            for node in closest_nodes.iter() {
                if queried_nodes.contains(&node.address) {
                    continue;
                }

                queried_nodes.insert(node.address);
                self.send_message(socket, &node.address, KademliaMessage::FindValue {
                    key,
                    sender_id: self.node.id,
                });

                // Wait briefly for responses
                thread::sleep(Duration::from_millis(100));

                // Collect responses
                let data_store = self.data_store.lock().unwrap();
                if let Some(value) = data_store.get(&key) {
                    return Some(value.clone());
                }

                let received_nodes = self.routing_table.lock().unwrap().find_closest_nodes(key, K_BUCKET_SIZE);
                for n in received_nodes {
                    let distance = n.id ^ key;

                    self.routing_table.lock().unwrap().add_node(self.node.id, n.clone(), socket);

                    if distance < best_known_distance {
                        best_known_distance = distance;
                        new_closest_nodes.push(n.clone());
                        new_nodes_found = true;
                    }
                }
            }

            if new_nodes_found {
                closest_nodes.extend(new_closest_nodes);
                closest_nodes.sort_by_key(|n| n.id ^ key);
                closest_nodes.truncate(K_BUCKET_SIZE);
            }
        }

        None
    }

    pub fn store_value(&self, socket: &UdpSocket, key: u64, value: String) -> Vec<Node> {
        // Find the closest nodes to store the value
        let mut closest_nodes = self.iterative_find_node(socket, key);
        closest_nodes.truncate(2);

        for node in closest_nodes.iter() {

            // Create STORE message
            let store_message = KademliaMessage::Store {
                key,
                value: value.clone(),
                sender_id: self.node.id,
            };

            // Send STORE message
            self.send_message(socket, &node.address, store_message);
        }

        // Store the value locally if this node is among the closest
        let mut data_store = self.data_store.lock().unwrap();
        data_store.insert(key, value);

        closest_nodes
    }

    // Send a message to another node
    pub fn send_message(&self, socket: &UdpSocket, target: &SocketAddr, message: KademliaMessage) {
        let message_with_sender = match message {
            KademliaMessage::FindNode { id, .. } => Some(KademliaMessage::FindNode {
                id,
                sender_id: self.node.id,
            }),
            KademliaMessage::Store { key, value, .. } => Some(KademliaMessage::Store {
                key,
                value: value.to_string(),
                sender_id: self.node.id,
            }),
            KademliaMessage::FindValue { key, .. } => Some(KademliaMessage::FindValue {
                key,
                sender_id: self.node.id,
            }),
            KademliaMessage::Response { .. } => None,
        };

        if message_with_sender.is_some() {
            let message_bytes = serde_json::to_vec(&message_with_sender).unwrap();
            socket.send_to(&message_bytes, target).unwrap();
        }
    }

    // Add a node to the routing table
    pub fn add_node(&self, node: Node, socket: &UdpSocket, ) {
        self.routing_table.lock().unwrap().add_node(self.node.id, node, socket);
    }
}