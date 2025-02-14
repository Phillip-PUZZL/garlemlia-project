use std::fs;
use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};
use serde_json;
use kademlia::{Kademlia, Node, RoutingTable};
use std::collections::{HashMap, VecDeque};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SimulatedNode {
    pub id: u64,
    pub address: String,
    pub port: u32,
    pub values: HashMap<u64, String>, // Key-value storage
    pub routing_table: RoutingTable, // Full routing table with K-buckets
}

pub struct KademliaWrapper {
    nodes: Arc<Mutex<HashMap<u64, Arc<Kademlia>>>>, // Store real Kademlia instances
}

impl KademliaWrapper {
    /// Load nodes from a `.json` file and create Kademlia instances
    pub fn new(file_path: &str) -> Self {
        let file_data = fs::read_to_string(file_path).unwrap_or_else(|_| {
            println!("⚠️ Warning: {} not found or empty. Initializing an empty network.", file_path);
            "[]".to_string() // Treat an empty or missing file as an empty JSON array
        });

        let simulated_nodes: Vec<SimulatedNode> = serde_json::from_str(&file_data).unwrap_or_else(|_| {
            println!("⚠️ Warning: Invalid JSON format. Initializing an empty network.");
            Vec::new()
        });

        let mut nodes_map = HashMap::new();
        for node in simulated_nodes {
            let mut kad = Kademlia::new(node.id, &*node.address, node.port);
            kad.data_store = Arc::new(Mutex::new(node.values));
            kad.routing_table = Arc::new(Mutex::new(node.routing_table));
            let kad_node = Arc::new(kad);
            nodes_map.insert(node.id, kad_node);
        }

        Self {
            nodes: Arc::new(Mutex::new(nodes_map)),
        }
    }

    /// Perform a `FIND_NODE` using dynamically created sockets
    pub fn find_node(&self, requester_id: u64, target_id: u64) -> Vec<Node> {
        let nodes = self.nodes.lock().unwrap();
        if let Some(requester) = nodes.get(&requester_id) {
            let socket = UdpSocket::bind(requester.node.address).expect("Failed to create temporary socket");
            requester.iterative_find_node(&socket, target_id)
        } else {
            println!("❌ Node {} not found!", requester_id);
            vec![]
        }
    }

    /// Perform a `FIND_VALUE`
    pub fn find_value(&self, requester_id: u64, key: u64) -> Option<String> {
        let nodes = self.nodes.lock().unwrap();
        if let Some(requester) = nodes.get(&requester_id) {
            let socket = UdpSocket::bind(requester.node.address).expect("Failed to create temporary socket");
            requester.iterative_find_value(&socket, key)
        } else {
            println!("❌ Node {} not found!", requester_id);
            None
        }
    }

    /// Perform a Store
    pub fn store_value(&self, requester_id: u64, key: u64, value: String) -> Vec<Node> {
        let nodes = self.nodes.lock().unwrap();
        if let Some(requester) = nodes.get(&requester_id) {
            let socket = UdpSocket::bind(requester.node.address).expect("Failed to create temporary socket");
            requester.store_value(&socket, key, value)
        } else {
            println!("❌ Node {} not found!", requester_id);
            vec![]
        }
    }

    /// Add a node to another node's routing table
    pub fn add_node(&self, owner_id: u64, new_node: Node) {
        let nodes = self.nodes.lock().unwrap();
        if let Some(owner) = nodes.get(&owner_id) {
            let socket = UdpSocket::bind(owner.node.address).expect("Failed to create temporary socket");
            owner.add_node(new_node, &socket);
        }
    }

    /// Save updated network state to a new JSON file
    pub fn save_network(&self, file_path: &str) {
        let nodes = self.nodes.lock().unwrap();
        let mut simulated_nodes: Vec<SimulatedNode> = Vec::new();

        for (id, kad_node) in nodes.iter() {
            let routing_table_vec = kad_node.routing_table.lock().unwrap().buckets.iter()
                .map(|bucket| bucket.iter().cloned().collect::<VecDeque<Node>>())
                .collect::<Vec<VecDeque<Node>>>();

            let node_info = SimulatedNode {
                id: *id,
                address: kad_node.node.address.ip().to_string(),
                port: kad_node.node.address.port() as u32,
                values: kad_node.data_store.lock().unwrap().clone(),
                routing_table: RoutingTable { buckets: routing_table_vec },
            };

            simulated_nodes.push(node_info);
        }

        let json_data = serde_json::to_string_pretty(&simulated_nodes).expect("Failed to serialize JSON");
        fs::write(file_path, json_data).expect("Failed to write updated_nodes.json");
        println!("📂 Updated network state saved to {}", file_path);
    }
}