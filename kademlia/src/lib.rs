use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use serde::{Serialize, Deserialize};
use tokio::task;
use rand::Rng;

// Constants
const K_BUCKET_SIZE: usize = 20;

// Node Struct
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: u64,
    pub address: SocketAddr,
}

// Kademlia Struct
pub struct Kademlia {
    node: Node,
    routing_table: Arc<Mutex<HashSet<Node>>>,
    data_store: Arc<Mutex<HashMap<u64, String>>>,
}

impl Kademlia {
    pub fn new(id: u64, address: SocketAddr) -> Self {
        Self {
            node: Node { id, address },
            routing_table: Arc::new(Mutex::new(HashSet::new())),
            data_store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn start(&self, socket: UdpSocket) {
        let routing_table = Arc::clone(&self.routing_table);
        let data_store = Arc::clone(&self.data_store);

        tokio::spawn(async move {
            let mut buf = [0; 1024];
            loop {
                if let Ok((size, src)) = socket.recv_from(&mut buf) {
                    let msg: KademliaMessage = serde_json::from_slice(&buf[..size]).unwrap();
                    match msg {
                        KademliaMessage::FindNode { id } => {
                            let nodes = routing_table.lock().unwrap().iter().cloned().collect();
                            let response = KademliaMessage::Response { nodes, value: None };
                            let response_bytes = serde_json::to_vec(&response).unwrap();
                            socket.send_to(&response_bytes, src).unwrap();
                        }
                        KademliaMessage::Store { key, value } => {
                            data_store.lock().unwrap().insert(key, value);
                        }
                        KademliaMessage::FindValue { key } => {
                            let value = data_store.lock().unwrap().get(&key).cloned();
                            let response = KademliaMessage::Response { nodes: vec![], value };
                            let response_bytes = serde_json::to_vec(&response).unwrap();
                            socket.send_to(&response_bytes, src).unwrap();
                        }
                        _ => {}
                    }
                }
            }
        });
    }
}

// Kademlia Messages
#[derive(Debug, Serialize, Deserialize)]
pub enum KademliaMessage {
    FindNode { id: u64 },
    Store { key: u64, value: String },
    FindValue { key: u64 },
    Response { nodes: Vec<Node>, value: Option<String> },
}