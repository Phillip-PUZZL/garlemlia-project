use async_trait::async_trait;
use kademlia_structs::{HeapNode, KBucket, KMessage, KademliaMessage, KademliaRoutingTable, MessageChannel, Node};
use serde::{Deserialize, Serialize};
use std::collections::{BinaryHeap, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::Mutex;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SimulatedRoutingTable {
    local_node: Node,
    buckets: HashMap<u8, KBucket>,
}

#[async_trait]
impl KademliaRoutingTable for SimulatedRoutingTable {
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

    // Add a node to the routing table from Kademlia Responder
    async fn add_node_from_responder(&mut self, _node: Node, _socket: &UdpSocket) {
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

            SimulatedMessageHandler::create().send(socket, &lru_address, &ping_message).await;

            // Wait up to 300ms for a response asynchronously
            let response = SimulatedMessageHandler::create().recv(response_queue, rx, 300, &lru_address).await;


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

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SimulatedMessageHandler {}

#[async_trait]
impl KMessage for SimulatedMessageHandler {
    fn create() -> Box<dyn KMessage> {
        Box::new(SimulatedMessageHandler {})
    }

    // Send a message to another node
    async fn send(&self, _socket: &UdpSocket, target: &SocketAddr, msg: &KademliaMessage) {

    }

    async fn recv(&self, _response_queue: Arc<Mutex<HashMap<u128, Vec<KademliaMessage>>>>,
                  _rx: Arc<Mutex<UnboundedReceiver<MessageChannel>>>, _time: u64, src: &SocketAddr) -> Option<KademliaMessage> {
        let km = KademliaMessage::FindNode { id: 0, sender_id: 0 };

        Some(km)
    }

    fn clone_box(&self) -> Box<dyn KMessage> {
        Box::new(self.clone())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileNode {
    pub id: u128,
    pub address: String,
    pub routing_table: Vec<Node>,
    pub data_store: HashMap<u128, String>,
    pub response_queue: HashMap<u128, Vec<KademliaMessage>>,
    pub locked: bool,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulatedNode {
    pub node: Node,
    pub routing_table: SimulatedRoutingTable,
    pub data_store: HashMap<u128, String>,
    pub response_queue: HashMap<u128, Vec<KademliaMessage>>,
    pub locked: bool,
}

impl SimulatedNode {
    pub fn new(node: Node, rt: SimulatedRoutingTable, ds: HashMap<u128, String>, rq: HashMap<u128, Vec<KademliaMessage>>) -> SimulatedNode {
        SimulatedNode {
            node,
            routing_table: rt,
            data_store: ds,
            response_queue: rq,
            locked: false,
        }
    }

    fn set_routing_table(&mut self, rt: Box<dyn KademliaRoutingTable>) {
        self.routing_table.update_from(&*rt);
    }

    fn set_data_store(&mut self, data_store: &mut HashMap<u128, String>) {
        self.data_store.clear();

        for i in data_store.iter() {
            self.data_store.insert(*i.0, i.1.clone());
        }
    }

    fn set_response_queue(&mut self, response_queue: &mut HashMap<u128, Vec<KademliaMessage>>) {
        self.response_queue.clear();

        for i in response_queue.iter() {
            self.response_queue.insert(*i.0, i.1.clone());
        }
    }
}

fn file_node_to_simulated(file_node: FileNode) -> SimulatedNode {
    let mut rt = SimulatedRoutingTable::new(Node { id: file_node.id, address: file_node.address.parse().unwrap() });

    for node in file_node.routing_table {
        rt.insert_direct(node);
    }

    SimulatedNode::new(Node { id: file_node.id, address: file_node.address.parse().unwrap() }, rt, file_node.data_store, file_node.response_queue)
}

fn simulated_node_to_file(sim_node: SimulatedNode) -> FileNode {
    FileNode {
        id: sim_node.node.id,
        address: sim_node.node.address.to_string(),
        routing_table: sim_node.routing_table.flat_nodes(),
        data_store: sim_node.data_store,
        response_queue: sim_node.response_queue,
        locked: sim_node.locked,
    }
}

/// Loads SimulatedNodes from a JSON file
pub async fn load_simulated_nodes(file_path: &str) -> Result<Vec<SimulatedNode>, Box<dyn std::error::Error>> {
    let mut file = File::open(file_path).await?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).await?;
    let file_nodes: Vec<FileNode> = serde_json::from_str(&contents)?;
    let mut simulated_nodes = vec![];
    for node in file_nodes {
        simulated_nodes.push(file_node_to_simulated(node));
    }
    Ok(simulated_nodes)
}

/// Saves SimulatedNodes to a JSON file
pub async fn save_simulated_nodes(file_path: &str, nodes: &Vec<SimulatedNode>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file_nodes = vec![];
    for node in nodes {
        file_nodes.push(simulated_node_to_file(node.clone()));
    }

    let json_string = serde_json::to_string_pretty(&file_nodes)?;
    let mut file = File::create(file_path).await?;
    file.write_all(json_string.as_bytes()).await?;
    Ok(())
}