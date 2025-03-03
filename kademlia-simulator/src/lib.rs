use async_trait::async_trait;
use kademlia_structs::{KMessage, KademliaMessage, MessageChannel, MessageError, Node, RoutingTable};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::Mutex;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SimulatedMessageHandler {}

#[async_trait]
impl KMessage for SimulatedMessageHandler {
    fn create() -> Box<dyn KMessage> {
        Box::new(SimulatedMessageHandler {})
    }

    // Send a message to another node
    async fn send(
        &self,
        _socket: &UdpSocket,
        target: &SocketAddr,
        msg: &KademliaMessage
    ) -> Result<(), MessageError> {

        Ok(())
    }

    async fn recv(
        &self,
        _response_queue: Arc<Mutex<HashMap<u128, Vec<KademliaMessage>>>>,
        _rx: Arc<Mutex<UnboundedReceiver<MessageChannel>>>,
        _time: u64,
        src: &SocketAddr
    ) -> Result<KademliaMessage, MessageError> {
        let km = KademliaMessage::FindNode { id: 0, sender_id: 0 };

        Ok(km)
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
    pub routing_table: RoutingTable,
    pub data_store: HashMap<u128, String>,
    pub response_queue: HashMap<u128, Vec<KademliaMessage>>,
    pub locked: bool,
}

impl SimulatedNode {
    pub fn new(node: Node, rt: RoutingTable, ds: HashMap<u128, String>, rq: HashMap<u128, Vec<KademliaMessage>>) -> SimulatedNode {
        SimulatedNode {
            node,
            routing_table: rt,
            data_store: ds,
            response_queue: rq,
            locked: false,
        }
    }

    fn set_routing_table(&mut self, rt: RoutingTable) {
        self.routing_table.update_from(rt);
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
    let mut rt = RoutingTable::new(Node { id: file_node.id, address: file_node.address.parse().unwrap() });

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