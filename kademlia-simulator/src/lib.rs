use async_trait::async_trait;
use kademlia_structs::{KMessage, KademliaMessage, MessageChannel, MessageError, Node, RoutingTable, DEFAULT_K};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use lazy_static::lazy_static;
use once_cell::sync::OnceCell;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use kademlia::Kademlia;

#[derive(Debug, Clone)]
pub struct Simulator {
    pub nodes: HashMap<SocketAddr, Arc<Mutex<SimulatedNode>>>,
    pub messages: HashMap<SocketAddr, KademliaMessage>,
    pub errors: HashMap<SocketAddr, MessageError>,
}

impl Simulator {
    pub fn new_empty() -> Simulator {
        Simulator {
            nodes: HashMap::new(),
            messages: HashMap::new(),
            errors: HashMap::new()  ,
        }
    }

    pub async fn create_node(&mut self, new_node: SimulatedNode) {
        self.nodes.insert(new_node.node.address.clone(), Arc::new(Mutex::new(new_node)));
    }

    pub async fn get_node(&self, address: SocketAddr) -> Option<Arc<Mutex<SimulatedNode>>> {
        self.nodes.get(&address).cloned()
    }

    pub async fn get_all_nodes(&self) -> Vec<SimulatedNode> {
        let mut finished = vec![];
        let sims;
        {
            sims = self.nodes.clone();
        }

        for i in sims {
            if let Some(node) = self.get_node(i.0).await {
                finished.push(node.lock().await.clone());
            }
        }

        finished
    }
}


lazy_static! {
    static ref SIM: Arc<Mutex<Simulator>> = Arc::new(Mutex::new(Simulator::new_empty()));
}

// A global cell that can store our socket once
static GLOBAL_SOCKET: OnceCell<Arc<UdpSocket>> = OnceCell::new();

// A helper function to initialize the socket (only if not already set)
pub async fn init_socket_once() -> Arc<UdpSocket> {
    if let Some(socket) = GLOBAL_SOCKET.get() {
        return socket.clone();
    }

    // Bind the socket
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:12000").await.unwrap());

    // Place it in the OnceCell
    let _ = GLOBAL_SOCKET.set(socket.clone());
    socket
}

// A getter function to retrieve the socket once it has been initialized
pub fn get_global_socket() -> Option<Arc<UdpSocket>> {
    GLOBAL_SOCKET.get().cloned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileNode {
    pub id: u128,
    pub address: String,
    pub routing_table: Vec<Node>,
    pub data_store: HashMap<u128, String>
}

#[derive(Debug, Clone)]
pub struct SimulatedNode {
    pub node: Node,
    pub routing_table: RoutingTable,
    pub data_store: HashMap<u128, String>
}

impl SimulatedNode {
    pub fn new(node: Node, rt: RoutingTable, ds: HashMap<u128, String>) -> SimulatedNode {
        SimulatedNode {
            node,
            routing_table: rt,
            data_store: ds
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

    async fn add_node(&mut self, node: Node) {
        self.routing_table.add_node(Arc::from(SimulatedMessageHandler::create(0)), node, &*get_global_socket().unwrap()).await;
    }

    async fn parse_message(&mut self, node: Node, msg: KademliaMessage) -> Option<KademliaMessage> {
        match msg {
            KademliaMessage::FindNode { id, .. } => {
                // Add the sender to the routing table
                self.add_node(node).await;
                let response = if id == self.node.id {
                    // If the search target is this node itself, return only this node
                    KademliaMessage::Response {
                        nodes: vec![self.node.clone()],
                        value: None,
                        sender_id: self.node.id,
                    }
                } else {
                    // Return the closest known nodes
                    let closest_nodes = self.routing_table.find_closest_nodes(id, DEFAULT_K).await;
                    KademliaMessage::Response {
                        nodes: closest_nodes,
                        value: None,
                        sender_id: self.node.id,
                    }
                };

                Some(response)
            }

            // Store a key-value pair
            KademliaMessage::Store { key, value, .. } => {
                self.add_node(node).await;
                self.data_store.insert(key, value);
                None
            }

            // Use find_closest_nodes() if value is not found
            KademliaMessage::FindValue { key, .. } => {
                self.add_node(node).await;
                let value = self.data_store.get(&key).cloned();

                let response = if let Some(val) = value {
                    KademliaMessage::Response {
                        nodes: vec![],
                        value: Some(val),
                        sender_id: self.node.id,
                    }
                } else {
                    let closest_nodes = self.routing_table.find_closest_nodes(key, DEFAULT_K).await;

                    KademliaMessage::Response {
                        nodes: closest_nodes,
                        value: None,
                        sender_id: self.node.id,
                    }
                };

                Some(response)
            }

            KademliaMessage::Response { nodes, value, sender_id, .. } => {
                let _constructed = KademliaMessage::Response {
                    nodes,
                    value,
                    sender_id,
                };

                None
            }

            KademliaMessage::Ping { .. } => {
                Some(KademliaMessage::Pong { sender_id: self.node.id })
            }

            KademliaMessage::Pong { .. } => {
                None
            }

            KademliaMessage::Stop {} => {
                None
            }
        }
    }
}

#[derive(Debug, Clone)]
struct SimulatedMessageHandler { }

#[async_trait]
impl KMessage for SimulatedMessageHandler {
    fn create(_channel_count: u8) -> Box<dyn KMessage> {
        Box::new(SimulatedMessageHandler { })
    }

    async fn send_tx(&self, _addr: SocketAddr, _msg: MessageChannel) -> Result<(), MessageError> {
        Ok(())
    }

    async fn send_no_recv(&self, _socket: &UdpSocket, self_node: Option<Node>, target: &SocketAddr, msg: &KademliaMessage) -> Result<(), MessageError> {
        let mut check_node;
        {
            check_node = SIM.lock().await.nodes.get_mut(target).cloned();
        }

        match check_node {
            Some(node) => {
                if let Some(response) = node.lock().await.parse_message(self_node.unwrap(), msg.clone()).await {
                    SIM.lock().await.messages.insert(target.clone(), response);
                }
                Ok(())
            }
            None => {
                SIM.lock().await.errors.insert(*target, MessageError::Timeout);
                Ok(())
            }
        }
    }

    // Send a message to another node
    async fn send(&self, _socket: &UdpSocket, self_node: Option<Node>, target: &SocketAddr, msg: &KademliaMessage) -> Result<(), MessageError> {
        let mut check_node;
        {
            check_node = SIM.lock().await.nodes.get_mut(target).cloned();
        }

        match check_node {
            Some(node) => {
                if let Some(response) = node.lock().await.parse_message(self_node.unwrap(), msg.clone()).await {
                    SIM.lock().await.messages.insert(target.clone(), response);
                }
                Ok(())
            }
            None => {
                SIM.lock().await.errors.insert(*target, MessageError::Timeout);
                Ok(())
            }
        }
    }

    async fn recv(&self, _time: u64, src: &SocketAddr) -> Result<KademliaMessage, MessageError> {
        let km = SIM.lock().await.messages.remove(src);
        let em = SIM.lock().await.errors.remove(src);

        match km {
            Some(km) => {
                Ok(km.clone())
            }
            None => {
                match em {
                    Some(em) => {
                        Err(em)
                    }
                    None => {
                        Err(MessageError::IoError("UHHHHHHHHH".to_string()))
                    }
                }
            }
        }
    }

    fn clone_box(&self) -> Box<dyn KMessage> {
        Box::new(self.clone())
    }
}

fn file_node_to_simulated(file_node: FileNode) -> SimulatedNode {
    let mut rt = RoutingTable::new(Node { id: file_node.id, address: file_node.address.parse().unwrap() });

    for node in file_node.routing_table {
        rt.insert_direct(node);
    }

    SimulatedNode::new(Node { id: file_node.id, address: file_node.address.parse().unwrap() }, rt, file_node.data_store)
}

async fn simulated_node_to_file(sim_node: SimulatedNode) -> FileNode {
    FileNode {
        id: sim_node.node.id,
        address: sim_node.node.address.to_string(),
        routing_table: sim_node.routing_table.flat_nodes().await,
        data_store: sim_node.data_store
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
        file_nodes.push(simulated_node_to_file(node.clone()).await);
    }

    let json_string = serde_json::to_string_pretty(&file_nodes)?;
    let mut file = File::create(file_path).await?;
    file.write_all(json_string.as_bytes()).await?;
    Ok(())
}

pub async fn create_network(mut nodes: Vec<SimulatedNode>) {
    let mut addresses = vec![];
    for node in nodes.clone() {
        addresses.push(node.node.address.clone());
    }

    {
        SIM.lock().await.create_node(SimulatedNode {
            node: nodes[0].node.clone(),
            routing_table: nodes[0].routing_table.clone(),
            data_store: nodes[0].data_store.clone()
        }).await;
    }

    nodes.remove(0);
    let mut index = 0;
    let mut range = 1;
    for node in nodes {
        let mut run_node = Kademlia::new_with_sock(node.node.id, "127.0.0.1", node.node.address.port(), RoutingTable::new(Node {id: node.node.id, address: SocketAddr::new("127.0.0.1".parse().unwrap(), node.node.address.port())}), SimulatedMessageHandler::create(0), get_global_socket().unwrap().clone()).await;

        let ind;
        if index ^ (range * 2) == 0 {
            range = range * 2;
        }

        ind = rand::random_range(0..range);

        run_node.join_network(get_global_socket().unwrap().clone(), &addresses[ind].clone()).await;

        {
            let node_actual = run_node.node.lock().await.clone();
            let mut rt = RoutingTable::new(node_actual.clone());
            rt.update_from(run_node.routing_table.lock().await.clone()).await;
            SIM.lock().await.create_node(SimulatedNode {
                node: node_actual.clone(),
                routing_table: rt.clone(),
                data_store: run_node.data_store.lock().await.clone()
            }).await;
        }

        index = index + 1;
    }
}

pub async fn create_random_simulated_nodes(count: u16) -> Vec<SimulatedNode> {
    let mut simulated_nodes = vec![];

    for i in 0..count {
        let node = Node { id: rand::random::<u128>(), address: SocketAddr::new("127.0.0.1".parse().unwrap(), 9000 + i)};
        simulated_nodes.push(SimulatedNode {
            node: node.clone(),
            routing_table: RoutingTable {local_node: node.clone(), buckets: Arc::new(Mutex::new(HashMap::new()))},
            data_store: HashMap::new()
        });
    }

    simulated_nodes
}

pub async fn run_create_network(updated_file_path: &str, count: u16) {
    let nodes = create_random_simulated_nodes(count).await;

    create_network(nodes.clone()).await;

    let mut updated_nodes = nodes.clone();
    {
        updated_nodes = SIM.lock().await.get_all_nodes().await;
    }

    // Save the modified nodes back to a new file
    if let Err(e) = save_simulated_nodes(updated_file_path, &updated_nodes).await {
        eprintln!("Error saving nodes: {}", e);
    } else {
        println!("Saved updated nodes to {}", updated_file_path);
    }
}

/// TESTS
#[cfg(test)]
mod sim_tests {
    use std::net::SocketAddr;
    use kademlia::Kademlia;
    use kademlia_structs::{KMessage, RoutingTable, Node};
    use crate::{load_simulated_nodes, save_simulated_nodes, SimulatedMessageHandler};

    async fn create_test_node(id: u128, port: u16) -> Kademlia {
        let mut node = Kademlia::new(id, "127.0.0.1", port, RoutingTable::new(Node { id, address: SocketAddr::new("127.0.0.1".parse().unwrap(), port) }), SimulatedMessageHandler::create(0)).await;

        node
    }

    #[tokio::test]
    async fn simulated_node_file_test() {
        let file_path = "../kademlia_nodes_empty.json";

        // Load nodes from JSON
        match load_simulated_nodes(file_path).await {
            Ok(mut nodes) => {
                println!("Loaded nodes: {:?}", nodes);

                // Save the modified nodes back to a new file
                let new_file_path = "../updated_nodes.json";
                if let Err(e) = save_simulated_nodes(new_file_path, &nodes).await {
                    eprintln!("Error saving nodes: {}", e);
                } else {
                    println!("Saved updated nodes to {}", new_file_path);
                }
            }
            Err(e) => eprintln!("Error loading nodes: {}", e),
        }
    }
}