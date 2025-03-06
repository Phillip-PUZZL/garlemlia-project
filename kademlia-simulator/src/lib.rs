use async_trait::async_trait;
use kademlia_structs::{KBucket, KMessage, KademliaMessage, MessageChannel, MessageError, Node, RoutingTable, DEFAULT_K};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use lazy_static::lazy_static;
use once_cell::sync::OnceCell;
use rand::prelude::IndexedRandom;
use rand::Rng;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex};
use kademlia::Kademlia;

#[derive(Debug, Clone)]
pub struct Simulator {
    pub nodes: HashMap<SocketAddr, Arc<Mutex<SimulatedNode>>>,
    pub times_failed: u16
}

impl Simulator {
    pub fn new_empty() -> Simulator {
        Simulator {
            nodes: HashMap::new(),
            times_failed: 0
        }
    }

    pub fn set_nodes(&mut self, nodes: Vec<SimulatedNode>) {
        for node in nodes {
            self.nodes.insert(node.node.address, Arc::new(Mutex::new(node)));
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

    // TODO: Modify FileNode and SimulatedNode to have is_alive: boolean key-value pairs
    // TODO: After done, need to create an event loop which randomly connects and disconnects
    // TODO: existing Node's and also creates random new nodes to join the network.
    pub fn node_is_alive(&self, _address: SocketAddr) -> bool {
        rand::random_bool(0.8)
    }

    pub fn add_fail(&mut self) {
        self.times_failed += 1;
    }

    pub fn get_fail(&self) -> u16 {
        self.times_failed
    }
}

struct RoutingTableInfo {
    routing_table: Arc<Mutex<RoutingTable>>
}

impl RoutingTableInfo {
    pub fn new() -> RoutingTableInfo {
        RoutingTableInfo {
            routing_table: Arc::new(Mutex::new(RoutingTable::new( Node { id: 0, address: "127.0.0.1:0".parse().unwrap() } )))
        }
    }

    pub fn from(routing_table: Arc<Mutex<RoutingTable>>) -> RoutingTableInfo {
        RoutingTableInfo {
            routing_table
        }
    }

    pub fn set(&mut self, routing_table: Arc<Mutex<RoutingTable>>) {
        self.routing_table = routing_table;
    }
}

lazy_static! {
    static ref SIM: Arc<Mutex<Simulator>> = Arc::new(Mutex::new(Simulator::new_empty()));
    static ref RUNNING_NODES: Arc<Mutex<HashSet<Node>>> = Arc::new(Mutex::new(HashSet::new()));
    static ref RUNNING_ROUTING_TABLES: Arc<Mutex<HashMap<Node, RoutingTableInfo>>> = Arc::new(Mutex::new(HashMap::new()));
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileNode {
    pub id: u128,
    pub address: String,
    pub routing_table: SerializableRoutingTable,
    pub data_store: HashMap<u128, String>
}

#[derive(Debug, Clone)]
pub struct SimulatedNode {
    pub node: Node,
    pub routing_table: Arc<Mutex<RoutingTable>>,
    pub data_store: HashMap<u128, String>
}

impl SimulatedNode {
    pub fn new(node: Node, rt: RoutingTable, ds: HashMap<u128, String>) -> SimulatedNode {
        SimulatedNode {
            node,
            routing_table: Arc::new(Mutex::new(rt)),
            data_store: ds
        }
    }

    async fn set_routing_table(&mut self, rt: RoutingTable) {
        self.routing_table.lock().await.update_from(rt).await;
    }

    fn set_data_store(&mut self, data_store: &mut HashMap<u128, String>) {
        self.data_store.clear();

        for i in data_store.iter() {
            self.data_store.insert(*i.0, i.1.clone());
        }
    }

    async fn add_node(&mut self, node: Node) {
        let mut rt = self.routing_table.lock().await;
        let index = rt.bucket_index(node.clone().id);
        if !rt.check_and_update_bucket(node.clone(), index).await {
            let mut locked_buckets = rt.buckets.lock().await;
            let bucket = locked_buckets.get_mut(&index).unwrap();
            if let Some(lru_node) = bucket.nodes.front().cloned() {
                if SIM.lock().await.node_is_alive(lru_node.address) {
                    bucket.update_node(lru_node);
                } else {
                    bucket.remove(&lru_node);
                    bucket.insert(node);
                }
            }
        }
    }

    async fn parse_message(&mut self, sender_node: Node, msg: KademliaMessage) -> Result<KademliaMessage, Option<MessageError>> {
        match msg {
            KademliaMessage::FindNode { id, .. } => {
                // Add the sender to the routing table
                self.add_node(sender_node).await;
                let response = if id == self.node.id {
                    // If the search target is this node itself, return only this node
                    KademliaMessage::Response {
                        nodes: vec![self.node.clone()],
                        value: None,
                        sender: self.node.clone(),
                    }
                } else {
                    // Return the closest known nodes
                    let closest_nodes;
                    {
                        closest_nodes = self.routing_table.lock().await.find_closest_nodes(id, DEFAULT_K).await;
                    }

                    KademliaMessage::Response {
                        nodes: closest_nodes,
                        value: None,
                        sender: self.node.clone(),
                    }
                };

                Ok(response)
            }

            // Store a key-value pair
            KademliaMessage::Store { key, value, .. } => {
                self.add_node(sender_node).await;
                self.data_store.insert(key, value);
                Err(None)
            }

            // Use find_closest_nodes() if value is not found
            KademliaMessage::FindValue { key, .. } => {
                self.add_node(sender_node).await;
                let value = self.data_store.get(&key).cloned();

                let response = if let Some(val) = value {
                    KademliaMessage::Response {
                        nodes: vec![],
                        value: Some(val),
                        sender: self.node.clone(),
                    }
                } else {
                    let closest_nodes;
                    {
                        closest_nodes = self.routing_table.lock().await.find_closest_nodes(key, DEFAULT_K).await;
                    }

                    KademliaMessage::Response {
                        nodes: closest_nodes,
                        value: None,
                        sender: self.node.clone(),
                    }
                };

                Ok(response)
            }

            KademliaMessage::Response { nodes, value, sender, .. } => {
                println!("This should never happen");
                self.add_node(sender_node).await;
                let _constructed = KademliaMessage::Response {
                    nodes,
                    value,
                    sender,
                };

                Err(None)
            }

            KademliaMessage::Ping { .. } => {
                if SIM.lock().await.node_is_alive(self.node.address) {
                    Ok(KademliaMessage::Pong { sender: self.node.clone() })
                } else {
                    Err(Some(MessageError::Timeout))
                }
            }

            KademliaMessage::Pong { .. } => {
                Err(None)
            }

            KademliaMessage::Stop {} => {
                Err(None)
            }
        }
    }
}

#[derive(Debug, Clone)]
struct SimulatedMessageHandler {
    pub messages: Arc<Mutex<HashMap<SocketAddr, VecDeque<Result<KademliaMessage, Option<MessageError>>>>>>,
}

#[async_trait]
impl KMessage for SimulatedMessageHandler {
    fn create(_channel_count: u8) -> Box<dyn KMessage> {
        Box::new(SimulatedMessageHandler {
            messages: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    async fn send_tx(&self, _addr: SocketAddr, _msg: MessageChannel) -> Result<(), MessageError> {
        Ok(())
    }

    async fn send_no_recv(&self, _socket: &UdpSocket, from_node: Node, target: &SocketAddr, msg: &KademliaMessage) -> Result<(), MessageError> {
        let check_node;
        {
            check_node = SIM.lock().await.nodes.get_mut(target).cloned();
        }

        match check_node {
            Some(node) => {
                let _ = node.lock().await.parse_message(from_node, msg.clone()).await;
            }
            None => {}
        }

        Ok(())
    }

    // Send a message to another node
    async fn send(&self, _socket: &UdpSocket, from_node: Node, target: &SocketAddr, msg: &KademliaMessage) -> Result<(), MessageError> {
        //println!("Send {:?} to {} from {}", msg, target, self_node.clone().address);
        let check_node;
        {
            check_node = SIM.lock().await.nodes.get_mut(target).cloned();
        }

        match check_node {
            Some(node) => {
                let mut self_messages = self.messages.lock().await;
                let mut node_locked = node.lock().await;

                if !self_messages.get(&target.clone()).is_some() {
                    self_messages.insert(target.clone(), VecDeque::new());
                }

                let response = node_locked.parse_message(from_node.clone(), msg.clone()).await;

                let messages = self_messages.get_mut(&target.clone());
                if let Some(msg_handler) = messages {
                    msg_handler.push_back(response.clone());
                }

                match response {
                    Ok(km) => {
                        let is_running;
                        {
                            is_running = RUNNING_ROUTING_TABLES.lock().await.contains_key(&from_node);
                        }
                        if is_running {
                            match km.sender() {
                                Some(sender) => {
                                    let mut running_table = RUNNING_ROUTING_TABLES.lock().await;
                                    let mut rt = running_table.get_mut(&from_node).unwrap().routing_table.lock().await;
                                    let index = rt.bucket_index(sender.clone().id);
                                    if !rt.check_and_update_bucket(sender.clone(), index).await {
                                        let mut locked_buckets = rt.buckets.lock().await;
                                        let bucket = locked_buckets.get_mut(&index).unwrap();
                                        if let Some(lru_node) = bucket.nodes.front().cloned() {
                                            if SIM.lock().await.node_is_alive(lru_node.address) {
                                                bucket.update_node(lru_node);
                                            } else {
                                                bucket.remove(&lru_node);
                                                bucket.insert(sender);
                                            }
                                        }
                                    }
                                }
                                None => {}
                            }
                        }
                    },
                    Err(_em) => {}
                }
            }
            _ => {
                let mut self_messages = self.messages.lock().await;

                if !self_messages.get(&target.clone()).is_some() {
                    self_messages.insert(target.clone(), VecDeque::new());
                }

                let messages = self_messages.get_mut(&target.clone());
                if let Some(msg_handler) = messages {
                    msg_handler.push_back(Err(Some(MessageError::MissingNode)));
                }
            }
        }

        Ok(())
    }

    async fn recv(&self, _time: u64, src: &SocketAddr) -> Result<KademliaMessage, MessageError> {
        let mut message = None;
        {
            let mut self_messages = self.messages.lock().await;
            let messages = self_messages.get_mut(src);
            if let Some(msg_handler) = messages {
                message = msg_handler.pop_front();
            }
        }

        match message {
            Some(message_info) => {
                match message_info {
                    Ok(km) => {
                        Ok(km.clone())
                    },
                    Err(em) => {
                        match em {
                            Some(em) => {
                                Err(em)
                            }
                            None => {
                                println!("No response should have been expected from {}", src);
                                Err(MessageError::IoError("UHHHHHHHHH".to_string()))
                            }
                        }
                    }
                }
            }
            None => {
                println!("No message found from {}", src);
                Err(MessageError::IoError("UHHHHHHHHH".to_string()))
            }
        }
    }

    fn clone_box(&self) -> Box<dyn KMessage> {
        Box::new(self.clone())
    }
}

async fn file_node_to_simulated(file_node: FileNode) -> SimulatedNode {
    SimulatedNode::new(Node { id: file_node.id, address: file_node.address.parse().unwrap() }, file_node.routing_table.to_routing_table(), file_node.data_store)
}

async fn simulated_node_to_file(sim_node: SimulatedNode) -> FileNode {
    FileNode {
        id: sim_node.node.id,
        address: sim_node.node.address.to_string(),
        routing_table: SerializableRoutingTable::from(sim_node.routing_table.lock().await.clone()).await,
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
        simulated_nodes.push(file_node_to_simulated(node).await);
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

async fn add_running(node: Node, routing_table: Arc<Mutex<RoutingTable>>) {
    {
        RUNNING_NODES.lock().await.insert(node.clone());
        RUNNING_ROUTING_TABLES.lock().await.insert(node, RoutingTableInfo::from(routing_table));
    }
}

async fn remove_running(node: Node) {
    {
        RUNNING_NODES.lock().await.remove(&node);
        RUNNING_ROUTING_TABLES.lock().await.remove(&node);
    }
}

pub async fn create_network(mut nodes: Vec<SimulatedNode>) {
    let mut addresses = vec![];
    let nodes_len = nodes.len();
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

    let mut usable_addresses = vec![nodes.get(0).unwrap().node.address];
    nodes.remove(0);
    let mut index = 0;
    let mut range = 1;
    let mut percent_threshold = 0.0;
    for node in nodes {
        if percent_threshold < index as f64/nodes_len as f64 {
            println!("RUNNING... {:.1}%: {}/{}", index as f64/nodes_len as f64 * 100.0, index, nodes_len);
            percent_threshold = percent_threshold + 0.01;
        }

        let mut run_node = Kademlia::new_with_sock(node.node.id, "127.0.0.1", node.node.address.port(), RoutingTable::new(node.node.clone()), SimulatedMessageHandler::create(0), get_global_socket().unwrap().clone());

        add_running(node.node.clone(), Arc::clone(&run_node.routing_table)).await;

        let ind;
        if index ^ (range * 2) == 0 {
            range = range * 2;
        }

        ind = rand::random_range(0..range);

        //run_node.join_network(get_global_socket().unwrap().clone(), &usable_addresses.choose(&mut rand::rng()).unwrap().clone()).await;
        run_node.join_network(get_global_socket().unwrap().clone(), &addresses[ind]).await;

        {
            let node_actual = run_node.node.lock().await.clone();
            let mut rt = RoutingTable::new(node_actual.clone());
            rt.update_from(run_node.routing_table.lock().await.clone()).await;
            SIM.lock().await.create_node(SimulatedNode {
                node: node_actual.clone(),
                routing_table: Arc::new(Mutex::new(rt.clone())),
                data_store: run_node.data_store.lock().await.clone()
            }).await;
        }

        remove_running(node.node.clone()).await;

        usable_addresses.push(node.node.address);

        index = index + 1;
    }
}

pub async fn create_random_simulated_nodes(count: u16) -> Vec<SimulatedNode> {
    let mut simulated_nodes = vec![];
    let mut used_ids = HashSet::new();

    for i in 0..count {
        let mut id = rand::random::<u128>();
        while used_ids.contains(&id) {
            println!("TRIED TO USE COPY OF ID {}", id);
            id = rand::random::<u128>();
        }
        used_ids.insert(id);
        let node = Node { id, address: SocketAddr::new("127.0.0.1".parse().unwrap(), 9000 + i)};
        simulated_nodes.push(SimulatedNode {
            node: node.clone(),
            routing_table: Arc::new(Mutex::new(RoutingTable {local_node: node.clone(), buckets: Arc::new(Mutex::new(HashMap::new()))})),
            data_store: HashMap::new()
        });
    }

    simulated_nodes
}

pub async fn run_create_network(updated_file_path: &str, count: u16) {
    let nodes = create_random_simulated_nodes(count).await;

    create_network(nodes.clone()).await;

    let updated_nodes;
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
    use std::sync::Arc;
    use rand::seq::IndexedRandom;
    use kademlia::Kademlia;
    use kademlia_structs::{KMessage, RoutingTable, Node};
    use crate::{get_global_socket, load_simulated_nodes, save_simulated_nodes, SimulatedMessageHandler, SIM, add_running, remove_running};

    async fn create_test_node(id: u128, port: u16) -> Kademlia {
        let node_actual = Node { id, address: SocketAddr::new("127.0.0.1".parse().unwrap(), port) };

        let mut node = Kademlia::new_with_sock(id, "127.0.0.1", port, RoutingTable::new(node_actual.clone()), SimulatedMessageHandler::create(0), get_global_socket().unwrap().clone());

        add_running(node_actual.clone(), Arc::clone(&node.routing_table)).await;

        node
    }

    #[tokio::test]
    async fn simulated_node_find_test() {
        crate::init_socket_once().await;
        let file_path = "../simulated_nodes_10000.json";

        // Load nodes from JSON
        match load_simulated_nodes(file_path).await {
            Ok(nodes) => {

                {
                    SIM.lock().await.set_nodes(nodes.clone());
                }

                let mut node1 = create_test_node(rand::random::<u128>(), 6000).await;

                {
                    println!("NODE:\nID: {}", node1.node.lock().await.id);
                }

                let test_node_sock = SocketAddr::new("127.0.0.1".parse().unwrap(), 9000 + (rand::random::<u16>() % nodes.len() as u16));

                let selected_port = 9000 + (nodes.len() / 2) as u16;

                let node_random = nodes.choose(&mut rand::rng()).unwrap().clone();
                let mut temp_node_selected = None;
                {
                    let temp_node = SIM.lock().await.get_node(SocketAddr::new("127.0.0.1".parse().unwrap(), selected_port)).await;
                    match temp_node {
                        Some(node_unlocked) => {
                            temp_node_selected = Some(node_unlocked.lock().await.clone());
                        }
                        None => {}
                    }
                }

                assert!(temp_node_selected.is_some(), "Could not retrieve Node with selected port");

                let node_selected = temp_node_selected.unwrap();

                println!("SEARCHING FOR:");
                println!("ID: {}, Address: {}", node_selected.node.id, node_selected.node.address);
                println!("ID: {}, Address: {}", node_random.node.id, node_random.node.address);

                println!("BOOTSTRAP IP: 127.0.0.1:{}", test_node_sock.clone().port());

                node1.join_network(get_global_socket().unwrap().clone(), &test_node_sock).await;

                println!("Joined Network");

                // Perform lookup
                let found_nodes_selected = node1.iterative_find_node(Arc::clone(&node1.socket), node_selected.node.id).await;
                let found_nodes_random = node1.iterative_find_node(Arc::clone(&node1.socket), node_random.node.id).await;

                println!("Send Find Node");

                println!("SEARCH FOR SELECTED NODE WITH PORT {} :: found_nodes: {:?}", selected_port, found_nodes_selected);
                println!("SEARCH FOR RANDOM NODE WITH PORT {} :: found_nodes: {:?}", node_random.node.address.port(), found_nodes_random);
                {
                    println!("ROUTING TABLE:\n{}", node1.routing_table.lock().await.to_string().await);
                }

                remove_running(node1.node.lock().await.clone()).await;

                assert_eq!(found_nodes_selected[0], node_selected.node, "Should find selected, and it should be first in the list");
                assert_eq!(found_nodes_random[0], node_random.node, "Should find random node, and it should be first in the list");

            }
            Err(e) => {
                eprintln!("Error loading nodes: {}", e);
                assert!(false, "Could not load nodes");
            },
        }
    }

    #[tokio::test]
    async fn simulated_node_store_test() {
        crate::init_socket_once().await;
        let file_path = "../simulated_nodes_10000.json";

        // Load nodes from JSON
        match load_simulated_nodes(file_path).await {
            Ok(nodes) => {

                {
                    SIM.lock().await.set_nodes(nodes.clone());
                }

                let mut node1 = create_test_node(rand::random::<u128>(), 6000).await;
                let mut node2 = create_test_node(rand::random::<u128>(), 6001).await;

                {
                    println!("NODE1:\nID: {}", node1.node.lock().await.id);
                    println!("NODE2:\nID: {}", node2.node.lock().await.id);
                }

                let test_node_sock1 = SocketAddr::new("127.0.0.1".parse().unwrap(), 9000 + (rand::random::<u16>() % nodes.len() as u16));
                let test_node_sock2 = SocketAddr::new("127.0.0.1".parse().unwrap(), 9000 + (rand::random::<u16>() % nodes.len() as u16));

                println!("NODE1 BOOTSTRAP IP: 127.0.0.1:{}", test_node_sock1.clone().port());
                println!("NODE2 BOOTSTRAP IP: 127.0.0.1:{}", test_node_sock2.clone().port());

                node1.join_network(get_global_socket().unwrap().clone(), &test_node_sock1).await;
                println!("Node1 Joined Network");
                node2.join_network(get_global_socket().unwrap().clone(), &test_node_sock2).await;
                println!("Node2 Joined Network");

                let key = rand::random::<u128>();
                let value = "PLEASE DEAR GOD LET THIS WORK".to_string();
                println!("STORE:\nKey: {}, Value: {}", key, value);

                // Perform store
                let store_nodes = node1.store_value(Arc::clone(&node1.socket), key, value.clone()).await;
                println!("Send Store");
                assert_eq!(store_nodes.len(), 2, "Should have stored in 2 nodes");

                // Perform search
                let found_value_option = node2.iterative_find_value(Arc::clone(&node2.socket), key).await;
                println!("Search Value");
                assert!(found_value_option.is_some(), "Did not find value");
                let found_value = found_value_option.unwrap();

                remove_running(node1.node.lock().await.clone()).await;
                remove_running(node2.node.lock().await.clone()).await;

                assert_eq!(found_value, value, "Should find value and it should be the correct one.");

                let mut updated_nodes = nodes.clone();
                {
                    let sim = SIM.lock().await;
                    updated_nodes = sim.get_all_nodes().await;
                }

                // Save the modified nodes back to a new file
                let new_file_path = "../updated_simulator_nodes_stored.json";
                if let Err(e) = save_simulated_nodes(new_file_path, &updated_nodes).await {
                    eprintln!("Error saving nodes: {}", e);
                } else {
                    println!("Saved updated nodes to {}", new_file_path);
                }
            }
            Err(e) => {
                eprintln!("Error loading nodes: {}", e);
                assert!(false, "Could not load nodes");
            },
        }
    }
}