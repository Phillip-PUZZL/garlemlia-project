use crate::garlemlia::garlemlia;
use crate::garlemlia_structs::garlemlia_structs;
use crate::garlic_cast::garlic_cast;
use async_trait::async_trait;
use garlemlia::Garlemlia;
use garlemlia_structs::{GMessage, GarlemliaMessage, GarlicMessage, KBucket, MessageChannel, MessageError, Node, RoutingTable, DEFAULT_K};
use garlic_cast::GarlicCast;
use lazy_static::lazy_static;
use once_cell::sync::OnceCell;
use rand::prelude::IndexedRandom;
use rand::random_range;
use rand_core::OsRng;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use crate::garlemlia_structs::garlemlia_structs::SerializableRoutingTable;
use crate::garlic_cast::garlic_cast::SerializableGarlicCast;

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
        true
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
    pub static ref SIM: Arc<Mutex<Simulator>> = Arc::new(Mutex::new(Simulator::new_empty()));
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
pub struct FileNode {
    pub id: u128,
    pub address: String,
    pub routing_table: SerializableRoutingTable,
    pub data_store: HashMap<u128, String>,
    pub garlic: SerializableGarlicCast
}

#[derive(Debug, Clone)]
pub struct SimulatedNode {
    pub node: Node,
    pub routing_table: Arc<Mutex<RoutingTable>>,
    pub data_store: HashMap<u128, String>,
    pub garlic: Arc<Mutex<GarlicCast>>
}

impl SimulatedNode {
    pub fn new(node: Node, rt: RoutingTable, ds: HashMap<u128, String>, gc: GarlicCast) -> SimulatedNode {
        SimulatedNode {
            node,
            routing_table: Arc::new(Mutex::new(rt)),
            data_store: ds,
            garlic: Arc::new(Mutex::new(gc))
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
            let mut locked_buckets = rt.buckets().await;
            let bucket = locked_buckets.get_mut(&index).unwrap();
            if let Some(lru_node) = bucket.nodes.front().cloned() {
                let mut is_alive = false;
                {
                    is_alive = SIM.lock().await.node_is_alive(lru_node.address);
                }

                if is_alive {
                    bucket.update_node(lru_node);
                } else {
                    bucket.remove(&lru_node);
                    bucket.insert(node);
                }
            }
        }
    }

    async fn parse_message(&mut self, sender_node: Node, msg: GarlemliaMessage) -> Result<GarlemliaMessage, Option<MessageError>> {
        match msg {
            GarlemliaMessage::FindNode { id, .. } => {
                // Add the sender to the routing table
                self.add_node(sender_node).await;
                let response = if id == self.node.id {
                    // If the search target is this node itself, return only this node
                    GarlemliaMessage::Response {
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

                    GarlemliaMessage::Response {
                        nodes: closest_nodes,
                        value: None,
                        sender: self.node.clone(),
                    }
                };

                Ok(response)
            }

            // Store a key-value pair
            GarlemliaMessage::Store { key, value, .. } => {
                self.add_node(sender_node).await;
                self.data_store.insert(key, value);
                Err(None)
            }

            // Use find_closest_nodes() if value is not found
            GarlemliaMessage::FindValue { key, .. } => {
                self.add_node(sender_node).await;
                let value = self.data_store.get(&key).cloned();

                let response = if let Some(val) = value {
                    GarlemliaMessage::Response {
                        nodes: vec![],
                        value: Some(val),
                        sender: self.node.clone(),
                    }
                } else {
                    let closest_nodes;
                    {
                        closest_nodes = self.routing_table.lock().await.find_closest_nodes(key, DEFAULT_K).await;
                    }

                    GarlemliaMessage::Response {
                        nodes: closest_nodes,
                        value: None,
                        sender: self.node.clone(),
                    }
                };

                Ok(response)
            }

            GarlemliaMessage::Response { nodes, value, sender, .. } => {
                println!("This should never happen");
                self.add_node(sender_node).await;
                let _constructed = GarlemliaMessage::Response {
                    nodes,
                    value,
                    sender,
                };

                Err(None)
            }

            GarlemliaMessage::Garlic { msg, sender } => {
                match msg {
                    GarlicMessage::IsAlive { .. } => {
                        return Err(None)
                    }
                    _ => {}
                }

                //println!("Before SIM lock 2");
                let mut is_alive = false;
                {
                    is_alive = SIM.lock().await.node_is_alive(self.node.address);
                }
                //println!("After SIM lock 2");

                if is_alive {
                    self.add_node(sender_node.clone()).await;
                    let sender_clone = sender_node.clone();
                    let msg_clone = msg.clone();
                    let garlic = Arc::clone(&self.garlic);

                    tokio::spawn(async move {
                        let _ = garlic.lock().await.recv(sender_clone, msg_clone).await;
                    });
                    return Ok(GarlemliaMessage::Garlic { msg: GarlicMessage::IsAlive { sender: self.node.clone() }, sender: self.node.clone() })
                }
                Err(Some(MessageError::Timeout))
            }

            GarlemliaMessage::Ping { .. } => {
                let mut is_alive = false;
                {
                    is_alive = SIM.lock().await.node_is_alive(self.node.address);
                }

                if is_alive {
                    Ok(GarlemliaMessage::Pong { sender: self.node.clone() })
                } else {
                    Err(Some(MessageError::Timeout))
                }
            }

            GarlemliaMessage::Pong { .. } => {
                Err(None)
            }

            GarlemliaMessage::Stop {} => {
                Err(None)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct SimulatedMessageHandler {
    pub messages: Arc<Mutex<HashMap<SocketAddr, VecDeque<Result<GarlemliaMessage, Option<MessageError>>>>>>,
}

#[async_trait]
impl GMessage for SimulatedMessageHandler {
    fn create(_channel_count: u8) -> Box<dyn GMessage> {
        Box::new(SimulatedMessageHandler {
            messages: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    async fn send_tx(&self, _addr: SocketAddr, _msg: MessageChannel) -> Result<(), MessageError> {
        Ok(())
    }

    async fn send_no_recv(&self, _socket: &UdpSocket, from_node: Node, target: &SocketAddr, msg: &GarlemliaMessage) -> Result<(), MessageError> {
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
    async fn send(&self, _socket: &UdpSocket, from_node: Node, target: &SocketAddr, msg: &GarlemliaMessage) -> Result<(), MessageError> {
        //println!("Send {:?} to {} from {}", msg, target, self_node.clone().address);
        //println!("Before SIM lock");
        let check_node;
        {
            check_node = SIM.lock().await.nodes.get_mut(target).cloned();
        }
        //println!("After SIM lock");

        match check_node {
            Some(node) => {
                //println!("Before messages lock");
                let mut self_messages = self.messages.lock().await;
                //println!("After messages lock");
                //println!("Before node lock");
                let mut node_locked = node.lock().await;
                //println!("After node lock");

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
                                        let mut locked_buckets = rt.buckets().await;
                                        let bucket = locked_buckets.get_mut(&index).unwrap();
                                        if let Some(lru_node) = bucket.nodes.front().cloned() {
                                            let mut is_alive = false;
                                            {
                                                is_alive = SIM.lock().await.node_is_alive(lru_node.address);
                                            }

                                            if is_alive {
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

    async fn recv(&self, _time: u64, src: &SocketAddr) -> Result<GarlemliaMessage, MessageError> {
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

    fn clone_box(&self) -> Box<dyn GMessage> {
        Box::new(self.clone())
    }
}

async fn file_node_to_simulated(file_node: FileNode) -> SimulatedNode {
    SimulatedNode::new(Node { id: file_node.id, address: file_node.address.parse().unwrap() }, file_node.routing_table.to_routing_table(), file_node.data_store, file_node.garlic.to_garlic())
}

async fn simulated_node_to_file(sim_node: SimulatedNode) -> FileNode {
    FileNode {
        id: sim_node.node.id,
        address: sim_node.node.address.to_string(),
        routing_table: SerializableRoutingTable::from(sim_node.routing_table.lock().await.clone()).await,
        data_store: sim_node.data_store,
        garlic: SerializableGarlicCast::from(sim_node.garlic.lock().await.clone()).await
    }
}

/// Loads SimulatedNodes from a JSON file
pub async fn load_simulated_nodes(file_path: &str) -> Result<Vec<SimulatedNode>, Box<dyn std::error::Error>> {
    let mut file = File::open(file_path).await?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).await?;
    let file_nodes: Vec<FileNode> = serde_json::from_str(&contents)?;
    let mut simulated_nodes = vec![];
    for mut node in file_nodes {
        node.garlic.known_nodes.extend(node.routing_table.clone().to_routing_table().flat_nodes().await);
        simulated_nodes.push(file_node_to_simulated(node).await);
    }
    Ok(simulated_nodes)
}

/// Saves SimulatedNodes to a JSON file
pub async fn save_simulated_nodes(file_path: &str, nodes: &Vec<SimulatedNode>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file_nodes = vec![];
    for node in nodes {
        {
            let garlic = node.garlic.lock().await;
            garlic.known_nodes.lock().await.clear();
        }
        file_nodes.push(simulated_node_to_file(node.clone()).await);
    }

    let json_string = serde_json::to_string_pretty(&file_nodes)?;
    let mut file = File::create(file_path).await?;
    file.write_all(json_string.as_bytes()).await?;
    Ok(())
}

pub async fn add_running(node: Node, routing_table: Arc<Mutex<RoutingTable>>) {
    {
        RUNNING_NODES.lock().await.insert(node.clone());
        RUNNING_ROUTING_TABLES.lock().await.insert(node, RoutingTableInfo::from(routing_table));
    }
}

pub async fn remove_running(node: Node) {
    {
        RUNNING_NODES.lock().await.remove(&node);
        RUNNING_ROUTING_TABLES.lock().await.remove(&node);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFileData {
    pub public_key: String,
    pub private_key: String,
}

async fn load_keys(file_path: &str) -> Result<Vec<KeyFileData>, Box<dyn std::error::Error>> {
    let mut file = File::open(file_path).await?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).await?;
    let file_keys: Vec<KeyFileData> = serde_json::from_str(&contents)?;
    Ok(file_keys)
}

async fn save_keys(file_path: &str, keys: &Vec<KeyFileData>) -> Result<(), Box<dyn std::error::Error>> {
    let json_string = serde_json::to_string_pretty(&keys)?;
    let mut file = File::create(file_path).await?;
    file.write_all(json_string.as_bytes()).await?;
    Ok(())
}

pub async fn generate_keys(file_path: &str, count: usize, max_threads: u8) {
    let mut keys = load_keys(file_path).await.unwrap();
    let curr_count = keys.len();

    let mut index = curr_count;
    for _ in curr_count..count {
        println!("RUNNING... {:.1}%: {}/{}", index as f64/count as f64 * 100.0, index, count);
        let mut tasks = Vec::new();
        for _ in 0..max_threads {

            let task = tokio::spawn(async move {
                let mut rng = OsRng;
                let bits = 2048;
                let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
                let public_key = RsaPublicKey::from(&private_key);

                KeyFileData {
                    public_key: public_key.to_public_key_pem(rsa::pkcs8::LineEnding::LF).unwrap(),
                    private_key: private_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap().to_string(),
                }
            });

            tasks.push(task);
        }

        for task in tasks {
            if let Ok(key) = task.await {
                keys.push(key);
                index += 1;
            }
        }

        save_keys(file_path, &keys).await.unwrap();
    }
}

pub async fn create_network(mut nodes: Vec<SimulatedNode>, mut keys: Vec<KeyFileData>) {
    let mut addresses = vec![];
    let nodes_len = nodes.len();
    for node in nodes.clone() {
        addresses.push(node.node.address.clone());
    }

    let key_pair_first = keys.remove(random_range(0..keys.len()));

    let pub_k_res_first = RsaPublicKey::from_public_key_pem(&*key_pair_first.public_key);
    let priv_k_res_first =  RsaPrivateKey::from_pkcs8_pem(&*key_pair_first.private_key);

    let pub_k_first;
    match pub_k_res_first {
        Ok(pub_k_yeet) => {
            pub_k_first = pub_k_yeet;
        }
        Err(e) => {
            println!("PUBLIC KEY ERROR: {:?}", e);
            return;
        }
    }

    let priv_k_first;
    match priv_k_res_first {
        Ok(priv_k_yeet) => {
            priv_k_first = priv_k_yeet;
        }
        Err(e) => {
            println!("PRIVATE KEY ERROR: {:?}", e);
            return;
        }
    }

    {
        let mut gc_first = nodes[0].garlic.lock().await;
        gc_first.set_public_key(pub_k_first).await;
        gc_first.set_private_key(priv_k_first).await;
    }

    {
        SIM.lock().await.create_node(SimulatedNode {
            node: nodes[0].node.clone(),
            routing_table: nodes[0].routing_table.clone(),
            data_store: nodes[0].data_store.clone(),
            garlic: nodes[0].garlic.clone()
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

        let key_ind = random_range(0..keys.len());

        let key_pair = keys.remove(key_ind);

        let pub_k_res = RsaPublicKey::from_public_key_pem(&*key_pair.public_key);
        let priv_k_res =  RsaPrivateKey::from_pkcs8_pem(&*key_pair.private_key);

        let pub_k;
        match pub_k_res {
            Ok(pub_k_yeet) => {
                pub_k = pub_k_yeet;
            }
            Err(e) => {
                println!("PUBLIC KEY ERROR: {:?}", e);
                continue;
            }
        }

        let priv_k;
        match priv_k_res {
            Ok(priv_k_yeet) => {
                priv_k = priv_k_yeet;
            }
            Err(e) => {
                println!("PRIVATE KEY ERROR: {:?}", e);
                continue;
            }
        }

        let mut run_node = Garlemlia::new_with_details(node.node.id, "127.0.0.1", node.node.address.port(), RoutingTable::new(node.node.clone()), SimulatedMessageHandler::create(0), get_global_socket().unwrap().clone(), pub_k, priv_k);

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
                data_store: run_node.data_store.lock().await.clone(),
                garlic: Arc::new(Mutex::new(run_node.garlic.lock().await.clone()))
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
            routing_table: Arc::new(Mutex::new(RoutingTable::new(node.clone()))),
            data_store: HashMap::new(),
            garlic: Arc::new(Mutex::new(GarlicCast::new(get_global_socket().unwrap(), node.clone(), Arc::new(SimulatedMessageHandler::create(0)), vec![], None, None)))
        });
    }

    simulated_nodes
}

pub async fn run_create_network(updated_file_path: &str, count: u16, keys_file: &str) {
    let nodes = create_random_simulated_nodes(count).await;

    let keys = load_keys(keys_file).await;

    match keys {
        Ok(keys) => {
            if keys.len() < nodes.len() {
                println!("Found {} nodes but only {} keys!", nodes.len(), keys.len());
                return;
            }
            create_network(nodes.clone(), keys).await;

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
        Err(_) => {
            println!("Could not load keys file!");
        }
    }
}