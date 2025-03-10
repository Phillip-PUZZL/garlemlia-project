use async_trait::async_trait;
use garlemlia::Garlemlia;
use garlemlia_structs::{Clove, CloveData, CloveNode, GMessage, GarlemliaMessage, GarlicMessage, KBucket, MessageChannel, MessageError, Node, RoutingTable, DEFAULT_K};
use garlic_cast::{CloveCache, GarlicCast, Proxy};
use lazy_static::lazy_static;
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use chrono::{DateTime, Utc};

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableCloveCache {
    cloves: HashMap<u128, CloveData>,
    next_hop_key: HashMap<u32, CloveNode>,
    next_hop_val: HashMap<u32, Option<CloveNode>>,
    alt_nodes_key: HashMap<u32, CloveNode>,
    alt_nodes_val: HashMap<u32, CloveNode>,
    associations: HashMap<u128, Vec<CloveNode>>,
    seen_last: HashMap<u128, DateTime<Utc>>,
    my_alt_nodes: HashMap<u128, CloveNode>
}

impl SerializableCloveCache {
    pub fn from(cache: CloveCache) -> SerializableCloveCache {
        let mut next_hop_key = HashMap::new();
        let mut next_hop_val = HashMap::new();
        let mut alt_nodes_key = HashMap::new();
        let mut alt_nodes_val = HashMap::new();

        let mut index = 0;
        for info in cache.next_hop.iter() {
            next_hop_key.insert(index, info.0.clone());
            next_hop_val.insert(index, info.1.clone());

            index += 1;
        }

        index = 0;
        for info in cache.alt_nodes.iter() {
            alt_nodes_key.insert(index, info.0.clone());
            alt_nodes_val.insert(index, info.1.clone());

            index += 1;
        }

        SerializableCloveCache {
            cloves: cache.cloves,
            next_hop_key,
            next_hop_val,
            alt_nodes_key,
            alt_nodes_val,
            associations: cache.associations,
            seen_last: cache.seen_last,
            my_alt_nodes: cache.my_alt_nodes,
        }
    }

    pub fn to_clove_cache(self) -> CloveCache {
        let mut next_hop = HashMap::new();
        let mut alt_nodes = HashMap::new();

        for entry in self.next_hop_key.iter() {
            let val = self.next_hop_val.get(entry.0).unwrap().clone();
            next_hop.insert(entry.1.clone(), val);
        }

        for entry in self.alt_nodes_key.iter() {
            let val = self.alt_nodes_val.get(entry.0).unwrap().clone();
            alt_nodes.insert(entry.1.clone(), val);
        }

        CloveCache {
            cloves: self.cloves,
            next_hop,
            alt_nodes,
            associations: self.associations,
            seen_last: self.seen_last,
            my_alt_nodes: self.my_alt_nodes,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableGarlicCast {
    local_node: Node,
    known_nodes: Vec<Node>,
    proxies: Vec<Proxy>,
    cache: SerializableCloveCache,
    collected_messages: Vec<Clove>,
}

impl SerializableGarlicCast {
    pub async fn from(garlic: GarlicCast) -> SerializableGarlicCast {
        SerializableGarlicCast {
            local_node: garlic.local_node.clone(),
            known_nodes: garlic.known_nodes.lock().await.clone(),
            proxies: garlic.proxies.lock().await.clone(),
            cache: SerializableCloveCache::from(garlic.cache.lock().await.clone()),
            collected_messages: garlic.collected_messages.lock().await.clone(),
        }
    }

    pub fn to_garlic(self) -> GarlicCast {
        GarlicCast {
            socket: get_global_socket().unwrap(),
            local_node: self.local_node,
            message_handler: Arc::new(SimulatedMessageHandler::create(0)),
            known_nodes: Arc::new(Mutex::new(self.known_nodes)),
            proxies: Arc::new(Mutex::new(self.proxies)),
            cache: Arc::new(Mutex::new(self.cache.to_clove_cache())),
            collected_messages: Arc::new(Mutex::new(self.collected_messages))
        }
    }
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
            let mut locked_buckets = rt.buckets.lock().await;
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
                    let sender_clone = sender.clone();
                    let msg_clone = msg.clone();
                    let garlic = Arc::clone(&self.garlic);

                    tokio::spawn(async move {
                        garlic.lock().await.recv(sender_clone, msg_clone).await;
                    });
                    return Ok(GarlemliaMessage::Garlic { msg: GarlicMessage::IsAlive { sender: sender.clone() }, sender })
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
                                        let mut locked_buckets = rt.buckets.lock().await;
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

        let mut run_node = Garlemlia::new_with_sock(node.node.id, "127.0.0.1", node.node.address.port(), RoutingTable::new(node.node.clone()), SimulatedMessageHandler::create(0), get_global_socket().unwrap().clone());

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
            routing_table: Arc::new(Mutex::new(RoutingTable {local_node: node.clone(), buckets: Arc::new(Mutex::new(HashMap::new()))})),
            data_store: HashMap::new(),
            garlic: Arc::new(Mutex::new(GarlicCast::new(get_global_socket().unwrap(), node.clone(), Arc::new(SimulatedMessageHandler::create(0)), vec![])))
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