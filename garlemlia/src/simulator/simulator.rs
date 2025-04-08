use crate::file_utils::garlemlia_files::FileStorage;
use crate::garlemlia::garlemlia;
use crate::garlemlia::garlemlia::GarlemliaFunctions;
use crate::garlemlia_structs::garlemlia_structs;
use crate::garlemlia_structs::garlemlia_structs::{u256_random, ChunkPartAssociations, GarlemliaData, ProcessingCheck, SerializableRoutingTable};
use crate::garlic_cast::garlic_cast;
use crate::garlic_cast::garlic_cast::SerializableGarlicCast;
use async_trait::async_trait;
use garlemlia::Garlemlia;
use garlemlia_structs::{GMessage, GarlemliaMessage, GarlicMessage, MessageChannel, MessageError, Node, RoutingTable};
use garlic_cast::GarlicCast;
use lazy_static::lazy_static;
use once_cell::sync::OnceCell;
use primitive_types::U256;
use rand::random_range;
use rand_core::OsRng;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use tokio::fs;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

lazy_static! {
    pub static ref SIM: Arc<Mutex<Simulator>> = Arc::new(Mutex::new(Simulator::new_empty()));
    static ref RUNNING_NODES: Arc<Mutex<HashSet<Node>>> = Arc::new(Mutex::new(HashSet::new()));
    static ref RUNNING_GARLEMLIA: Arc<Mutex<HashMap<Node, Arc<GarlemliaInfo>>>> = Arc::new(Mutex::new(HashMap::new()));
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

pub struct GarlemliaInfo {
    pub node: Arc<Mutex<Node>>,
    pub message_handler: Arc<Box<dyn GMessage>>,
    pub routing_table: Arc<Mutex<RoutingTable>>,
    pub data_store: Arc<Mutex<HashMap<U256, GarlemliaData>>>,
    pub garlic: Arc<Mutex<GarlicCast>>,
    pub file_storage: Arc<Mutex<FileStorage>>,
    pub chunk_part_associations: Arc<Mutex<ChunkPartAssociations>>,
    is_processing: Arc<Mutex<ProcessingCheck>>
}

impl GarlemliaInfo {
    pub fn from(node: Arc<Mutex<Node>>,
                message_handler: Arc<Box<dyn GMessage>>,
                routing_table: Arc<Mutex<RoutingTable>>,
                data_store: Arc<Mutex<HashMap<U256, GarlemliaData>>>,
                garlic: Arc<Mutex<GarlicCast>>,
                file_storage: Arc<Mutex<FileStorage>>,
                chunk_part_associations: Arc<Mutex<ChunkPartAssociations>>) -> GarlemliaInfo {
        GarlemliaInfo {
            node,
            message_handler,
            routing_table,
            data_store,
            garlic,
            file_storage,
            chunk_part_associations,
            is_processing: Arc::new(Mutex::new(ProcessingCheck::new(false)))
        }
    }

    pub fn set(&mut self, garlemlia: Garlemlia) {
        self.node = Arc::clone(&garlemlia.node);
        self.message_handler = Arc::clone(&garlemlia.message_handler);
        self.routing_table = Arc::clone(&garlemlia.routing_table);
        self.data_store = Arc::clone(&garlemlia.data_store);
        self.garlic = Arc::clone(&garlemlia.garlic);
        self.file_storage = Arc::clone(&garlemlia.file_storage);
        self.chunk_part_associations = Arc::clone(&garlemlia.chunk_part_associations);
        self.is_processing = Arc::new(Mutex::new(ProcessingCheck::new(false)));
    }
}

#[derive(Debug, Clone)]
pub struct Simulator {
    pub nodes: HashMap<SocketAddr, SimulatedNode>,
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
            self.nodes.insert(node.node.address, node);
        }
    }

    pub fn clear_nodes(&mut self) {
        self.nodes.clear();
    }

    pub async fn create_node(&mut self, new_node: SimulatedNode) {
        self.nodes.insert(new_node.node.address.clone(), new_node);
    }

    pub async fn get_node(&self, address: SocketAddr) -> Option<SimulatedNode> {
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
                finished.push(node.clone());
            }
        }

        finished
    }

    // TODO: Modify FileNode and SimulatedNode to have is_alive: boolean key-value pairs
    // TODO: After done, need to create an event loop which randomly connects and disconnects
    // TODO: existing Node's and also creates random new nodes to join the network.
    pub async fn node_is_alive(&self, address: SocketAddr) -> bool {
        if let Some(node) = self.nodes.get(&address) {
            node.is_online
        } else {
            false
        }
    }

    pub async fn disconnect(&mut self, address: SocketAddr) -> Result<(), ()> {
        if let Some(node) = self.nodes.get_mut(&address) {
            node.set_is_online(false);
            return Ok(());
        }
        Err(())
    }

    pub async fn connect(&mut self, address: SocketAddr) -> Result<(), ()> {
        if let Some(node) = self.nodes.get_mut(&address) {
            node.set_is_online(true);
            return Ok(());
        }
        Err(())
    }

    pub fn add_fail(&mut self) {
        self.times_failed += 1;
    }

    pub fn get_fail(&self) -> u16 {
        self.times_failed
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileNode {
    pub id: U256,
    pub address: String,
    pub routing_table: SerializableRoutingTable,
    pub data_store: HashMap<U256, GarlemliaData>,
    pub file_storage: String,
    pub garlic: SerializableGarlicCast,
    pub chunk_part_associations: ChunkPartAssociations,
    pub is_online: bool
}

#[derive(Debug, Clone)]
pub struct SimulatedNode {
    pub node: Node,
    pub routing_table: Arc<Mutex<RoutingTable>>,
    pub data_store: Arc<Mutex<HashMap<U256, GarlemliaData>>>,
    pub file_storage: Arc<Mutex<FileStorage>>,
    pub garlic: Arc<Mutex<GarlicCast>>,
    pub chunk_part_associations: Arc<Mutex<ChunkPartAssociations>>,
    pub is_online: bool,
    is_processing: Arc<Mutex<ProcessingCheck>>
}

impl SimulatedNode {
    pub fn new(node: Node, rt: RoutingTable, ds: HashMap<U256, GarlemliaData>, gc: GarlicCast, fs: FileStorage, cpa: ChunkPartAssociations, is_online: bool) -> SimulatedNode {
        SimulatedNode {
            node,
            routing_table: Arc::new(Mutex::new(rt)),
            data_store: Arc::new(Mutex::new(ds)),
            file_storage: Arc::new(Mutex::new(fs)),
            garlic: Arc::new(Mutex::new(gc)),
            chunk_part_associations: Arc::new(Mutex::new(cpa)),
            is_online,
            is_processing: Arc::new(Mutex::new(ProcessingCheck::new(false)))
        }
    }

    async fn add_node(&mut self, node: Node) {
        add_to_routing_table(Arc::clone(&self.routing_table), node).await;
    }

    async fn parse_message(&mut self, sender_node: Node, msg: GarlemliaMessage) -> Result<GarlemliaMessage, Option<MessageError>> {
        if self.is_online {
            return parse_message_generic(Arc::clone(&self.routing_table), Arc::clone(&self.data_store), Arc::clone(&self.garlic), Arc::clone(&self.file_storage), Arc::clone(&self.chunk_part_associations), sender_node, self.node.clone(), msg, Arc::clone(&self.is_processing)).await;
        }
        Err(Some(MessageError::Timeout))
    }

    fn set_is_online(&mut self, is_online: bool) {
        self.is_online = is_online;
    }
}

async fn add_to_routing_table(routing_table: Arc<Mutex<RoutingTable>>, node: Node) {
    let mut rt = routing_table.lock().await;
    let index = rt.bucket_index(node.clone().id);
    if !rt.check_and_update_bucket(node.clone(), index).await {
        let mut locked_buckets = rt.buckets().await;
        let bucket = locked_buckets.get_mut(&index).unwrap();
        if let Some(lru_node) = bucket.nodes.front().cloned() {
            let is_alive;
            {
                is_alive = SIM.lock().await.node_is_alive(lru_node.address).await;
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

async fn parse_message_generic(routing_table: Arc<Mutex<RoutingTable>>,
                               data_store: Arc<Mutex<HashMap<U256, GarlemliaData>>>,
                               garlic_cast: Arc<Mutex<GarlicCast>>,
                               file_storage: Arc<Mutex<FileStorage>>,
                               chunk_part_associations: Arc<Mutex<ChunkPartAssociations>>,
                               sender_node: Node,
                               self_node: Node,
                               message: GarlemliaMessage,
                               simulated_processing: Arc<Mutex<ProcessingCheck>>) -> Result<GarlemliaMessage, Option<MessageError>> {
    let message_handler = Arc::new(simulated_to_gmessage(self_node.address));
    match message.clone() {
        GarlemliaMessage::Ping { .. } => {
            Ok(GarlemliaMessage::Pong { sender: self_node.clone() })
        }

        GarlemliaMessage::Pong { .. } => {
            Err(None)
        }

        GarlemliaMessage::AgreeAlt { .. } => {
            Err(None)
        }

        GarlemliaMessage::Stop {} => {
            Err(None)
        }

        GarlemliaMessage::Response { .. } => {
            println!("This should never happen");
            Err(None)
        }

        GarlemliaMessage::Garlic { msg, .. } => {
            add_to_routing_table(routing_table.clone(), sender_node.clone()).await;

            let msg_clone = message.clone();
            let self_node_clone = self_node.clone();

            tokio::spawn(async move {
                GarlemliaFunctions::run_message(self_node_clone,
                                                get_global_socket().unwrap(),
                                                message_handler,
                                                routing_table,
                                                data_store,
                                                garlic_cast,
                                                file_storage,
                                                chunk_part_associations,
                                                simulated_processing,
                                                msg_clone,
                                                sender_node).await;
            });

            match msg {
                GarlicMessage::RequestAlt { .. } => {
                    return Ok(GarlemliaMessage::AgreeAlt { alt_sequence_number: msg.sequence_number(), sender: self_node.clone() })
                }
                _ => {}
            }
            Ok(GarlemliaMessage::Pong { sender: self_node.clone() })
        }

        GarlemliaMessage::SearchFile { .. } |
        GarlemliaMessage::DownloadFileChunk { .. } => {
            add_to_routing_table(routing_table.clone(), sender_node.clone()).await;

            let msg_clone = message.clone();

            tokio::spawn(async move {
                GarlemliaFunctions::run_message(self_node,
                                                get_global_socket().unwrap(),
                                                message_handler,
                                                routing_table,
                                                data_store,
                                                garlic_cast,
                                                file_storage,
                                                chunk_part_associations,
                                                simulated_processing,
                                                msg_clone,
                                                sender_node).await;
            });

            Err(None)
        }

        _ => {
            add_to_routing_table(routing_table.clone(), sender_node.clone()).await;

            let response = GarlemliaFunctions::run_message(self_node,
                                                           get_global_socket().unwrap(),
                                                           Arc::clone(&message_handler),
                                                           routing_table,
                                                           data_store,
                                                           garlic_cast,
                                                           file_storage,
                                                           chunk_part_associations,
                                                           simulated_processing,
                                                           message,
                                                           sender_node).await;

            if response.is_some() {
                Ok(response.unwrap())
            } else {
                Err(None)
            }
        }
    }
}

async fn parse_message_running(garl: Arc<GarlemliaInfo>, sender_node: Node, msg: GarlemliaMessage) -> Result<GarlemliaMessage, Option<MessageError>> {
    let node = garl.node.lock().await.clone();
    let routing_table = Arc::clone(&garl.routing_table);
    let data_store = Arc::clone(&garl.data_store);
    let garlic = Arc::clone(&garl.garlic);
    let file_storage = Arc::clone(&garl.file_storage);
    let chunk_parts_association = Arc::clone(&garl.chunk_part_associations);
    let is_processing = Arc::clone(&garl.is_processing);

    parse_message_generic(routing_table, data_store, garlic, file_storage, chunk_parts_association, sender_node, node, msg, is_processing).await
}

pub fn simulated_to_gmessage(local_addr: SocketAddr) -> Box<dyn GMessage> {
    Box::new(SimulatedMessageHandler {
        messages: Arc::new(Mutex::new(HashMap::new())),
        local_addr,
    })
}

#[derive(Debug, Clone)]
pub struct SimulatedMessageHandler {
    pub messages: Arc<Mutex<HashMap<SocketAddr, VecDeque<Result<GarlemliaMessage, Option<MessageError>>>>>>,
    pub local_addr: SocketAddr,
}

#[async_trait]
impl GMessage for SimulatedMessageHandler {
    fn create(_channel_count: u8) -> Box<dyn GMessage> {
        Box::new(SimulatedMessageHandler {
            messages: Arc::new(Mutex::new(HashMap::new())),
            local_addr: SocketAddr::new(IpAddr::from(Ipv4Addr::UNSPECIFIED), 0),
        })
    }

    async fn send_tx(&self, _addr: SocketAddr, _msg: MessageChannel) -> Result<(), MessageError> {
        Ok(())
    }

    async fn send_no_recv(&self, socket: &UdpSocket, from_node: Node, target: &SocketAddr, msg: &GarlemliaMessage) -> Result<Option<GarlemliaMessage>, MessageError> {
        let check_node;
        {
            check_node = SIM.lock().await.nodes.get_mut(target).cloned();
        }

        match check_node {
            Some(mut node) => {
                let _ = node.parse_message(from_node, msg.clone()).await;
            }
            None => {
                let running_nodes;
                {
                    running_nodes = RUNNING_NODES.lock().await.clone();
                }

                let mut is_running = false;
                let mut target_running = None;
                for test_node in running_nodes {
                    if test_node.address == *target {
                        is_running = true;
                        target_running = Some(test_node.clone());
                        break;
                    }
                }

                if is_running {
                    let target_garm;
                    {
                        target_garm = Arc::clone(RUNNING_GARLEMLIA.lock().await.get(&target_running.unwrap()).unwrap());
                    }
                    if self.local_addr.to_string() == target.to_string() {
                        let _ = parse_message_running(target_garm, from_node.clone(), msg.clone()).await;
                    } else {
                        let stupid_mh;
                        {
                            stupid_mh = Arc::clone(&target_garm.message_handler);
                        }

                        let _ = stupid_mh.send_no_recv(socket, from_node, target, msg).await;
                    }
                }
            }
        }

        Ok(None)
    }

    // Send a message to another node
    async fn send(&self, socket: &UdpSocket, from_node: Node, target: &SocketAddr, msg: &GarlemliaMessage) -> Result<Option<GarlemliaMessage>, MessageError> {
        let check_node;
        {
            check_node = SIM.lock().await.nodes.get_mut(target).cloned();
        }

        match check_node {
            Some(mut node) => {
                let mut self_messages = self.messages.lock().await;

                if !self_messages.get(&target.clone()).is_some() {
                    self_messages.insert(target.clone(), VecDeque::new());
                }

                let response = node.parse_message(from_node.clone(), msg.clone()).await;

                let messages = self_messages.get_mut(&target.clone());
                if let Some(msg_handler) = messages {
                    msg_handler.push_back(response.clone());
                }

                match response {
                    Ok(km) => {
                        let is_running;
                        {
                            is_running = RUNNING_NODES.lock().await.contains(&from_node);
                        }
                        if is_running {
                            match km.sender() {
                                Some(sender) => {
                                    let mut gars = RUNNING_GARLEMLIA.lock().await;
                                    let running_gar = gars.get_mut(&from_node).unwrap();
                                    let rt = Arc::clone(&running_gar.routing_table);
                                    add_to_routing_table(rt, sender).await;
                                }
                                None => {}
                            }
                        } else {
                            match km.sender() {
                                Some(sender) => {
                                    node.add_node(sender.clone()).await;
                                }
                                None => {}
                            }
                        }
                        Ok(Some(km))
                    },
                    Err(em) => {
                        match em {
                            None => {
                                Ok(None)
                            }
                            Some(e) => {
                                Err(e)
                            }
                        }
                    }
                }
            }
            None => {
                let running_nodes;
                {
                    running_nodes = RUNNING_NODES.lock().await.clone();
                }

                let mut is_running = false;
                let mut target_running = None;
                for test_node in running_nodes {
                    if test_node.address == *target {
                        is_running = true;
                        target_running = Some(test_node.clone());
                        break;
                    }
                }

                if is_running {
                    let target_garm;
                    {
                        target_garm = Arc::clone(RUNNING_GARLEMLIA.lock().await.get(&target_running.unwrap()).unwrap());
                    }
                    if self.local_addr.to_string() == target.to_string() {
                        let response = parse_message_running(target_garm, from_node.clone(), msg.clone()).await;
                        let mut self_messages = self.messages.lock().await;

                        if !self_messages.get(&target.clone()).is_some() {
                            self_messages.insert(target.clone(), VecDeque::new());
                        }

                        let messages = self_messages.get_mut(&target.clone());
                        if let Some(msg_handler) = messages {
                            msg_handler.push_back(response.clone());
                        }

                        match response {
                            Ok(gm) => {
                                Ok(Some(gm))
                            }
                            Err(em) => {
                                match em {
                                    None => {
                                        Ok(None)
                                    }
                                    Some(e) => {
                                        Err(e)
                                    }
                                }
                            }
                        }
                    } else {
                        let stupid_mh;
                        {
                            stupid_mh = Arc::clone(&target_garm.message_handler);
                        }

                        let info = stupid_mh.send(socket, from_node, target, msg).await;

                        match info {
                            Ok(msg) => {
                                match msg {
                                    Some(gm) => {
                                        let mut self_messages = self.messages.lock().await;

                                        if !self_messages.get(&target.clone()).is_some() {
                                            self_messages.insert(target.clone(), VecDeque::new());
                                        }

                                        let messages = self_messages.get_mut(&target.clone());
                                        if let Some(msg_handler) = messages {
                                            msg_handler.push_back(Ok(gm.clone()));
                                        }
                                        Ok(Some(gm))
                                    }
                                    None => {
                                        Ok(None)
                                    }
                                }
                            }
                            Err(e) => {
                                let mut self_messages = self.messages.lock().await;

                                if !self_messages.get(&target.clone()).is_some() {
                                    self_messages.insert(target.clone(), VecDeque::new());
                                }

                                let messages = self_messages.get_mut(&target.clone());
                                if let Some(msg_handler) = messages {
                                    msg_handler.push_back(Err(Some(e.clone())));
                                }
                                Err(e)
                            }
                        }
                    }
                } else {
                    Err(MessageError::MissingNode)
                }
            }
        }
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
                                println!("{}: No response should have been expected from {}", self.local_addr, src);
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

async fn file_node_to_simulated(file_node: FileNode, file_storage_from: Option<FileStorage>) -> Option<SimulatedNode> {
    let file_storage;
    if file_storage_from.is_some() {
        file_storage = Ok(file_storage_from.unwrap());
    } else {
        file_storage = FileStorage::load(file_node.file_storage).await;
    }

    match file_storage {
        Ok(file_storage) => {
            Some(SimulatedNode::new(Node { id: file_node.id, address: file_node.address.parse().unwrap() }, file_node.routing_table.to_routing_table(), file_node.data_store, file_node.garlic.to_garlic(), file_storage, file_node.chunk_part_associations, file_node.is_online))
        }
        Err(em) => {
            println!("Error loading file storage: {:?}", em);
            None
        }
    }
}

async fn simulated_node_to_file(sim_node: SimulatedNode) -> FileNode {
    FileNode {
        id: sim_node.node.id,
        address: sim_node.node.address.to_string(),
        routing_table: SerializableRoutingTable::from(sim_node.routing_table.lock().await.clone()).await,
        data_store: sim_node.data_store.lock().await.clone(),
        file_storage: sim_node.file_storage.lock().await.file_storage_settings_path.clone(),
        garlic: SerializableGarlicCast::from(sim_node.garlic.lock().await.clone()),
        chunk_part_associations: sim_node.chunk_part_associations.lock().await.clone(),
        is_online: sim_node.is_online
    }
}

/// Loads SimulatedNodes from a JSON file
pub async fn load_simulated_nodes(file_path: &str) -> Result<Vec<SimulatedNode>, Box<dyn std::error::Error>> {
    let mut file = File::open(file_path).await?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).await?;
    let file_nodes: Vec<FileNode> = serde_json::from_str(&contents)?;

    let dir_path = Path::new("./simulated_nodes_files");

    let mut should_create = true;
    if dir_path.exists() && dir_path.is_dir() {
        should_create = false;
    } else {

    }

    let mut simulated_nodes = vec![];
    for mut node in file_nodes {
        let mut file_storage = None;
        if should_create {
            let mut dir_id = dir_path.join(node.id.to_string());
            dir_id.push("downloads");
            fs::create_dir_all(dir_id.clone()).await.unwrap();
            dir_id.pop();
            dir_id.push("chunks");
            fs::create_dir_all(dir_id.clone()).await.unwrap();
            dir_id.pop();
            dir_id.push("temp_chunks");
            fs::create_dir_all(dir_id.clone()).await.unwrap();

            let root_dir = format!("./simulated_nodes_files/{}", node.id);
            file_storage = Some(FileStorage::new(format!("{}/file_storage.json", root_dir), format!("{}/downloads", root_dir), format!("{}/chunks", root_dir), format!("{}/temp_chunks", root_dir)));
        }

        node.garlic.known_nodes.extend(node.routing_table.clone().to_routing_table().flat_nodes().await.clone());
        let sim_node = file_node_to_simulated(node, file_storage).await;
        if sim_node.is_some() {
            simulated_nodes.push(sim_node.unwrap());
        }
    }
    Ok(simulated_nodes)
}

/// Saves SimulatedNodes to a JSON file
pub async fn save_simulated_nodes(file_path: &str, nodes: &Vec<SimulatedNode>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file_nodes = vec![];
    for node in nodes {
        {
            node.file_storage.lock().await.save().await?;
            node.garlic.lock().await.set_known(vec![]);
        }
        file_nodes.push(simulated_node_to_file(node.clone()).await);
    }

    let json_string = serde_json::to_string_pretty(&file_nodes)?;
    let mut file = File::create(file_path).await?;
    file.write_all(json_string.as_bytes()).await?;
    Ok(())
}

pub async fn add_running(node: Node, garlemlia: GarlemliaInfo) {
    {
        RUNNING_NODES.lock().await.insert(node.clone());
        RUNNING_GARLEMLIA.lock().await.insert(node.clone(), Arc::new(garlemlia));
    }
}

pub async fn remove_running(node: Node) {
    {
        RUNNING_NODES.lock().await.remove(&node);
        RUNNING_GARLEMLIA.lock().await.remove(&node);
    }
}

pub async fn clear_running() {
    {
        RUNNING_NODES.lock().await.clear();
        RUNNING_GARLEMLIA.lock().await.clear();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFileData {
    pub public_key: String,
    pub private_key: String,
}

impl KeyFileData {
    async fn load(file_path: &str) -> Result<Vec<KeyFileData>, Box<dyn std::error::Error>> {
        let mut file = File::open(file_path).await?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).await?;
        let file_keys: Vec<KeyFileData> = serde_json::from_str(&contents)?;
        Ok(file_keys)
    }

    async fn save(file_path: &str, keys: &Vec<KeyFileData>) -> Result<(), Box<dyn std::error::Error>> {
        let json_string = serde_json::to_string_pretty(&keys)?;
        let mut file = File::create(file_path).await?;
        file.write_all(json_string.as_bytes()).await?;
        Ok(())
    }
}

pub async fn generate_keys(file_path: &str, count: usize, max_threads: u8) {
    let mut keys = KeyFileData::load(file_path).await.unwrap();
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

        KeyFileData::save(file_path, &keys).await.unwrap();
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
        gc_first.set_public_key(pub_k_first);
        gc_first.set_private_key(priv_k_first);
    }

    {
        SIM.lock().await.create_node(SimulatedNode {
            node: nodes[0].node.clone(),
            routing_table: nodes[0].routing_table.clone(),
            data_store: nodes[0].data_store.clone(),
            file_storage: nodes[0].file_storage.clone(),
            garlic: nodes[0].garlic.clone(),
            chunk_part_associations: nodes[0].chunk_part_associations.clone(),
            is_online: true,
            is_processing: Arc::new(Mutex::new(ProcessingCheck::new(false)))
        }).await;
    }

    let mut usable_addresses = vec![nodes.get(0).unwrap().node.address];
    nodes.remove(0);
    let mut index = 0;
    let mut range = 1;
    let mut percent_threshold = 0.0;
    for node in nodes {
        if percent_threshold <= index as f64/nodes_len as f64 {
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

        let mut run_node = Garlemlia::new_with_details(node.node.id, "127.0.0.1", node.node.address.port(), RoutingTable::new(node.node.clone()), simulated_to_gmessage(node.node.address), get_global_socket().unwrap().clone(), pub_k, priv_k, Box::new(Path::new("./simulated_nodes_files"))).await;

        add_running(node.node.clone(), GarlemliaInfo::from(Arc::clone(&run_node.node), Arc::clone(&run_node.message_handler), Arc::clone(&run_node.routing_table), Arc::clone(&run_node.data_store), Arc::clone(&run_node.garlic), Arc::clone(&run_node.file_storage), Arc::clone(&run_node.chunk_part_associations))).await;

        let ind;
        if index ^ (range * 2) == 0 {
            range = range * 2;
        }

        ind = random_range(0..range);

        //run_node.join_network(get_global_socket().unwrap().clone(), &usable_addresses.choose(&mut rand::rng()).unwrap().clone()).await;
        run_node.join_network(get_global_socket().unwrap().clone(), &addresses[ind]).await;

        {
            let node_actual = run_node.node.lock().await.clone();
            let mut rt = RoutingTable::new(node_actual.clone());
            rt.update_from(run_node.routing_table.lock().await.clone()).await;
            let ds = run_node.data_store.lock().await.clone();
            let gar = run_node.garlic.lock().await.clone();
            let fs = run_node.file_storage.lock().await.clone();
            let cpa = run_node.chunk_part_associations.lock().await.clone();
            SIM.lock().await.create_node(SimulatedNode {
                node: node_actual.clone(),
                routing_table: Arc::new(Mutex::new(rt.clone())),
                data_store: Arc::new(Mutex::new(ds)),
                file_storage: Arc::new(Mutex::new(fs)),
                garlic: Arc::new(Mutex::new(gar)),
                chunk_part_associations: Arc::new(Mutex::new(cpa.clone())),
                is_online: true,
                is_processing: Arc::new(Mutex::new(ProcessingCheck::new(false)))
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

    let dir_path = Path::new("./simulated_nodes_files");

    if dir_path.exists() && dir_path.is_dir() {
        fs::remove_dir_all(dir_path).await.unwrap();
        println!("Old Simulated Nodes Folder Removed!");
    }

    fs::create_dir(dir_path).await.unwrap();

    for i in 0..count {
        let mut id = u256_random();
        while used_ids.contains(&id) {
            println!("TRIED TO USE COPY OF ID {}", id);
            id = u256_random();
        }

        let mut dir_id = dir_path.join(id.to_string());
        dir_id.push("downloads");
        fs::create_dir_all(dir_id.clone()).await.unwrap();
        dir_id.pop();
        dir_id.push("chunks");
        fs::create_dir_all(dir_id.clone()).await.unwrap();
        dir_id.pop();
        dir_id.push("temp_chunks");
        fs::create_dir_all(dir_id.clone()).await.unwrap();

        let root_dir = format!("./simulated_nodes_files/{}", id);
        let file_storage = FileStorage::new(format!("{}/file_storage.json", root_dir), format!("{}/downloads", root_dir), format!("{}/chunks", root_dir), format!("{}/temp_chunks", root_dir));

        used_ids.insert(id);
        let node = Node { id, address: SocketAddr::new("127.0.0.1".parse().unwrap(), 9000 + i)};
        simulated_nodes.push(SimulatedNode {
            node: node.clone(),
            routing_table: Arc::new(Mutex::new(RoutingTable::new(node.clone()))),
            data_store: Arc::new(Mutex::new(HashMap::new())),
            file_storage: Arc::new(Mutex::new(file_storage)),
            garlic: Arc::new(Mutex::new(GarlicCast::new(get_global_socket().unwrap(), node.clone(), Arc::new(simulated_to_gmessage(node.address)), vec![], None, None))),
            chunk_part_associations: Arc::new(Mutex::new(ChunkPartAssociations::new())),
            is_online: true,
            is_processing: Arc::new(Mutex::new(ProcessingCheck::new(false)))
        });
    }

    simulated_nodes
}

pub async fn run_create_network(updated_file_path: &str, count: u16, keys_file: &str) {
    let nodes = create_random_simulated_nodes(count).await;

    let keys = KeyFileData::load(keys_file).await;

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