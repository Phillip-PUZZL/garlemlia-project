use crate::garlemlia::garlemlia;
use crate::garlemlia_structs::garlemlia_structs;
use crate::garlemlia_structs::garlemlia_structs::{u256_random, CloveMessage, GarlemliaData, GarlemliaFindRequest, GarlemliaStoreRequest, SerializableRoutingTable};
use crate::garlic_cast::garlic_cast;
use crate::garlic_cast::garlic_cast::SerializableGarlicCast;
use async_trait::async_trait;
use garlemlia::Garlemlia;
use garlemlia_structs::{GMessage, GarlemliaMessage, GarlicMessage, MessageChannel, MessageError, Node, RoutingTable, DEFAULT_K};
use garlic_cast::GarlicCast;
use lazy_static::lazy_static;
use once_cell::sync::OnceCell;
use rand::random_range;
use rand_core::OsRng;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use primitive_types::U256;
use tokio::fs;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use crate::file_utils::garlemlia_files::FileStorage;
use crate::garlemlia::garlemlia::GarlemliaFunctions;

lazy_static! {
    pub static ref SIM: Arc<Mutex<Simulator>> = Arc::new(Mutex::new(Simulator::new_empty()));
    static ref RUNNING_NODES: Arc<Mutex<HashSet<Node>>> = Arc::new(Mutex::new(HashSet::new()));
    static ref RUNNING_GARLEMLIA: Arc<Mutex<HashMap<Node, Arc<Mutex<GarlemliaInfo>>>>> = Arc::new(Mutex::new(HashMap::new()));
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
    is_processing: Arc<Mutex<ProcessingCheck>>
}

impl GarlemliaInfo {
    pub fn from(node: Arc<Mutex<Node>>,
                message_handler: Arc<Box<dyn GMessage>>,
                routing_table: Arc<Mutex<RoutingTable>>,
                data_store: Arc<Mutex<HashMap<U256, GarlemliaData>>>,
                garlic: Arc<Mutex<GarlicCast>>,
                file_storage: Arc<Mutex<FileStorage>>) -> GarlemliaInfo {
        GarlemliaInfo {
            node,
            message_handler,
            routing_table,
            data_store,
            garlic,
            file_storage,
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
        self.is_processing = Arc::new(Mutex::new(ProcessingCheck::new(false)));
    }
}

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
    pub async fn node_is_alive(&self, address: SocketAddr) -> bool {
        if let Some(node) = self.nodes.get(&address) {
            node.lock().await.is_online
        } else {
            false
        }
    }

    pub async fn disconnect(&mut self, address: SocketAddr) -> Result<(), ()> {
        if let Some(node) = self.nodes.get_mut(&address) {
            node.lock().await.set_is_online(false);
            return Ok(());
        }
        Err(())
    }

    pub async fn connect(&mut self, address: SocketAddr) -> Result<(), ()> {
        if let Some(node) = self.nodes.get_mut(&address) {
            node.lock().await.set_is_online(true);
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
    pub is_online: bool
}

#[derive(Debug, Clone)]
pub struct ProcessingCheck {
    is_processing: bool
}

impl ProcessingCheck {
    pub fn new(is_processing: bool) -> ProcessingCheck {
        ProcessingCheck {
            is_processing
        }
    }

    pub fn check(&self) -> bool {
        self.is_processing
    }

    pub fn set(&mut self, state: bool) {
        self.is_processing = state;
    }
}

#[derive(Debug, Clone)]
pub struct SimulatedNode {
    pub node: Node,
    pub routing_table: Arc<Mutex<RoutingTable>>,
    pub data_store: Arc<Mutex<HashMap<U256, GarlemliaData>>>,
    pub file_storage: Arc<Mutex<FileStorage>>,
    pub garlic: Arc<Mutex<GarlicCast>>,
    pub is_online: bool,
    is_processing: Arc<Mutex<ProcessingCheck>>
}

impl SimulatedNode {
    pub fn new(node: Node, rt: RoutingTable, ds: HashMap<U256, GarlemliaData>, gc: GarlicCast, fs: FileStorage, is_online: bool) -> SimulatedNode {
        SimulatedNode {
            node,
            routing_table: Arc::new(Mutex::new(rt)),
            data_store: Arc::new(Mutex::new(ds)),
            file_storage: Arc::new(Mutex::new(fs)),
            garlic: Arc::new(Mutex::new(gc)),
            is_online,
            is_processing: Arc::new(Mutex::new(ProcessingCheck::new(false)))
        }
    }

    async fn add_node(&mut self, node: Node) {
        add_to_routing_table(Arc::clone(&self.routing_table), node).await;
    }

    async fn parse_message(&mut self, sender_node: Node, msg: GarlemliaMessage) -> Result<GarlemliaMessage, Option<MessageError>> {
        if self.is_online {
            return parse_message_generic(self.routing_table.clone(), self.data_store.clone(), self.garlic.clone(), self.file_storage.clone(), sender_node, self.node.clone(), msg, self.is_processing.clone()).await;
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
                               sender_node: Node,
                               self_node: Node,
                               msg: GarlemliaMessage,
                               simulated_processing: Arc<Mutex<ProcessingCheck>>) -> Result<GarlemliaMessage, Option<MessageError>> {
    let message_handler = Arc::new(simulated_to_gmessage(self_node.address));
    match msg {
        GarlemliaMessage::FindNode { id, .. } => {
            // Add the sender to the routing table
            add_to_routing_table(routing_table.clone(), sender_node).await;
            let response = if id == self_node.id {
                // If the search target is this node itself, return only this node
                GarlemliaMessage::Response {
                    nodes: vec![self_node.clone()],
                    value: None,
                    sender: self_node.clone(),
                }
            } else {
                // Return the closest known nodes
                let closest_nodes;
                {
                    closest_nodes = routing_table.lock().await.find_closest_nodes(id, DEFAULT_K).await;
                }

                GarlemliaMessage::Response {
                    nodes: closest_nodes,
                    value: None,
                    sender: self_node.clone(),
                }
            };

            Ok(response)
        }

        // Store a key-value pair
        GarlemliaMessage::Store { key, value, .. } => {
            add_to_routing_table(routing_table.clone(), sender_node.clone()).await;

            let mut store_val;
            if value.is_validator() {
                let current;
                {
                    current = data_store.lock().await.get(&key).cloned();
                }

                if current.is_some() {
                    let stored_data = current.unwrap();
                    match stored_data {
                        GarlemliaData::Validator { id, proxy_ids, proxies } => {
                            let this_proxy_id = value.validator_get_proxy_id().unwrap();
                            let mut new_ids = proxy_ids;
                            new_ids.push(this_proxy_id);
                            let mut new_proxies = proxies;
                            new_proxies.insert(this_proxy_id, sender_node.clone().address);
                            store_val = Some(GarlemliaData::Validator {
                                id,
                                proxy_ids: new_ids,
                                proxies: new_proxies
                            });
                        }
                        _ => {
                            store_val = None;
                        }
                    }
                } else {
                    let this_proxy_id = value.validator_get_proxy_id().unwrap();
                    let mut set_proxies = HashMap::new();
                    set_proxies.insert(this_proxy_id, sender_node.clone().address);

                    store_val = Some(GarlemliaData::Validator {
                        id: key,
                        proxy_ids: vec![this_proxy_id],
                        proxies: set_proxies
                    });
                }
            } else {
                store_val = value.to_store_data();
            }

            if store_val.is_some() {
                let mut check = store_val.unwrap();
                check.store();

                store_val = Some(check);
            }

            if value.is_chunk() {
                let _ = file_storage.lock().await.store_chunk(key, value.chunk_get_data().unwrap()).await;
                println!("STORING FILE CHUNK ON {}", self_node.id);
            } else {
                println!("STORING FILE INFO ON {}", self_node.id)
            }

            if store_val.is_some() {
                data_store.lock().await.insert(key, store_val.clone().unwrap());
            }

            Err(None)
        }

        // Use find_closest_nodes() if value is not found
        GarlemliaMessage::FindValue { request, .. } => {
            let key = request.get_id();

            add_to_routing_table(routing_table.clone(), sender_node).await;
            let value;
            {
                value = data_store.lock().await.get(&key).cloned();
            }

            let response = if let Some(val) = value {
                let mut val_response = val.get_response(Some(request));
                if val.is_chunk() {
                    let chunk_data;
                    {
                        chunk_data = file_storage.lock().await.get_chunk(val.get_id()).await;
                    }

                    if chunk_data.is_ok() {
                        val_response = val.get_chunk_response(chunk_data.unwrap());
                    }
                }

                GarlemliaMessage::Response {
                    nodes: vec![],
                    value: val_response,
                    sender: self_node.clone(),
                }
            } else {
                let closest_nodes;
                {
                    closest_nodes = routing_table.lock().await.find_closest_nodes(key, DEFAULT_K).await;
                }

                GarlemliaMessage::Response {
                    nodes: closest_nodes,
                    value: None,
                    sender: self_node.clone(),
                }
            };

            Ok(response)
        }

        GarlemliaMessage::Response { nodes, value, sender, .. } => {
            println!("This should never happen");
            add_to_routing_table(routing_table.clone(), sender_node).await;
            let _constructed = GarlemliaMessage::Response {
                nodes,
                value,
                sender,
            };

            Err(None)
        }

        GarlemliaMessage::Garlic { msg, .. } => {
            add_to_routing_table(routing_table.clone(), sender_node.clone()).await;
            let sender_clone = sender_node.clone();
            let msg_clone = msg.clone();
            let self_node_clone = self_node.clone();
            let routing_table_clone = Arc::clone(&routing_table);
            let message_handler_clone = Arc::clone(&message_handler);
            let data_store_clone = Arc::clone(&data_store);
            let garlic_clone = Arc::clone(&garlic_cast);
            let file_storage_clone = Arc::clone(&file_storage);
            let check_processing = Arc::clone(&simulated_processing);

            tokio::spawn(async move {
                let action_res;
                {
                    {
                        loop {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            let mut check = check_processing.lock().await;
                            if !check.check() {
                                check.set(true);
                                break;
                            }
                        }
                    }

                    action_res = garlic_clone.lock().await.recv(sender_clone, msg_clone).await;

                    {
                        check_processing.lock().await.set(false);
                    }
                }

                if action_res.is_ok() {
                    let action_opt = action_res.unwrap();
                    if action_opt.is_some() {
                        let action = action_opt.unwrap();

                        let mut response_data = None;
                        match action.clone() {
                            CloveMessage::SearchOverlay { request_id, proxy_id, search_term, .. } => {
                                GarlemliaFunctions::store_value(get_global_socket().unwrap(), self_node_clone,
                                                                routing_table_clone,
                                                                message_handler_clone,
                                                                data_store_clone,
                                                                Arc::clone(&garlic_clone),
                                                                file_storage_clone,
                                                                GarlemliaStoreRequest::Validator { id: request_id.request_id, proxy_id },
                                                                3).await;

                                response_data = GarlemliaFunctions::search_file(Arc::clone(&data_store), search_term).await;
                            }
                            CloveMessage::SearchGarlemlia { key, .. } => {
                                response_data = GarlemliaFunctions::iterative_find_value(get_global_socket().unwrap(), self_node_clone,
                                                                                             routing_table_clone,
                                                                                             message_handler_clone,
                                                                                             data_store_clone,
                                                                                             GarlemliaFindRequest::Key { id: key }).await;
                            }
                            CloveMessage::ResponseWithValidator { request_id, proxy_id, .. } => {
                                response_data = GarlemliaFunctions::iterative_find_value(get_global_socket().unwrap(), self_node_clone,
                                                                                             routing_table_clone,
                                                                                             message_handler_clone,
                                                                                             data_store_clone,
                                                                                             GarlemliaFindRequest::Validator { id: request_id.request_id, proxy_id }).await;
                            }
                            CloveMessage::Store { data, .. } => {
                                GarlemliaFunctions::store_value(get_global_socket().unwrap(), self_node_clone,
                                                                routing_table_clone,
                                                                message_handler_clone,
                                                                data_store_clone,
                                                                Arc::clone(&garlic_clone),
                                                                file_storage_clone,
                                                                data.clone(),
                                                                2).await;

                                match data {
                                    GarlemliaStoreRequest::FileName { .. } | GarlemliaStoreRequest::MetaData { .. } | GarlemliaStoreRequest::FileKey { .. } => {
                                        {
                                            let garlic_lock = garlic_clone.lock().await;
                                            let proxies_count;
                                            {
                                                proxies_count = garlic_lock.proxies.lock().await.len();
                                            }
                                            if proxies_count == 0 {
                                                {
                                                    loop {
                                                        tokio::time::sleep(Duration::from_millis(10)).await;
                                                        let mut check = check_processing.lock().await;
                                                        if !check.check() {
                                                            check.set(true);
                                                            break;
                                                        }
                                                    }
                                                }

                                                garlic_lock.discover_proxies(20).await;

                                                {
                                                    check_processing.lock().await.set(false);
                                                }
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            _ => {}
                        }

                        {
                            {
                                loop {
                                    tokio::time::sleep(Duration::from_millis(10)).await;
                                    let mut check = check_processing.lock().await;
                                    if !check.check() {
                                        check.set(true);
                                        break;
                                    }
                                }
                            }

                            garlic_clone.lock().await.run_proxy_message(action, response_data).await;

                            {
                                check_processing.lock().await.set(false);
                            }
                        }
                    }
                }
            });

            match msg {
                GarlicMessage::RequestAlt { .. } => {
                    return Ok(GarlemliaMessage::AgreeAlt { alt_sequence_number: msg.sequence_number(), sender: self_node.clone() })
                }
                _ => {}
            }
            Ok(GarlemliaMessage::Pong { sender: self_node.clone() })
        }

        GarlemliaMessage::Ping { .. } => {
            Ok(GarlemliaMessage::Pong { sender: self_node.clone() })
        }

        GarlemliaMessage::Pong { .. } => {
            Err(None)
        }

        GarlemliaMessage::SearchFile { request_id, proxy_id, search_term, public_key, .. } => {
            add_to_routing_table(routing_table.clone(), sender_node.clone()).await;

            let response_data = GarlemliaFunctions::search_file(Arc::clone(&data_store), search_term.clone()).await;
            
            if response_data.is_some() {
                println!("FILE FOUND HERE DUMMY");
            }
            
            let new_clove_msg = CloveMessage::SearchOverlay { request_id, proxy_id, search_term, public_key };

            let garlic_clone = Arc::clone(&garlic_cast);
            let check_processing = Arc::clone(&simulated_processing);

            tokio::spawn(async move {
                {
                    {
                        loop {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            let mut check = check_processing.lock().await;
                            if !check.check() {
                                check.set(true);
                                break;
                            }
                        }
                    }

                    garlic_clone.lock().await.run_proxy_message(new_clove_msg, response_data).await;

                    {
                        check_processing.lock().await.set(false);
                    }
                }
            });


            Err(None)
        }

        GarlemliaMessage::AgreeAlt { .. } => {
            Err(None)
        }

        GarlemliaMessage::Stop {} => {
            Err(None)
        }
    }
}

async fn parse_message_running(garl: Arc<Mutex<GarlemliaInfo>>, sender_node: Node, msg: GarlemliaMessage) -> Result<GarlemliaMessage, Option<MessageError>> {
    let garlemlia = garl.lock().await;
    let node = garlemlia.node.lock().await.clone();
    parse_message_generic(garlemlia.routing_table.clone(), garlemlia.data_store.clone(), garlemlia.garlic.clone(), garlemlia.file_storage.clone(), sender_node, node.clone(), msg, garlemlia.is_processing.clone()).await
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

    async fn send_no_recv(&self, _socket: &UdpSocket, from_node: Node, target: &SocketAddr, msg: &GarlemliaMessage) -> Result<Option<GarlemliaMessage>, MessageError> {
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

        Ok(None)
    }

    // Send a message to another node
    async fn send(&self, socket: &UdpSocket, from_node: Node, target: &SocketAddr, msg: &GarlemliaMessage) -> Result<Option<GarlemliaMessage>, MessageError> {
        //println!("Send {:?} to {} from {}", msg, target, from_node.clone().address);
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

                //println!("Before parse message");
                let response = node_locked.parse_message(from_node.clone(), msg.clone()).await;
                //println!("After parse message");

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
                                    //println!("1");
                                    let mut gars = RUNNING_GARLEMLIA.lock().await;
                                    //println!("2");
                                    let running_gar_locked = gars.get_mut(&from_node).unwrap();
                                    //println!("3");
                                    let running_gar = running_gar_locked.lock().await;
                                    //println!("4");
                                    let rt = Arc::clone(&running_gar.routing_table);
                                    //println!("Before routing table shenanigans");
                                    add_to_routing_table(rt, sender).await;
                                    //println!("After routing table shenanigans");
                                }
                                None => {}
                            }
                        } else {
                            match km.sender() {
                                Some(sender) => {
                                    node_locked.add_node(sender.clone()).await;
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
                            stupid_mh = Arc::clone(&target_garm.lock().await.message_handler);
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

async fn file_node_to_simulated(file_node: FileNode) -> Option<SimulatedNode> {
    let file_storage = FileStorage::load(file_node.file_storage).await;
    match file_storage {
        Ok(file_storage) => {
            Some(SimulatedNode::new(Node { id: file_node.id, address: file_node.address.parse().unwrap() }, file_node.routing_table.to_routing_table(), file_node.data_store, file_node.garlic.to_garlic(), file_storage, file_node.is_online))
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
        garlic: SerializableGarlicCast::from(sim_node.garlic.lock().await.clone()).await,
        is_online: sim_node.is_online
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
        node.garlic.known_nodes.extend(node.routing_table.clone().to_routing_table().flat_nodes().await.clone());
        let sim_node = file_node_to_simulated(node).await;
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
            let garlic = node.garlic.lock().await;
            garlic.set_known(vec![]).await;
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
        RUNNING_GARLEMLIA.lock().await.insert(node.clone(), Arc::new(Mutex::new(garlemlia)));
    }
}

pub async fn remove_running(node: Node) {
    {
        RUNNING_NODES.lock().await.remove(&node);
        RUNNING_GARLEMLIA.lock().await.remove(&node);
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
        gc_first.set_public_key(pub_k_first).await;
        gc_first.set_private_key(priv_k_first).await;
    }

    {
        SIM.lock().await.create_node(SimulatedNode {
            node: nodes[0].node.clone(),
            routing_table: nodes[0].routing_table.clone(),
            data_store: nodes[0].data_store.clone(),
            file_storage: nodes[0].file_storage.clone(),
            garlic: nodes[0].garlic.clone(),
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

        add_running(node.node.clone(), GarlemliaInfo::from(Arc::clone(&run_node.node), Arc::clone(&run_node.message_handler), Arc::clone(&run_node.routing_table), Arc::clone(&run_node.data_store), Arc::clone(&run_node.garlic), Arc::clone(&run_node.file_storage))).await;

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
            SIM.lock().await.create_node(SimulatedNode {
                node: node_actual.clone(),
                routing_table: Arc::new(Mutex::new(rt.clone())),
                data_store: Arc::new(Mutex::new(ds)),
                file_storage: Arc::new(Mutex::new(fs)),
                garlic: Arc::new(Mutex::new(gar)),
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