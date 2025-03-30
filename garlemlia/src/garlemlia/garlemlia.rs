use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr};
use std::path::Path;
use std::sync::{Arc};
use std::sync::atomic::{AtomicBool, Ordering};
use primitive_types::U256;
use rand_core::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex};
use tokio::{fs, task};

use crate::garlemlia_structs::garlemlia_structs;
use crate::garlic_cast::garlic_cast;
use garlemlia_structs::{Node, MessageChannel, DEFAULT_K, GMessage, GarlemliaMessage, RoutingTable, LOOKUP_ALPHA};
use garlic_cast::{GarlicCast};
use crate::file_utils::garlemlia_files::FileStorage;
use crate::garlemlia_structs::garlemlia_structs::{CloveMessage, GarlemliaData, GarlemliaFindRequest, GarlemliaResponse, GarlemliaStoreRequest};
use crate::simulator::simulator::get_global_socket;

pub struct GarlemliaFunctions {}

impl GarlemliaFunctions {
    pub async fn iterative_find_node(socket: Arc<UdpSocket>,
                                     self_node: Node,
                                     routing_table: Arc<Mutex<RoutingTable>>,
                                     message_handler: Arc<Box<dyn GMessage>>,
                                     garlic: Arc<Mutex<GarlicCast>>,
                                     target_id: U256) -> Vec<Node> {
        let mut queried_nodes = HashSet::new();

        // Get initial candidate set from the routing table.
        let mut initial_nodes = routing_table.lock().await
            .find_closest_nodes(target_id, LOOKUP_ALPHA)
            .await;
        if initial_nodes.contains(&self_node) {
            initial_nodes = routing_table.lock().await
                .find_closest_nodes(target_id, LOOKUP_ALPHA + 1)
                .await;
            initial_nodes.retain(|x| *x != self_node);
        }
        // Initialize candidate set (top_k)
        let mut top_k = initial_nodes.clone();
        top_k.sort_by_key(|n| n.id ^ target_id);
        top_k.truncate(DEFAULT_K);

        // Initialize nodes to query from the candidate set.
        let mut nodes_to_query: Vec<Node> = top_k
            .iter()
            .filter(|n| !queried_nodes.contains(&n.address))
            .cloned()
            .collect();
        if nodes_to_query.len() > LOOKUP_ALPHA {
            nodes_to_query.truncate(LOOKUP_ALPHA);
        }

        loop {
            let mut tasks = Vec::new();
            // Query all nodes that haven't been queried yet (up to α)
            for node in nodes_to_query.iter() {
                if queried_nodes.contains(&node.address) {
                    continue;
                }

                queried_nodes.insert(node.address);
                let socket_clone = Arc::clone(&socket);
                let node_clone = node.clone();
                let message_handler = Arc::clone(&message_handler);
                let self_thread_node = self_node.clone();

                let task = tokio::spawn(async move {
                    let message = GarlemliaMessage::FindNode {
                        id: target_id,
                        sender: self_thread_node.clone(),
                    };

                    if let Err(e) = message_handler.send(&socket_clone, self_thread_node.clone(), &node_clone.address, &message).await {
                        eprintln!("Failed to send FindNode to {}: {:?}", node_clone.address, e);
                    }

                    let response = message_handler.recv(200, &node_clone.address).await;
                    if let Ok(msg) = response {
                        if let GarlemliaMessage::Response { nodes, .. } = msg {
                            return Some(nodes);
                        }
                    }
                    None
                });
                tasks.push(task);
            }

            // Gather all new nodes returned by this round.
            let mut new_nodes = vec![];
            for task in tasks {
                if let Ok(Some(nodes)) = task.await {
                    new_nodes.extend(nodes);
                }
            }

            {
                // Adds to list of known nodes
                garlic.lock().await.update_known(new_nodes.clone()).await;
            }

            // Merge new nodes into our candidate set.
            let mut new_candidate_set = top_k.clone();
            new_candidate_set.extend(new_nodes.clone());
            new_candidate_set.sort_by_key(|n| n.id ^ target_id);
            new_candidate_set.dedup();
            new_candidate_set.retain(|n| *n != self_node);
            new_candidate_set.truncate(DEFAULT_K);

            // Compare candidate sets using IDs (order-independent)
            let old_ids: HashSet<U256> = top_k.iter().map(|n| n.id).collect();
            let new_ids: HashSet<U256> = new_candidate_set.iter().map(|n| n.id).collect();
            if old_ids == new_ids {
                break;
            }
            top_k = new_candidate_set;

            // Update nodes to query: those in the new candidate set not yet queried.
            nodes_to_query = top_k
                .iter()
                .filter(|node| !queried_nodes.contains(&node.address))
                .cloned()
                .collect();
            if nodes_to_query.len() > LOOKUP_ALPHA {
                nodes_to_query.truncate(LOOKUP_ALPHA);
            }
            if nodes_to_query.is_empty() {
                break;
            }
        }

        // Add self to the candidate set, sort and truncate before returning.
        let mut result = top_k;
        result.push(self_node.clone());
        result.dedup();
        result.sort_by_key(|n| n.id ^ target_id);
        result.truncate(DEFAULT_K);
        result
    }


    // Perform an iterative lookup for a value in the DHT
    pub async fn iterative_find_value(socket: Arc<UdpSocket>,
                                      self_node: Node,
                                      routing_table: Arc<Mutex<RoutingTable>>,
                                      message_handler: Arc<Box<dyn GMessage>>,
                                      data_store: Arc<Mutex<HashMap<U256, GarlemliaData>>>,
                                      request: GarlemliaFindRequest) -> Option<GarlemliaResponse> {
        let key = request.get_id();
        // Check if this node has the value first
        let local = data_store.lock().await.get(&key).cloned();
        match local {
            Some(val) => {
                return val.get_response(request);
            }
            _ => {}
        }

        let mut queried_nodes = HashSet::new();

        // Get initial candidate set from the routing table.
        let mut initial_nodes = routing_table.lock().await
            .find_closest_nodes(key, LOOKUP_ALPHA)
            .await;
        if initial_nodes.contains(&self_node) {
            initial_nodes = routing_table.lock().await
                .find_closest_nodes(key, LOOKUP_ALPHA + 1)
                .await;
            initial_nodes.retain(|x| *x != self_node);
        }
        // Initialize candidate set (top_k)
        let mut top_k = initial_nodes.clone();
        top_k.sort_by_key(|n| n.id ^ key);
        top_k.truncate(DEFAULT_K);

        // Initialize nodes to query from the candidate set.
        let mut nodes_to_query: Vec<Node> = top_k
            .iter()
            .filter(|n| !queried_nodes.contains(&n.address))
            .cloned()
            .collect();
        if nodes_to_query.len() > LOOKUP_ALPHA {
            nodes_to_query.truncate(LOOKUP_ALPHA);
        }

        loop {
            let mut tasks = Vec::new();

            for node in nodes_to_query.iter() {
                if queried_nodes.contains(&node.address) {
                    continue;
                }

                queried_nodes.insert(node.address);
                let socket_clone = Arc::clone(&socket);
                let node_clone = node.clone();
                let message_handler = Arc::clone(&message_handler);
                let self_thread_node = self_node.clone();
                let request_clone = request.clone();

                // Spawn async task for each lookup request
                let task = task::spawn(async move {
                    let message = GarlemliaMessage::FindValue {
                        request: request_clone,
                        sender: self_thread_node.clone(),
                    };

                    {
                        if let Err(e) = message_handler.send(&socket_clone, self_thread_node.clone(), &node_clone.address, &message).await {
                            eprintln!("Failed to send FindValue to {}: {:?}", node_clone.address, e);
                        }
                    }

                    let response;
                    {
                        response = message_handler.recv(200, &node_clone.address).await;
                    }

                    if response.is_ok() {
                        let msg = response.unwrap();
                        match msg {
                            GarlemliaMessage::Response { nodes, value, .. } => {
                                if let Some(value) = value {
                                    return Some(Ok(value))
                                }
                                Some(Err(nodes))
                            }
                            _ => {
                                Some(Err(vec![]))
                            }
                        }
                    } else {
                        Some(Err(vec![]))
                    }
                });

                tasks.push(task);
            }

            // Collect results from tasks
            let mut new_nodes = vec![];
            for task in tasks {
                if let Ok(Some(result)) = task.await {
                    match result {
                        Ok(value) => return Some(value), // Return immediately if value is found
                        Err(received_nodes) => {
                            new_nodes.extend(received_nodes);
                        }
                    }
                }
            }

            // Merge new nodes into our candidate set.
            let mut new_candidate_set = top_k.clone();
            new_candidate_set.extend(new_nodes.clone());
            new_candidate_set.sort_by_key(|n| n.id ^ key);
            new_candidate_set.truncate(DEFAULT_K);

            // Compare candidate sets using IDs (order-independent)
            let old_ids: HashSet<U256> = top_k.iter().map(|n| n.id).collect();
            let new_ids: HashSet<U256> = new_candidate_set.iter().map(|n| n.id).collect();
            if old_ids == new_ids {
                break;
            }
            top_k = new_candidate_set;

            // Update nodes to query: those in the new candidate set not yet queried.
            nodes_to_query = top_k
                .iter()
                .filter(|node| !queried_nodes.contains(&node.address))
                .cloned()
                .collect();
            if nodes_to_query.len() > LOOKUP_ALPHA {
                nodes_to_query.truncate(LOOKUP_ALPHA);
            }
            if nodes_to_query.is_empty() {
                break;
            }
        }

        None
    }

    pub async fn store_value(socket: Arc<UdpSocket>,
                             self_node: Node,
                             routing_table: Arc<Mutex<RoutingTable>>,
                             message_handler: Arc<Box<dyn GMessage>>,
                             data_store: Arc<Mutex<HashMap<U256, GarlemliaData>>>,
                             garlic: Arc<Mutex<GarlicCast>>,
                             file_storage: Arc<Mutex<FileStorage>>,
                             request: GarlemliaStoreRequest, store_count: usize) -> Vec<Node> {
        // Find the closest nodes to store the value
        let mut closest_nodes = GarlemliaFunctions::iterative_find_node(Arc::clone(&socket), self_node.clone(), Arc::clone(&routing_table), Arc::clone(&message_handler), Arc::clone(&garlic), request.get_id()).await;
        closest_nodes.truncate(store_count);

        for node in closest_nodes.clone() {
            if node.id == self_node.id {
                let store_val = request.to_store_data();

                if request.is_chunk() {
                    let _ = file_storage.lock().await.store_chunk(request.get_id(), request.chunk_get_data().unwrap()).await;
                }

                // Store the value locally if this node is among the closest
                let mut data_store = data_store.lock().await;
                if store_val.is_some() {
                    data_store.insert(request.get_id(), store_val.unwrap());
                    continue;
                }
            }

            // Create STORE message
            let store_message = GarlemliaMessage::Store {
                key: request.get_id(),
                value: request.clone(),
                sender: self_node.clone(),
            };

            // Send STORE message
            {
                if let Err(e) = message_handler.send_no_recv(&socket, self_node.clone(), &node.address, &store_message).await {
                    eprintln!("Failed to send Store to {}: {:?}", node.address, e);
                }
            }
        }

        closest_nodes
    }
}

// Kademlia Struct
#[derive(Clone)]
pub struct Garlemlia {
    pub node: Arc<Mutex<Node>>,
    pub socket: Arc<UdpSocket>,
    pub receive_addr: SocketAddr,
    pub message_handler: Arc<Box<dyn GMessage>>,
    pub routing_table: Arc<Mutex<RoutingTable>>,
    pub data_store: Arc<Mutex<HashMap<U256, GarlemliaData>>>,
    pub file_storage: Arc<Mutex<FileStorage>>,
    pub garlic: Arc<Mutex<GarlicCast>>,
    stop_signal: Arc<AtomicBool>,
    join_handle: Arc<Option<task::JoinHandle<()>>>,
}

// TODO: Implement new event thread for watching last_seen information and pinging nodes
// TODO: which have not been seen in an hour + evicting those which fail
// TODO: Add RPC ID's to messages?
impl Garlemlia {
    pub async fn new(id: U256, address: &str, port: u16, rt: RoutingTable, msg_handler: Box<dyn GMessage>, file_storage_path: Box<&Path>) -> Self {
        let mut dir_id = file_storage_path.join(id.to_string());
        dir_id.push("downloads");
        fs::create_dir_all(dir_id.clone()).await.unwrap();
        dir_id.pop();
        dir_id.push("chunks");
        fs::create_dir_all(dir_id.clone()).await.unwrap();
        dir_id.pop();
        dir_id.push("temp_chunks");
        fs::create_dir_all(dir_id.clone()).await.unwrap();

        let root_dir = format!("{}/{}", file_storage_path.to_str().unwrap(), id);
        let file_storage = FileStorage::new(format!("{}/file_storage.json", root_dir), format!("{}/downloads", root_dir), format!("{}/chunks", root_dir), format!("{}/temp_chunks", root_dir));

        let node = Node { id, address: format!("{address}:{port}").parse().unwrap() };
        let socket = Arc::new(UdpSocket::bind(format!("{}:{}", address, port)).await.unwrap());

        let mut rng = OsRng;
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);

        let garlic = GarlicCast::new(Arc::clone(&socket), node.clone(), Arc::new(msg_handler.clone()), vec![], Some(public_key), Some(private_key));

        Self {
            node: Arc::new(Mutex::new(node)),
            socket,
            receive_addr: format!("{address}:{port}").parse().unwrap(),
            message_handler: Arc::new(msg_handler),
            routing_table: Arc::new(Mutex::new(rt)),
            data_store: Arc::new(Mutex::new(HashMap::new())),
            file_storage: Arc::new(Mutex::new(file_storage)),
            garlic: Arc::new(Mutex::new(garlic)),
            stop_signal: Arc::new(AtomicBool::new(false)),
            join_handle: Arc::new(None),
        }
    }

    pub async fn new_with_details(id: U256, address: &str, port: u16, rt: RoutingTable, msg_handler: Box<dyn GMessage>, socket: Arc<UdpSocket>, public_key: RsaPublicKey, private_key: RsaPrivateKey, file_storage_path: Box<&Path>) -> Self {
        let mut dir_id = file_storage_path.join(id.to_string());
        dir_id.push("downloads");
        fs::create_dir_all(dir_id.clone()).await.unwrap();
        dir_id.pop();
        dir_id.push("chunks");
        fs::create_dir_all(dir_id.clone()).await.unwrap();
        dir_id.pop();
        dir_id.push("temp_chunks");
        fs::create_dir_all(dir_id.clone()).await.unwrap();

        let root_dir = format!("{}/{}", file_storage_path.to_str().unwrap(), id);
        let file_storage = FileStorage::new(format!("{}/file_storage.json", root_dir), format!("{}/downloads", root_dir), format!("{}/chunks", root_dir), format!("{}/temp_chunks", root_dir));

        let node = Node { id, address: format!("{address}:{port}").parse().unwrap() };

        let message_handler = Arc::new(msg_handler);

        let garlic = GarlicCast::new(Arc::clone(&socket), node.clone(), Arc::clone(&message_handler), vec![], Some(public_key), Some(private_key));

        Self {
            node: Arc::new(Mutex::new(node)),
            socket: Arc::clone(&socket),
            receive_addr: format!("{address}:{port}").parse().unwrap(),
            message_handler,
            routing_table: Arc::new(Mutex::new(rt)),
            data_store: Arc::new(Mutex::new(HashMap::new())),
            file_storage: Arc::new(Mutex::new(file_storage)),
            garlic: Arc::new(Mutex::new(garlic)),
            stop_signal: Arc::new(AtomicBool::new(false)),
            join_handle: Arc::new(None),
        }
    }

    pub async fn set_node(&self, node: &mut Node) {
        self.node.lock().await.update(node);
    }

    pub async fn set_routing_table(&self, rt: RoutingTable) {
        self.routing_table.lock().await.update_from(rt).await;
    }

    pub async fn set_data_store(&self, data_store: &mut HashMap<U256, GarlemliaData>) {
        let mut ds = self.data_store.lock().await;
        ds.clear();

        for i in data_store.iter() {
            ds.insert(*i.0, i.1.clone());
        }
    }
    pub async fn set_garlic_cast(&self, gc: GarlicCast) {
        self.garlic.lock().await.update_from(gc).await;
    }
    

    async fn get_node(&self) -> Node {
        let node;
        {
            node = self.node.lock().await;
        }
        node.clone()
    }

    // Start listening for messages
    pub async fn start(&mut self, orig_socket: Arc<UdpSocket>) {
        let self_node = Arc::clone(&self.node);
        let socket = Arc::clone(&orig_socket);
        let message_handler = Arc::clone(&self.message_handler);
        let routing_table = Arc::clone(&self.routing_table);
        let data_store = Arc::clone(&self.data_store);
        let garlic = Arc::clone(&self.garlic);
        let file_storage = Arc::clone(&self.file_storage);
        let stop_clone = Arc::clone(&self.stop_signal);
        println!("STARTING {}", socket.local_addr().unwrap());

        // TODO: Modify this thread to spawn other threads to process messages as they come in.
        // TODO: This should ensure that this thread is always available to actually receive messages
        let handle = tokio::spawn(async move {
            let mut buf = [0; 8192];
            while !stop_clone.load(Ordering::Relaxed) {
                if let Ok((size, src)) = socket.recv_from(&mut buf).await {
                    let self_ref;
                    {
                        self_ref = self_node.lock().await;
                    }
                    let msg: GarlemliaMessage = serde_json::from_slice(&buf[..size]).unwrap();

                    //println!("{} received {:?}", socket.local_addr().unwrap(), msg);

                    // Extract sender Node info
                    let sender_node = Node {
                        id: msg.sender_id(),
                        address: src,
                    };

                    if cfg!(debug_assertions) {
                        println!("Received msg {:?} from {:?} to {:?}", msg, sender_node, self_ref);
                    }

                    match msg {
                        GarlemliaMessage::FindNode { id, .. } => {
                            let mut rt = routing_table.lock().await;
                            // Add the sender to the routing table
                            rt.add_node_from_responder(Arc::clone(&message_handler), sender_node.clone(), Arc::clone(&socket)).await;
                            let response = if id == self_ref.id {
                                // If the search target is this node itself, return only this node
                                GarlemliaMessage::Response {
                                    nodes: vec![self_ref.clone()],
                                    value: None,
                                    sender: self_ref.clone(),
                                }
                            } else {
                                // Return the closest known nodes
                                let closest_nodes = rt.find_closest_nodes(id, DEFAULT_K).await;
                                GarlemliaMessage::Response {
                                    nodes: closest_nodes,
                                    value: None,
                                    sender: self_ref.clone(),
                                }
                            };

                            if cfg!(debug_assertions) {
                                //println!("Responding to message with {:?}", response);
                            }

                            if let Err(e) = message_handler.send_no_recv(&socket, self_ref.clone(), &src, &response).await {
                                eprintln!("Failed to send response to {}: {:?}", src, e);
                            }
                        }

                        // Store a key-value pair
                        GarlemliaMessage::Store { key, value, .. } => {
                            routing_table.lock().await.add_node_from_responder(Arc::clone(&message_handler), sender_node.clone(), Arc::clone(&socket)).await;

                            let store_val;
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

                            if value.is_chunk() {
                                let _ = file_storage.lock().await.store_chunk(key, value.chunk_get_data().unwrap()).await;
                            }

                            if store_val.is_some() {
                                data_store.lock().await.insert(key, store_val.clone().unwrap());
                            }
                        }

                        // Use find_closest_nodes() if value is not found
                        GarlemliaMessage::FindValue { request, .. } => {
                            let key = request.get_id();
                            let mut rt = routing_table.lock().await;

                            rt.add_node_from_responder(Arc::clone(&message_handler), sender_node.clone(), Arc::clone(&socket)).await;
                            let value = data_store.lock().await.get(&key).cloned();

                            let response = if let Some(val) = value {
                                let mut val_response = val.get_response(request);
                                if val.is_chunk() {
                                    let chunk_data = file_storage.lock().await.get_chunk(val.get_id()).await;

                                    if chunk_data.is_ok() {
                                        val_response = val.get_chunk_response(chunk_data.unwrap());
                                    }
                                }

                                GarlemliaMessage::Response {
                                    nodes: vec![],
                                    value: val_response,
                                    sender: self_ref.clone(),
                                }
                            } else {
                                let closest_nodes = rt.find_closest_nodes(key, DEFAULT_K).await;

                                GarlemliaMessage::Response {
                                    nodes: closest_nodes,
                                    value: None,
                                    sender: self_ref.clone(),
                                }
                            };

                            if let Err(e) = message_handler.send_no_recv(&socket, self_ref.clone(), &src, &response).await {
                                eprintln!("Failed to send response to {}: {:?}", src, e);
                            }
                        }

                        GarlemliaMessage::Response { nodes, value, sender, .. } => {
                            let mut rt = routing_table.lock().await;
                            rt.add_node_from_responder(Arc::clone(&message_handler), sender_node.clone(), Arc::clone(&socket)).await;

                            let constructed = GarlemliaMessage::Response {
                                nodes,
                                value,
                                sender,
                            };

                            let tx_info = message_handler.send_tx(sender_node.address, MessageChannel { node_id: sender_node.id, msg: constructed }).await;

                            match tx_info {
                                Ok(_) => {}
                                Err(e) => {
                                    eprintln!("Failed to send TX for message from {}: {:?}", src, e);
                                }
                            }
                        }

                        GarlemliaMessage::Garlic { msg, sender } => {
                            let mut rt = routing_table.lock().await;
                            rt.add_node_from_responder(Arc::clone(&message_handler), sender_node.clone(), Arc::clone(&socket)).await;
                            let action_res;
                            {
                                action_res = garlic.lock().await.recv(sender, msg).await;
                            }

                            if action_res.is_ok() {
                                let action_opt = action_res.unwrap();
                                if action_opt.is_some() {
                                    let action = action_opt.unwrap();

                                    let mut response_data = None;
                                    match action.clone() {
                                        CloveMessage::SearchOverlay { request_id, proxy_id, .. } => {
                                            let yeet_node;
                                            {
                                                yeet_node = self_node.lock().await.clone();
                                            }
                                            GarlemliaFunctions::store_value(Arc::clone(&socket), yeet_node,
                                                                            Arc::clone(&routing_table),
                                                                            Arc::clone(&message_handler),
                                                                            Arc::clone(&data_store),
                                                                            Arc::clone(&garlic),
                                                                            Arc::clone(&file_storage),
                                                                            GarlemliaStoreRequest::Validator { id: request_id.request_id, proxy_id },
                                                                            3).await;
                                        }
                                        CloveMessage::SearchGarlemlia { key, .. } => {
                                            let yeet_node;
                                            {
                                                yeet_node = self_node.lock().await.clone();
                                            }
                                            response_data = GarlemliaFunctions::iterative_find_value(Arc::clone(&socket), yeet_node,
                                                                                                         Arc::clone(&routing_table),
                                                                                                         Arc::clone(&message_handler),
                                                                                                         Arc::clone(&data_store),
                                                                                                         GarlemliaFindRequest::Key { id: key }).await;
                                        }
                                        CloveMessage::ResponseWithValidator { request_id, proxy_id, .. } => {
                                            let yeet_node;
                                            {
                                                yeet_node = self_node.lock().await.clone();
                                            }
                                            response_data = GarlemliaFunctions::iterative_find_value(Arc::clone(&socket), yeet_node,
                                                                                                         Arc::clone(&routing_table),
                                                                                                         Arc::clone(&message_handler),
                                                                                                         Arc::clone(&data_store),
                                                                                                         GarlemliaFindRequest::Validator { id: request_id.request_id, proxy_id }).await;
                                        }
                                        CloveMessage::Store { data, .. } => {
                                            let yeet_node;
                                            {
                                                yeet_node = self_node.lock().await.clone();
                                            }
                                            GarlemliaFunctions::store_value(get_global_socket().unwrap(), yeet_node,
                                                                            Arc::clone(&routing_table),
                                                                            Arc::clone(&message_handler),
                                                                            Arc::clone(&data_store),
                                                                            Arc::clone(&garlic),
                                                                            Arc::clone(&file_storage),
                                                                            data,
                                                                            2).await;
                                        }
                                        _ => {}
                                    }

                                    {
                                        garlic.lock().await.run_proxy_message(action, response_data).await;
                                    }
                                }
                            }
                        }

                        GarlemliaMessage::Ping { .. } => {
                            if let Err(e) = message_handler.send_no_recv(&socket, self_ref.clone(), &src, &GarlemliaMessage::Pong { sender: self_ref.clone() }).await {
                                eprintln!("Failed to send response to {}: {:?}", src, e);
                            }
                        }

                        GarlemliaMessage::Pong { sender, .. } => {
                            let tx_info = message_handler.send_tx(sender_node.address, MessageChannel { node_id: sender_node.id, msg: GarlemliaMessage::Pong { sender } }).await;

                            match tx_info {
                                Ok(_) => {}
                                Err(e) => {
                                    eprintln!("Failed to send TX for message from {}: {:?}", src, e);
                                }
                            }
                        }

                        GarlemliaMessage::SearchFile { search_id, proxy_id, search_term, sender } => {
                            let mut rt = routing_table.lock().await;
                            rt.add_node_from_responder(Arc::clone(&message_handler), sender_node.clone(), Arc::clone(&socket)).await;
                            // TODO: Search data store for file names which are close to the search_term
                        }

                        GarlemliaMessage::AgreeAlt { alt_sequence_number, sender } => {
                            let mut rt = routing_table.lock().await;
                            rt.add_node_from_responder(Arc::clone(&message_handler), sender_node.clone(), Arc::clone(&socket)).await;

                            let tx_info = message_handler.send_tx(sender_node.address, MessageChannel { node_id: sender_node.id, msg: GarlemliaMessage::AgreeAlt { alt_sequence_number, sender } }).await;

                            match tx_info {
                                Ok(_) => {}
                                Err(e) => {
                                    eprintln!("Failed to send TX for message from {}: {:?}", src, e);
                                }
                            }
                        }

                        GarlemliaMessage::Stop {} => {
                            if sender_node.address == self_ref.address {
                                break;
                            }
                        }
                    }
                }
            }
            println!("FINISHED {}", socket.local_addr().unwrap());
            drop(socket);
        });
        *Arc::get_mut(&mut self.join_handle).unwrap() = Some(handle);
    }

    pub async fn stop(&self) {
        self.stop_signal.store(true, Ordering::Relaxed);

        if let Some(handle) = Arc::get_mut(&mut self.join_handle.clone()).and_then(|h| h.take()) {
            handle.abort();
            let _ = handle.await;
        }

        self.socket.send_to(&*serde_json::to_vec(&GarlemliaMessage::Stop {}).unwrap(), &self.receive_addr).await.unwrap();
    }

    pub async fn iterative_find_node(&self, socket: Arc<UdpSocket>, target_id: U256) -> Vec<Node> {
        GarlemliaFunctions::iterative_find_node(socket, self.get_node().await,
                                                Arc::clone(&self.routing_table),
                                                Arc::clone(&self.message_handler),
                                                Arc::clone(&self.garlic), target_id).await
    }


    // Perform an iterative lookup for a value in the DHT
    pub async fn iterative_find_value(&self, socket: Arc<UdpSocket>, request: GarlemliaFindRequest) -> Option<GarlemliaResponse> {
        GarlemliaFunctions::iterative_find_value(socket, self.get_node().await,
                                                 Arc::clone(&self.routing_table),
                                                 Arc::clone(&self.message_handler),
                                                 Arc::clone(&self.data_store), request).await
    }

    pub async fn store_value(&mut self, socket: Arc<UdpSocket>, request: GarlemliaStoreRequest, store_count: usize) -> Vec<Node> {
        GarlemliaFunctions::store_value(socket, self.get_node().await,
                                        Arc::clone(&self.routing_table),
                                        Arc::clone(&self.message_handler),
                                        Arc::clone(&self.data_store),
                                        Arc::clone(&self.garlic),
                                        Arc::clone(&self.file_storage),
                                        request, store_count).await
    }

    // Add a node to the routing table
    pub async fn add_node(&self, socket: &UdpSocket, node: Node) {
        let self_node = self.get_node().await;
        if node.id != self_node.id {
            let message_handler = Arc::clone(&self.message_handler);
            self.routing_table.lock().await.add_node(message_handler, node, socket).await;
        }
    }

    pub async fn refresh_buckets(&mut self, socket: Arc<UdpSocket>) {
        let self_id;
        {
            self_id = self.node.lock().await.id;
        }

        let total_buckets = 255;
        for b in 0..=total_buckets {
            let refresh_id = RoutingTable::random_id_for_bucket(self_id, b);
            self.iterative_find_node(socket.clone(), refresh_id).await;
        }
    }

    pub async fn join_network(&mut self, socket: Arc<UdpSocket>, target: &SocketAddr) {
        let self_node = self.get_node().await;
        let socket_clone = Arc::clone(&socket);
        let message = GarlemliaMessage::FindNode {
            id: self_node.id,
            sender: self_node.clone(),
        };

        {
            if let Err(e) = self.message_handler.send(&socket, self_node.clone(), &target, &message).await {
                eprintln!("Failed to send FindNode to {}: {:?}", target, e);
            }
        }

        let response;
        {
            response = self.message_handler.recv(200, &target).await;
        }

        if response.is_ok() {
            self.iterative_find_node(socket_clone.clone(), self_node.id).await;
            self.refresh_buckets(socket_clone).await;
        } else {
            println!("FAILED TO JOIN NETWORK");
        }
    }
}