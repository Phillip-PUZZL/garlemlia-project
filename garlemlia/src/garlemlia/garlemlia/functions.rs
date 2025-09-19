use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use primitive_types::U256;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::task;
use tokio::time::sleep;
use crate::file_utils::garlemlia_files::FileStorage;
use crate::garlemlia::garlemlia::Garlemlia;
use crate::garlic_cast::garlic_cast::file_operations::FileOperations;
use crate::garlic_cast::garlic_cast::GarlicCast;
use crate::garlic_cast::garlic_cast::message_handling::MessageHandling;
use crate::garlic_cast::garlic_cast::proxy_request::ProxyRequest;
use crate::garlic_cast::garlic_cast::response_handling::ResponseHandling;
use crate::structs::constants::{DEFAULT_K, LOOKUP_ALPHA};
use crate::structs::file_chunks::{ChunkPartAssociations, ProcessingCheck, ProxyChunkPartInfo, ProxyFileChunkInfo};
use crate::structs::garlemlia_data::GarlemliaData;
use crate::structs::garlemlia_message::{GMessage, GarlemliaFindRequest, GarlemliaMessage, GarlemliaResponse, GarlemliaStoreRequest};
use crate::structs::garlic_message::{CloveMessage, CloveRequestID, GarlicMessage};
use crate::structs::node::Node;
use crate::structs::routing_table::RoutingTable;

/// Garlemlia Context information
pub struct GarlemliaContext {
    pub socket: Arc<UdpSocket>,
    pub self_node: Node,
    pub routing_table: Arc<Mutex<RoutingTable>>,
    pub message_handler: Arc<Box<dyn GMessage>>,
    pub data_store: Arc<Mutex<HashMap<U256, GarlemliaData>>>,
    pub garlic: Arc<Mutex<GarlicCast>>,
    pub file_storage: Arc<Mutex<FileStorage>>,
    pub chunk_part_associations: Arc<Mutex<ChunkPartAssociations>>,
}

impl GarlemliaContext {
    pub fn new(
        socket: Arc<UdpSocket>,
        self_node: Node,
        routing_table: Arc<Mutex<RoutingTable>>,
        message_handler: Arc<Box<dyn GMessage>>,
        data_store: Arc<Mutex<HashMap<U256, GarlemliaData>>>,
        garlic: Arc<Mutex<GarlicCast>>,
        file_storage: Arc<Mutex<FileStorage>>,
        chunk_part_associations: Arc<Mutex<ChunkPartAssociations>>,
    ) -> Self {
        Self {
            socket,
            self_node,
            routing_table,
            message_handler,
            data_store,
            garlic,
            file_storage,
            chunk_part_associations,
        }
    }

    pub async fn from(garlemlia: &Garlemlia, socket: Arc<UdpSocket>) -> Self {
        Self {
            socket,
            self_node: garlemlia.get_node().await,
            routing_table: Arc::clone(&garlemlia.routing_table),
            message_handler: Arc::clone(&garlemlia.message_handler),
            data_store: Arc::clone(&garlemlia.data_store),
            garlic: Arc::clone(&garlemlia.garlic),
            file_storage: Arc::clone(&garlemlia.file_storage),
            chunk_part_associations: Arc::clone(&garlemlia.chunk_part_associations)
        }
    }
}

/// **Struct to store Kademlia functions**
pub struct GarlemliaFunctions {}

impl GarlemliaFunctions {
    async fn refresh_initial_nodes(context: &GarlemliaContext,
                                   initial_nodes: &mut Vec<Node>,
                                   key: U256) {
        if initial_nodes.contains(&context.self_node) {
            *initial_nodes = context.routing_table.lock().await
                .find_closest_nodes(key, LOOKUP_ALPHA + 1)
                .await;
            initial_nodes.retain(|x| *x != context.self_node);
        }
    }

    /// Basic Kademlia iterative find node implementation
    pub async fn iterative_find_node(context: &GarlemliaContext,
                                     target_id: U256) -> Vec<Node> {
        // For storing all nodes which have already been queried so as not to re-query
        let mut queried_nodes = HashSet::new();

        // Get initial candidate set from the routing table.
        let mut initial_nodes = context.routing_table.lock().await
            .find_closest_nodes(target_id, LOOKUP_ALPHA)
            .await;
        Self::refresh_initial_nodes(context, &mut initial_nodes, target_id).await;
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
                let socket_clone = Arc::clone(&context.socket);
                let node_clone = node.clone();
                let message_handler = Arc::clone(&context.message_handler);
                let self_thread_node = context.self_node.clone();

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
                context.garlic.lock().await.update_known(new_nodes.clone());
            }

            // Merge new nodes into our candidate set.
            let mut new_candidate_set = top_k.clone();
            new_candidate_set.extend(new_nodes.clone());
            new_candidate_set.sort_by_key(|n| n.id ^ target_id);
            new_candidate_set.dedup();
            // Remove self in case it is added
            new_candidate_set.retain(|n| *n != context.self_node);
            // Keep only closest K nodes
            new_candidate_set.truncate(DEFAULT_K);

            // Compare candidate sets using IDs (order-independent)
            let old_ids: HashSet<U256> = top_k.iter().map(|n| n.id).collect();
            let new_ids: HashSet<U256> = new_candidate_set.iter().map(|n| n.id).collect();
            if old_ids == new_ids {
                // No new closest K nodes found, can stop querying
                break;
            }
            top_k = new_candidate_set;

            // Update nodes to query: those in the new candidate set not yet queried.
            nodes_to_query = top_k
                .iter()
                .filter(|node| !queried_nodes.contains(&node.address))
                .cloned()
                .collect();
            // Only want to query Alpha nodes at one time
            if nodes_to_query.len() > LOOKUP_ALPHA {
                nodes_to_query.truncate(LOOKUP_ALPHA);
            }
            if nodes_to_query.is_empty() {
                break;
            }
        }

        // Add self to the candidate set, sort and truncate before returning.
        let mut result = top_k;
        result.push(context.self_node.clone());
        result.dedup();
        result.sort_by_key(|n| n.id ^ target_id);
        result.truncate(DEFAULT_K);

        // Return K closest nodes
        result
    }


    /// Perform an iterative lookup for a value in the DHT - Kademlia regular implementation
    pub async fn iterative_find_value(context: &GarlemliaContext,
                                      request: GarlemliaFindRequest) -> Option<GarlemliaResponse> {
        let key = request.get_id();
        // Check if this node has the value first
        let local = context.data_store.lock().await.get(&key).cloned();
        match local {
            Some(val) => {
                return val.get_response(Some(request));
            }
            _ => {}
        }

        // Keep track of nodes already queried
        let mut queried_nodes = HashSet::new();

        // Get initial candidate set from the routing table.
        let mut initial_nodes = context.routing_table.lock().await
            .find_closest_nodes(key, LOOKUP_ALPHA)
            .await;
        Self::refresh_initial_nodes(context, &mut initial_nodes, key).await;
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

        // Loop to handle multiple queries
        loop {
            // Vec to house Handler processes
            let mut tasks = Vec::new();

            for node in nodes_to_query.iter() {
                // Check if already queried
                if queried_nodes.contains(&node.address) {
                    continue;
                }

                queried_nodes.insert(node.address);
                let socket_clone = Arc::clone(&context.socket);
                let node_clone = node.clone();
                let message_handler = Arc::clone(&context.message_handler);
                let self_thread_node = context.self_node.clone();
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
                        // Return immediately if value is found
                        Ok(value) => return Some(value),
                        // Else, add the found nodes to the list
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

    /// Kademlia implementation of storing values
    pub async fn store_value(context: &GarlemliaContext,
                             request: GarlemliaStoreRequest, store_count: usize) -> Vec<Node> {
        // Find the closest nodes to store the value
        let mut closest_nodes = GarlemliaFunctions::iterative_find_node(context, request.get_id()).await;
        // Just want to get the closest store_count nodes
        closest_nodes.truncate(store_count);

        // Iterate through nodes
        for node in closest_nodes.clone() {
            // Check if I am one of the closest nodes
            // TODO: Manage self being one of the closest nodes in a better way
            if node.id == context.self_node.id {
                let mut store_val = request.to_store_data();

                // Run through process of determining store type
                if request.is_chunk_info() {
                    // Add chunk info to pending chunks
                    context.chunk_part_associations.lock().await.add_to_chunk_storage(request.get_file_chunk_info().unwrap());
                } else if request.is_chunk_part() {
                    // Lock chunk pending list
                    let mut cpa = context.chunk_part_associations.lock().await;
                    // Get the request ID
                    let chunk_id = request.get_id();
                    // Check whether it is a store request
                    if cpa.am_storing_chunk(chunk_id) {
                        // Get mutable storage FileChunkInfo
                        let chunk_info = cpa.get_mut_chunk_stored(chunk_id).unwrap();
                        // Add appropriate chunk part information
                        chunk_info.parts_info.push(request.get_chunk_part_info().unwrap());

                        // Get the index of the chunk part
                        let index = request.get_chunk_part_index().unwrap();
                        // Get the data of the chunk part
                        let chunk_part_data = request.get_chunk_part_data().unwrap();

                        {
                            // Store the chunk part on the disk
                            let _ = context.file_storage.lock().await.store_chunk_part(chunk_id, index, chunk_part_data).await;
                        }

                        // Check if all chunk parts have been received
                        if chunk_info.parts_info.len() == chunk_info.parts_count {
                            // Put chunk together from chunk parts
                            let check = context.file_storage.lock().await.assemble_chunk(chunk_id, chunk_info.parts_count).await;

                            // Check whether successfully assembled chunk
                            if check.is_ok() {
                                // Remove chunk info from pending list
                                cpa.remove_from_chunk_storage(chunk_id);
                            }
                        }
                    }

                    // Set flag since this is a chunk part
                    store_val = None;
                }

                if store_val.is_some() {
                    let mut check = store_val.unwrap();
                    // Convert data to a variation that is more easily stored
                    check.store();

                    store_val = Some(check);
                }

                // Store the value locally if this node is among the closest
                if store_val.is_some() {
                    context.data_store.lock().await.insert(request.get_id(), store_val.unwrap());
                    continue;
                }
            }

            // Create STORE message
            let store_message = GarlemliaMessage::Store {
                key: request.get_id(),
                value: request.clone(),
                sender: context.self_node.clone(),
            };

            // Send STORE message
            {
                if let Err(e) = context.message_handler.send_no_recv(&context.socket, context.self_node.clone(), &node.address, &store_message).await {
                    eprintln!("Failed to send Store to {}: {:?}", node.address, e);
                }
            }
        }

        closest_nodes
    }

    pub async fn send_chunk_parts(socket: Arc<UdpSocket>,
                                  self_node: Node,
                                  message_handler: Arc<Box<dyn GMessage>>,
                                  request_id: CloveRequestID,
                                  chunks: Vec<GarlemliaResponse>,
                                  requester: SocketAddr) {
        // Loop through chunk parts
        for chunk in chunks {
            // Provide some measure of reprieve to the network
            sleep(Duration::from_millis(200)).await;
            // Create GarlemliaMessage for a FileChunkPart
            let response = GarlemliaMessage::Garlic {
                sender: self_node.clone(),
                msg: GarlicMessage::FileChunkPart {
                    request_id: request_id.clone(),
                    data: chunk.clone(),
                }
            };

            {
                // Send Message
                if let Err(e) = message_handler.send_no_recv(&Arc::clone(&socket), self_node.clone(), &requester, &response).await {
                    eprintln!("Failed to send Chunk Part to {}: {:?}", requester, e);
                }
            }
        }
    }

    pub async fn search_file(data_store: Arc<Mutex<HashMap<U256, GarlemliaData>>>, file_name: String) -> Option<GarlemliaResponse> {
        let mut response = None;

        let ds;
        {
            ds = data_store.lock().await.clone();
        }

        // Iterate through Data Store to search for a file
        for item in ds.iter() {
            let g_data = item.1.clone();

            match g_data.clone() {
                GarlemliaData::FileName { name, .. } => {
                    if file_name == name {
                        response = g_data.get_response(None);
                        break;
                    }
                }
                _ => {}
            }
        }

        response
    }

    /// Function to match a request / response and run appropriate action
    pub async fn run_message(self_node: Node,
                             socket: Arc<UdpSocket>,
                             message_handler: Arc<Box<dyn GMessage>>,
                             routing_table: Arc<Mutex<RoutingTable>>,
                             data_store: Arc<Mutex<HashMap<U256, GarlemliaData>>>,
                             garlic: Arc<Mutex<GarlicCast>>,
                             file_storage: Arc<Mutex<FileStorage>>,
                             chunk_part_associations: Arc<Mutex<ChunkPartAssociations>>,
                             check_processing: Arc<Mutex<ProcessingCheck>>,
                             msg: GarlemliaMessage,
                             sender_node: Node) -> Option<GarlemliaMessage> {
        match msg {
            GarlemliaMessage::FindNode { id, .. } => {
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

                if cfg!(debug_assertions) {
                    //println!("Responding to message with {:?}", response);
                }

                Some(response)
            }

            // Store a key-value pair
            GarlemliaMessage::Store { key, value, .. } => {
                let mut store_val;
                // Check whether this node is storing validator information
                if value.is_validator() {
                    let current;
                    {
                        current = data_store.lock().await.get(&key).cloned();
                    }

                    // Check whether there are already entries for this validation session
                    if current.is_some() {
                        let stored_data = current.unwrap();
                        match stored_data {
                            GarlemliaData::Validator { id, proxy_ids, proxies } => {
                                // Get the ID for the proxy
                                let this_proxy_id = value.validator_get_proxy_id().unwrap();
                                // Get the old list of IDs for the validation session
                                let mut new_ids = proxy_ids;
                                // Add the ID from the requester
                                new_ids.push(this_proxy_id);
                                // Get the old list of Proxy IP addresses
                                let mut new_proxies = proxies;
                                // Insert the IP address of the requester
                                new_proxies.insert(this_proxy_id, sender_node.clone().address);
                                // Set the validation pool to this modified version
                                store_val = Some(GarlemliaData::Validator {
                                    id,
                                    proxy_ids: new_ids,
                                    proxies: new_proxies
                                });
                            }
                            _ => {
                                // This should, in theory, never be the case
                                store_val = None;
                            }
                        }
                    } else {
                        // This is a new validation pool request
                        let this_proxy_id = value.validator_get_proxy_id().unwrap();
                        let mut set_proxies = HashMap::new();
                        set_proxies.insert(this_proxy_id, sender_node.clone().address);

                        // Set the new validation pool with the requester as the only entry for the moment
                        store_val = Some(GarlemliaData::Validator {
                            id: key,
                            proxy_ids: vec![this_proxy_id],
                            proxies: set_proxies
                        });
                    }
                } else {
                    // Get the data to store from the request
                    store_val = value.to_store_data();
                }

                // Verify that the data is actually capable of being stored
                if store_val.is_some() {
                    let mut check = store_val.unwrap();
                    // Transpose the data to a form where it can more easily be stored
                    check.store();

                    store_val = Some(check);
                }

                // Check whether this is preliminary chunk data
                if value.is_chunk_info() {
                    // Add the chunk info to the pending list for chunk parts
                    chunk_part_associations.lock().await.add_to_chunk_storage(value.get_file_chunk_info().unwrap());
                } else if value.is_chunk_part() {
                    // Lock the pending chunk part information
                    let mut cpa = chunk_part_associations.lock().await;
                    // Get this chunk ID
                    let chunk_id = value.get_id();
                    // Check to make sure we are storing the chunk
                    if cpa.am_storing_chunk(chunk_id) {
                        // Get mutable chunk info
                        let chunk_info = cpa.get_mut_chunk_stored(chunk_id).unwrap();
                        // Add this chunk part to the list of received chunk parts
                        chunk_info.parts_info.push(value.get_chunk_part_info().unwrap());

                        // Get the chunk part index
                        let index = value.get_chunk_part_index().unwrap();
                        // Get the actual chunk part data
                        let chunk_part_data = value.get_chunk_part_data().unwrap();

                        {
                            // Store the chunk part on the disk for later assembly
                            let _ = file_storage.lock().await.store_chunk_part(chunk_id, index, chunk_part_data).await;
                        }

                        // Check if received all chunk parts for this chunk
                        if chunk_info.parts_info.len() == chunk_info.parts_count {
                            // Assemble the whole chunk from its parts
                            let check = file_storage.lock().await.assemble_chunk(chunk_id, chunk_info.parts_count).await;

                            // Verify that chunk was assembled properly
                            if check.is_ok() {
                                // Remove chunk part information from the list of pending chunks
                                cpa.remove_from_chunk_storage(chunk_id);
                            }
                        }
                    }

                    store_val = None;
                }

                // This is simply a value
                if store_val.is_some() {
                    // Insert value to data store
                    data_store.lock().await.insert(key, store_val.clone().unwrap());
                }

                /*match value {
                    // Check whether we are storing FileName information
                    GarlemliaStoreRequest::FileName { .. } => {
                        let proxies_count;
                        {
                            proxies_count = garlic.lock().await.proxies.len();
                        }

                        if proxies_count == 0 {
                            loop {
                                tokio::time::sleep(Duration::from_millis(10)).await;
                                let mut check = check_processing.lock().await;
                                if !check.check() {
                                    check.set(true);
                                    break;
                                }
                            }

                            let total_buckets = 255;
                            for b in 0..=total_buckets {
                                let refresh_id = RoutingTable::random_id_for_bucket(self_node.id, b);
                                GarlemliaFunctions::iterative_find_node(Arc::clone(&socket), self_node.clone(),
                                                                        Arc::clone(&routing_table),
                                                                        Arc::clone(&message_handler),
                                                                        Arc::clone(&garlic),
                                                                        refresh_id).await;
                            }

                            {
                                garlic.lock().await.discover_proxies(60).await;
                            }

                            {
                                check_processing.lock().await.set(false);
                            }
                        }
                    }
                    _ => {}
                } */

                None
            }

            // Use find_closest_nodes() if value is not found
            GarlemliaMessage::FindValue { request, .. } => {
                // Get key for request and get entry in data store, if it exists
                let key = request.get_id();
                let value = data_store.lock().await.get(&key).cloned();

                let mut response = None;

                // Check if we have the value they are looking for
                if value.is_some() {
                    // We have the value, so unwrap
                    let val = value.unwrap();

                    // If the value is a file chunk
                    if val.is_chunk() {
                        // Get the file chunk data from storage
                        let chunk_data = file_storage.lock().await.get_chunk(val.get_id()).await;

                        // Verify that the chunk data exists
                        if chunk_data.is_ok() {
                            // Get the unwrapped chunk data
                            let chunk_data_clean = chunk_data.unwrap();
                            // Generate the appropriate chunk information response
                            let response_info = val.get_chunk_info(chunk_data_clean.clone(), request.get_request_id().unwrap(), self_node.clone());

                            // Send the chunk info only
                            response = Some(GarlemliaMessage::Response {
                                nodes: vec![],
                                value: response_info,
                                sender: self_node.clone(),
                            });
                        }
                    } else {
                        // Regular data, just generate response and send
                        response = Some(GarlemliaMessage::Response {
                            nodes: vec![],
                            value: val.get_response(Some(request)),
                            sender: self_node.clone(),
                        });
                    }
                } else {
                    // Don't have the data, find the closest nodes and send them
                    let closest_nodes;
                    {
                        closest_nodes = routing_table.lock().await.find_closest_nodes(key, DEFAULT_K).await;
                    }

                    response = Some(GarlemliaMessage::Response {
                        nodes: closest_nodes,
                        value: None,
                        sender: self_node.clone(),
                    });
                }

                response
            }

            GarlemliaMessage::Garlic { msg, sender } => {
                // Firstly need to send an IsAlive message for some message types so that sender knows
                // we received the message
                match msg {
                    GarlicMessage::FindProxy { .. } |
                    GarlicMessage::Forward { .. } |
                    GarlicMessage::ProxyAgree { .. } |
                    GarlicMessage::RefreshAlt { .. } |
                    GarlicMessage::UpdateAlt { .. } |
                    GarlicMessage::UpdateAltNextOrLast { .. } => {
                        {
                            if let Err(e) = message_handler.send_no_recv(&Arc::from(Arc::clone(&socket)), self_node.clone(), &sender_node.address, &GarlicMessage::build_send_is_alive(self_node.clone())).await {
                                eprintln!("Failed to send IsAlive to {}: {:?}", sender_node.address, e);
                            }
                        }
                    }
                    _ => {}
                }

                // Need to get a lock on processing Garlic messages
                ProcessingCheck::wait_and_acquire(&check_processing).await;

                // Get lock on our garlic handler and retrieve message
                let action_res;
                {
                    action_res = garlic.lock().await.recv(sender, msg).await;
                }

                // Get lock on our routing table and get our flat routing table
                let send_search_nodes;
                {
                    send_search_nodes = routing_table.lock().await.flat_nodes().await;
                }

                let mut send_info = None;
                // Verify that we properly received the message
                if action_res.is_ok() {
                    // Get message operator
                    let action_opt = action_res.unwrap();
                    if action_opt.is_some() {
                        // Get actual message
                        let action = action_opt.unwrap();

                        let mut response_data = None;
                        let context_data = GarlemliaContext::new(Arc::clone(&socket), self_node.clone(),
                                                                 Arc::clone(&routing_table),
                                                                 Arc::clone(&message_handler),
                                                                 Arc::clone(&data_store),
                                                                 Arc::clone(&garlic),
                                                                 Arc::clone(&file_storage),
                                                                 Arc::clone(&chunk_part_associations));
                        match action.clone() {
                            CloveMessage::SearchOverlay { request_id, proxy_id, search_term, .. } => {
                                // Searching overlay, need to first generate and store validator information
                                GarlemliaFunctions::store_value(&context_data,
                                                                GarlemliaStoreRequest::Validator { id: request_id.request_id, proxy_id },
                                                                3).await;

                                sleep(Duration::from_millis(100)).await;

                                // Send a search for a file
                                response_data = GarlemliaFunctions::search_file(Arc::clone(&data_store), search_term.clone()).await;
                            }
                            CloveMessage::SearchGarlemlia { key, request_id, .. } => {
                                // Wanting to find a key, so iterative find value
                                response_data = GarlemliaFunctions::iterative_find_value(&context_data,
                                                                                         GarlemliaFindRequest::Key { id: key, request_id: request_id.request_id }).await;

                                // Check response
                                if response_data.is_some() {
                                    // Got data from request
                                    let data = response_data.clone().unwrap();
                                    match data.clone() {
                                        // Check if response has file chunk info
                                        GarlemliaResponse::FileChunkInfo { sender, .. } => {
                                            // Don't have all file chunk info
                                            let mut send_and_process = false;
                                            {
                                                // Lock pending chunk info
                                                let mut cpa = chunk_part_associations.lock().await;
                                                // Check whether we already have this chunk info
                                                if !cpa.already_has.contains_key(&data.get_chunk_id().unwrap()) {
                                                    // Add this chunk info to the list
                                                    cpa.add_to_chunk_proxy(data.get_proxy_file_chunk_info().unwrap());
                                                    // Associate chunk ID with request ID
                                                    cpa.already_has.insert(data.get_chunk_id().unwrap(), data.get_request_id().unwrap());
                                                    send_and_process = true;
                                                }
                                            }

                                            // Check whether to forward chunk info
                                            if send_and_process {
                                                {
                                                    // Forward chunk info
                                                    garlic.lock().await.send_chunk_part(data.get_request_id().unwrap(), data, false).await;
                                                }

                                                // Prepare message to request chunk parts
                                                let download_chunk_msg = GarlemliaMessage::DownloadFileChunk {
                                                    sender: self_node.clone(),
                                                    request: GarlemliaFindRequest::Key { id: key, request_id: request_id.request_id }
                                                };

                                                {
                                                    // Send message to request chunk parts
                                                    if let Err(e) = message_handler.send_no_recv(&Arc::from(Arc::clone(&socket)), self_node.clone(), &sender.address, &download_chunk_msg).await {
                                                        eprintln!("Failed to send IsAlive to {}: {:?}", sender.address, e);
                                                    }
                                                }
                                            }

                                            response_data = None;
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            CloveMessage::ResponseWithValidator { request_id, proxy_id, .. } => {
                                // Get forward proxy
                                response_data = GarlemliaFunctions::iterative_find_value(&context_data,
                                                                                         GarlemliaFindRequest::Validator { id: request_id.request_id, proxy_id }).await;
                            }
                            // Storing Garlic info
                            CloveMessage::Store { data, .. } => {
                                match data.clone() {
                                    // Storing File Name information
                                    GarlemliaStoreRequest::FileName { .. } => {
                                        GarlemliaFunctions::store_value(&context_data, data, 20).await;
                                    }
                                    // Storing File Chunk info
                                    GarlemliaStoreRequest::FileChunkInfo { id , request_id, chunk_size, parts_count } => {
                                        let mut send_and_process = false;
                                        {
                                            let mut cpa = chunk_part_associations.lock().await;
                                            // Check whether we already sent this info
                                            if !cpa.already_has.contains_key(&id) {
                                                // Extrapolate pertinent information
                                                let proxy_chunk_info = ProxyFileChunkInfo {
                                                    request_id,
                                                    chunk_id: id,
                                                    chunk_size,
                                                    parts_count,
                                                    parts_info: vec![],
                                                };
                                                // Add this chunk info to the temporary list
                                                cpa.add_to_chunk_proxy(proxy_chunk_info);
                                                // Add this to our list of already having
                                                cpa.already_has.insert(id, request_id);
                                                send_and_process = true;
                                            }
                                        }

                                        // Send the store request for the chunk info
                                        if send_and_process {
                                            GarlemliaFunctions::store_value(&context_data, data, 2).await;
                                        }
                                    }
                                    // Storing a file chunk part
                                    GarlemliaStoreRequest::FileChunkPart { id, index, part_size, data } => {
                                        let mut cpa = chunk_part_associations.lock().await;
                                        // Verify whether this is actually a file chunk part that we are missing
                                        if cpa.am_proxy_for_chunk(id) {
                                            let proxy_chunk_part = ProxyChunkPartInfo {
                                                index,
                                                size: part_size,
                                                data
                                            };

                                            // Get the file chunk info and add the chunk part information
                                            let proxy_chunk_info = cpa.get_mut_chunk_proxy(id).unwrap();
                                            proxy_chunk_info.parts_info.push(proxy_chunk_part);

                                            // If we have all of the chunk parts
                                            if proxy_chunk_info.parts_info.len() == proxy_chunk_info.parts_count {
                                                // Get all chunk parts
                                                let parts_data = proxy_chunk_info.parts_info.clone();

                                                // Loop through all chunk parts
                                                for i in 0..parts_data.len() {
                                                    let mut remove_me = false;
                                                    // Check if this is the last part
                                                    if i == parts_data.len() - 1 {
                                                        // If so then set flag for removing at the end
                                                        remove_me = true;
                                                    }

                                                    // Generate appropriate request
                                                    let send_store_req = GarlemliaStoreRequest::FileChunkPart {
                                                        id,
                                                        index: parts_data[i].index,
                                                        part_size: parts_data[i].size,
                                                        data: parts_data[i].clone().data
                                                    };

                                                    // Send store request for chunk part
                                                    GarlemliaFunctions::store_value(&context_data, send_store_req, 2).await;

                                                    // Remove chunk info from list if all parts sent
                                                    if remove_me {
                                                        cpa.remove_from_chunk_proxy(id);
                                                        cpa.already_has.remove(&id);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    _ => {
                                        GarlemliaFunctions::store_value(&context_data, data, 2).await;
                                    }
                                }
                            }
                            // FileChunkPart message
                            CloveMessage::FileChunkPart { data, .. } => {
                                match data {
                                    // Verify that this is actually a chunk part
                                    GarlemliaResponse::ChunkPart { .. } => {
                                        let mut cpa = chunk_part_associations.lock().await;
                                        // Get the overall chunk ID
                                        let chunk_id = data.get_chunk_id().unwrap();
                                        // Verify that we are a proxy for the chunk part
                                        if cpa.am_proxy_for_chunk(chunk_id) {
                                            // Add chunk part to pending list of chunk parts
                                            let proxy_chunk_info = cpa.get_mut_chunk_proxy(chunk_id).unwrap();
                                            proxy_chunk_info.parts_info.push(data.get_proxy_chunk_part_info().unwrap());

                                            // Check if we have all chunk parts
                                            if proxy_chunk_info.parts_info.len() == proxy_chunk_info.parts_count {
                                                // Get all chunk parts
                                                let parts_data = proxy_chunk_info.parts_info.clone();

                                                // Loop through chunk parts
                                                for i in 0..parts_data.len() {
                                                    let mut remove_me = false;
                                                    // Check if this is final chunk part
                                                    if i == parts_data.len() - 1 {
                                                        // Final chunk part, set flag to remove
                                                        remove_me = true;
                                                    }

                                                    // Generate message for sending this chunk part
                                                    let response = GarlemliaResponse::ChunkPart {
                                                        request_id: data.get_request_id().unwrap(),
                                                        chunk_id,
                                                        part_size: parts_data[i].size,
                                                        index: parts_data[i].index,
                                                        data: parts_data[i].clone().data
                                                    };

                                                    {
                                                        // Actually send this chunk part
                                                        garlic.lock().await.send_chunk_part(data.get_request_id().unwrap(), response, remove_me).await;
                                                    }

                                                    // Remove chunk information from pending list if
                                                    // all parts sent
                                                    if remove_me {
                                                        cpa.remove_from_chunk_proxy(chunk_id);
                                                        cpa.already_has.remove(&chunk_id);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            // Garlic Cast responses
                            CloveMessage::Response { data, .. } => {
                                match data {
                                    // Initiator receiving chunk parts
                                    GarlemliaResponse::ChunkPart { .. } => {
                                        // Lock pending chunks
                                        let mut cpa = chunk_part_associations.lock().await;
                                        // Set Chunk ID info
                                        let chunk_id = data.get_chunk_id().unwrap();
                                        // Check if this is already registered as a pending chunk
                                        if cpa.am_downloading_chunk(chunk_id) {
                                            // Add the chunk part to the pending chunk part list
                                            let temp_chunk_info = cpa.get_mut_chunk_downloading(chunk_id).unwrap();
                                            temp_chunk_info.parts_info.push(data.get_chunk_part_info().unwrap());

                                            // Get the chunk part index
                                            let index = data.get_chunk_part_index().unwrap();
                                            let chunk_part_data = data.get_chunk_part_data().unwrap();

                                            {
                                                // Store the chunk part on the disk
                                                let _ = file_storage.lock().await.store_temp_chunk_part(chunk_id, index, chunk_part_data).await;
                                            }

                                            // Check if we already have all the chunk parts
                                            if temp_chunk_info.parts_info.len() == temp_chunk_info.parts_count {
                                                // Assemble entire chunk from parts
                                                let _ = file_storage.lock().await.assemble_temp_chunk(chunk_id, temp_chunk_info.parts_count).await;

                                                {
                                                    // Set the chunk flag to downloaded
                                                    garlic.lock().await.file_chunk_downloaded(data.get_request_id().unwrap(), chunk_id, sender_node).await;
                                                }
                                            }
                                        }
                                    }
                                    // Receiving file chunk info as initiator
                                    GarlemliaResponse::FileChunkInfo { .. } => {
                                        // Lock pending chunk parts info
                                        let mut cpa = chunk_part_associations.lock().await;
                                        // Check if this chunk info has already been set to pending
                                        if !cpa.already_has.contains_key(&data.get_chunk_id().unwrap()) {
                                            // Add this chunk info to pending
                                            cpa.add_to_chunk_downloads(data.get_file_chunk_info().unwrap());
                                            cpa.already_has.insert(data.get_chunk_id().unwrap(), data.get_request_id().unwrap());
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            _ => {}
                        }

                        {
                            // Forwarding on to proxy
                            send_info = garlic.lock().await.run_proxy_message(action, response_data).await;
                        }
                    }
                }

                {
                    // No longer processing, we can release the mutex lock for another thread
                    check_processing.lock().await.set(false);
                }

                // Check if we have a pending search to commit
                if send_info.is_some() {
                    // Send pending search
                    GarlicCast::send_search(Arc::clone(&socket), self_node, Arc::clone(&message_handler), send_search_nodes, send_info.unwrap()).await;
                }

                None
            }

            // Searching for a file
            GarlemliaMessage::SearchFile { request_id, proxy_id, search_term, public_key, ttl, .. } => {
                // Need to access shared memory, wait for available lock
                ProcessingCheck::wait_and_acquire(&check_processing).await;

                let already_checked;
                {
                    // Check if this is a search that we have already done
                    let mut garlic_locked = garlic.lock().await;
                    already_checked = garlic_locked.has_search_checked(request_id.clone());

                    // If we haven't already done search
                    if !already_checked {
                        // Set this to having been searched
                        garlic_locked.check_search(request_id.clone());
                    }
                }

                // Get flat routing table
                let send_search_nodes;
                {
                    send_search_nodes = routing_table.lock().await.flat_nodes().await;
                }

                let mut send_info = None;
                // See if we have already checked for this file / forwarded request
                if !already_checked {
                    // Search for this file in our storage
                    let response_data = GarlemliaFunctions::search_file(Arc::clone(&data_store), search_term.clone()).await;

                    // Forward search message
                    let new_clove_msg = CloveMessage::SearchOverlay { request_id, proxy_id, search_term, public_key, ttl };

                    {
                        // Get forward search info
                        send_info = garlic.lock().await.run_proxy_message(new_clove_msg, response_data).await;
                    }
                }

                {
                    // Stop lock on shared data
                    check_processing.lock().await.set(false);
                }

                // Check if we are forwarding
                if send_info.is_some() {
                    // Forward search
                    GarlicCast::send_search(Arc::clone(&socket), self_node, Arc::clone(&message_handler), send_search_nodes, send_info.unwrap()).await;
                }

                None
            }

            // Request for file chunk
            GarlemliaMessage::DownloadFileChunk { request, .. } => {
                // Get key / value for the request
                let key = request.get_id();
                let value = data_store.lock().await.get(&key).cloned();
                // Check if we have the value
                if value.is_some() {
                    let val = value.unwrap();

                    // Check if this really is chunk data
                    if val.is_chunk() {
                        // Get all the chunk data from the stored file
                        let chunk_data = file_storage.lock().await.get_chunk(val.get_id()).await;

                        if chunk_data.is_ok() {
                            let chunk_data_clean = chunk_data.unwrap();
                            // Generate a set of responses including the chunk info and chunk part messages
                            let response_data = val.get_chunk_responses(chunk_data_clean.clone(), request.get_request_id().unwrap()).unwrap();

                            // Actually send the chunk info and parts
                            GarlemliaFunctions::send_chunk_parts(Arc::clone(&socket), self_node.clone(),
                                                                 Arc::clone(&message_handler),
                                                                 CloveRequestID::new(request.get_request_id().unwrap(), rand::random::<u64>()),
                                                                 response_data,
                                                                 sender_node.address).await;
                        }
                    }
                } else {
                    println!("COULD NOT FIND DESIGNATED FILE CHUNK!");
                }

                None
            }

            _ => {
                None
            }
        }
    }
}