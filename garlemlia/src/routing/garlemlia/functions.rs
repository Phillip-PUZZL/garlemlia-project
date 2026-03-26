use crate::file_utils::garlemlia_files::FileStorage;
use crate::garlic_cast::garlic::file_operations::FileOperations;
use crate::garlic_cast::garlic::message_handling::MessageHandling;
use crate::garlic_cast::garlic::proxy_request::ProxyRequest;
use crate::garlic_cast::garlic::response_handling::ResponseHandling;
use crate::garlic_cast::garlic::GarlicCast;
use crate::routing::garlemlia::Garlemlia;
use crate::structs::constants::{DEFAULT_K, LOOKUP_ALPHA};
use crate::structs::file_chunks::{ChunkPartAssociations, ProcessingCheck, ProxyChunkPartInfo, ProxyFileChunkInfo};
use crate::structs::garlemlia_data::GarlemliaData;
use crate::structs::garlemlia_message::{GMessage, GarlemliaFindRequest, GarlemliaMessage, GarlemliaResponse, GarlemliaStoreRequest};
use crate::structs::garlic_message::{CloveMessage, CloveRequestID, GarlicMessage};
use crate::structs::node::Node;
use crate::structs::routing_table::RoutingTable;
use primitive_types::U256;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::task;
use tokio::time::sleep;

/// Garlemlia Context information
#[derive(Clone)]
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

enum LookupOutcome<T> {
    Continue(Vec<Node>),
    Found(T),
}

/// **Struct to store Kademlia garlemlia**
pub struct GarlemliaFunctions {}

impl GarlemliaFunctions {
    fn sort_by_distance(nodes: &mut Vec<Node>, target: U256) {
        nodes.sort_by_key(|n| n.id ^ target);
    }

    fn dedup_and_trim(nodes: &mut Vec<Node>, target: U256, self_node: &Node, limit: usize) {
        Self::sort_by_distance(nodes, target);
        nodes.dedup();
        nodes.retain(|n| n != self_node);
        nodes.truncate(limit);
    }

    fn next_nodes_to_query(top_k: &[Node], queried_nodes: &HashSet<SocketAddr>) -> Vec<Node> {
        let mut nodes: Vec<Node> = top_k
            .iter()
            .filter(|n| !queried_nodes.contains(&n.address))
            .cloned()
            .collect();

        if nodes.len() > LOOKUP_ALPHA {
            nodes.truncate(LOOKUP_ALPHA);
        }

        nodes
    }

    fn candidate_ids(nodes: &[Node]) -> HashSet<U256> {
        nodes.iter().map(|n| n.id).collect()
    }

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

    async fn query_find_node_round(context: &GarlemliaContext,
                                   target_id: U256,
                                   nodes_to_query: Vec<Node>,
                                   queried_nodes: &mut HashSet<SocketAddr>) -> Vec<Node> {
        let mut tasks = Vec::new();

        for node in nodes_to_query {
            if queried_nodes.contains(&node.address) {
                continue;
            }

            queried_nodes.insert(node.address);

            let socket = Arc::clone(&context.socket);
            let message_handler = Arc::clone(&context.message_handler);
            let self_node = context.self_node.clone();
            let node_clone = node.clone();

            tasks.push(tokio::spawn(async move {
                let message = GarlemliaMessage::FindNode {
                    id: target_id,
                    sender: self_node.clone(),
                };

                if let Err(e) = message_handler.send(&socket, self_node, &node_clone.address, &message).await {
                    eprintln!("Failed to send FindNode to {}: {:?}", node_clone.address, e);
                    return None;
                }

                match message_handler.recv(200, &node_clone.address).await {
                    Ok(GarlemliaMessage::Response { nodes, .. }) => Some(nodes),
                    _ => None,
                }
            }));
        }

        let mut new_nodes = Vec::new();
        for task in tasks {
            if let Ok(Some(nodes)) = task.await {
                new_nodes.extend(nodes);
            }
        }

        new_nodes
    }

    async fn query_find_value_round(context: &GarlemliaContext,
                                    request: GarlemliaFindRequest,
                                    nodes_to_query: Vec<Node>,
                                    queried_nodes: &mut HashSet<SocketAddr>) -> LookupOutcome<GarlemliaResponse> {
        let mut tasks = Vec::new();

        for node in nodes_to_query {
            if queried_nodes.contains(&node.address) {
                continue;
            }

            queried_nodes.insert(node.address);

            let socket = Arc::clone(&context.socket);
            let message_handler = Arc::clone(&context.message_handler);
            let self_node = context.self_node.clone();
            let node_clone = node.clone();
            let request_clone = request.clone();

            tasks.push(task::spawn(async move {
                let message = GarlemliaMessage::FindValue {
                    request: request_clone,
                    sender: self_node.clone(),
                };

                if let Err(e) = message_handler.send(&socket, self_node, &node_clone.address, &message).await {
                    eprintln!("Failed to send FindValue to {}: {:?}", node_clone.address, e);
                    return None;
                }

                match message_handler.recv(200, &node_clone.address).await {
                    Ok(GarlemliaMessage::Response { nodes, value, .. }) => {
                        if let Some(value) = value {
                            Some(LookupOutcome::Found(value))
                        } else {
                            Some(LookupOutcome::Continue(nodes))
                        }
                    }
                    _ => Some(LookupOutcome::Continue(vec![])),
                }
            }));
        }

        let mut new_nodes = Vec::new();

        for task in tasks {
            if let Ok(Some(result)) = task.await {
                match result {
                    LookupOutcome::Found(value) => return LookupOutcome::Found(value),
                    LookupOutcome::Continue(nodes) => new_nodes.extend(nodes),
                }
            }
        }

        LookupOutcome::Continue(new_nodes)
    }

    /// Basic Kademlia iterative find node implementation
    pub async fn iterative_find_node(context: &GarlemliaContext, target_id: U256) -> Vec<Node> {
        let mut queried_nodes = HashSet::new();

        let mut initial_nodes = context
            .routing_table
            .lock()
            .await
            .find_closest_nodes(target_id, LOOKUP_ALPHA)
            .await;

        Self::refresh_initial_nodes(context, &mut initial_nodes, target_id).await;

        let mut top_k = initial_nodes;
        Self::dedup_and_trim(&mut top_k, target_id, &context.self_node, DEFAULT_K);

        loop {
            let nodes_to_query = Self::next_nodes_to_query(&top_k, &queried_nodes);
            if nodes_to_query.is_empty() {
                break;
            }

            let new_nodes =
                Self::query_find_node_round(context, target_id, nodes_to_query, &mut queried_nodes).await;

            context.garlic.lock().await.update_known(new_nodes.clone());

            let old_ids = Self::candidate_ids(&top_k);

            let mut new_candidate_set = top_k.clone();
            new_candidate_set.extend(new_nodes);
            Self::dedup_and_trim(&mut new_candidate_set, target_id, &context.self_node, DEFAULT_K);

            if old_ids == Self::candidate_ids(&new_candidate_set) {
                break;
            }

            top_k = new_candidate_set;
        }

        top_k.push(context.self_node.clone());
        Self::dedup_and_trim(&mut top_k, target_id, &context.self_node, DEFAULT_K);
        top_k
    }

    /// Perform an iterative lookup for a value in the DHT - Kademlia regular implementation
    pub async fn iterative_find_value(
        context: &GarlemliaContext,
        request: GarlemliaFindRequest,
    ) -> Option<GarlemliaResponse> {
        let key = request.get_id();

        if let Some(val) = context.data_store.lock().await.get(&key).cloned() {
            return val.get_response(Some(request));
        }

        let mut queried_nodes = HashSet::new();

        let mut initial_nodes = context
            .routing_table
            .lock()
            .await
            .find_closest_nodes(key, LOOKUP_ALPHA)
            .await;

        Self::refresh_initial_nodes(context, &mut initial_nodes, key).await;

        let mut top_k = initial_nodes;
        Self::dedup_and_trim(&mut top_k, key, &context.self_node, DEFAULT_K);

        loop {
            let nodes_to_query = Self::next_nodes_to_query(&top_k, &queried_nodes);
            if nodes_to_query.is_empty() {
                break;
            }

            let old_ids = Self::candidate_ids(&top_k);

            match Self::query_find_value_round(context, request.clone(), nodes_to_query, &mut queried_nodes).await {
                LookupOutcome::Found(value) => return Some(value),
                LookupOutcome::Continue(new_nodes) => {
                    let mut new_candidate_set = top_k.clone();
                    new_candidate_set.extend(new_nodes);
                    Self::dedup_and_trim(&mut new_candidate_set, key, &context.self_node, DEFAULT_K);

                    if old_ids == Self::candidate_ids(&new_candidate_set) {
                        break;
                    }

                    top_k = new_candidate_set;
                }
            }
        }

        None
    }

    async fn send_store_to_node(context: &GarlemliaContext,
                                node: &Node,
                                request: &GarlemliaStoreRequest) {
        let message = GarlemliaMessage::Store {
            key: request.get_id(),
            value: request.clone(),
            sender: context.self_node.clone(),
        };

        if let Err(e) = context
            .message_handler
            .send_no_recv(&context.socket, context.self_node.clone(), &node.address, &message)
            .await
        {
            eprintln!("Failed to send Store to {}: {:?}", node.address, e);
        }
    }

    async fn store_local_chunk_part(context: &GarlemliaContext, request: &GarlemliaStoreRequest) {
        let chunk_id = request.get_id();
        let mut cpa = context.chunk_part_associations.lock().await;

        if !cpa.am_storing_chunk(chunk_id) {
            return;
        }

        let chunk_info = cpa.get_mut_chunk_stored(chunk_id).unwrap();
        chunk_info.parts_info.push(request.get_chunk_part_info().unwrap());

        let index = request.get_chunk_part_index().unwrap();
        let chunk_part_data = request.get_chunk_part_data().unwrap();

        let _ = context
            .file_storage
            .lock()
            .await
            .store_chunk_part(chunk_id, index, chunk_part_data)
            .await;

        if chunk_info.parts_info.len() == chunk_info.parts_count {
            let assembled = context
                .file_storage
                .lock()
                .await
                .assemble_chunk(chunk_id, chunk_info.parts_count)
                .await;

            if assembled.is_ok() {
                cpa.remove_from_chunk_storage(chunk_id);
            }
        }
    }

    async fn store_local_value(context: &GarlemliaContext, request: &GarlemliaStoreRequest) {
        let mut store_val = request.to_store_data();

        if request.is_chunk_info() {
            context
                .chunk_part_associations
                .lock()
                .await
                .add_to_chunk_storage(request.get_file_chunk_info().unwrap());
            return;
        }

        if request.is_chunk_part() {
            Self::store_local_chunk_part(context, request).await;
            return;
        }

        if let Some(mut value) = store_val.take() {
            value.store();
            context.data_store.lock().await.insert(request.get_id(), value);
        }
    }

    /// Kademlia implementation of storing values
    pub async fn store_value(
        context: &GarlemliaContext,
        request: GarlemliaStoreRequest,
        store_count: usize,
    ) -> Vec<Node> {
        let mut closest_nodes = Self::iterative_find_node(context, request.get_id()).await;
        closest_nodes.truncate(store_count);

        for node in closest_nodes.clone() {
            if node.id == context.self_node.id {
                Self::store_local_value(context, &request).await;
                continue;
            }

            Self::send_store_to_node(context, &node, &request).await;
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

    pub async fn search_file(data_store: Arc<Mutex<HashMap<U256, GarlemliaData>>>,
                             file_name: String, ) -> Option<GarlemliaResponse> {
        let ds = data_store.lock().await;

        ds.values().find_map(|data| match data {
            GarlemliaData::FileName { name, .. } if *name == file_name => data.get_response(None),
            _ => None,
        })
    }

    /// Function to match a request / response and run the appropriate action
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
        let context = GarlemliaContext::new(
            socket,
            self_node,
            routing_table,
            message_handler,
            data_store,
            garlic,
            file_storage,
            chunk_part_associations,
        );

        match msg {
            GarlemliaMessage::FindNode { id, .. } => Self::handle_find_node(&context, id).await,
            GarlemliaMessage::Store { key, value, .. } => {
                Self::handle_store(&context, &sender_node, key, value).await
            }
            GarlemliaMessage::FindValue { request, .. } => {
                Self::handle_find_value(&context, request).await
            }
            GarlemliaMessage::Garlic { msg, sender } => {
                Self::handle_garlic(&context, check_processing, sender_node, sender, msg).await
            }
            GarlemliaMessage::SearchFile {
                request_id,
                proxy_id,
                search_term,
                public_key,
                ttl,
                ..
            } => {
                Self::handle_search_file(
                    &context,
                    check_processing,
                    request_id,
                    proxy_id,
                    search_term,
                    public_key,
                    ttl,
                )
                    .await
            }
            GarlemliaMessage::DownloadFileChunk { request, .. } => {
                Self::handle_download_file_chunk(&context, sender_node, request).await
            }
            _ => None,
        }
    }

    async fn handle_find_node(context: &GarlemliaContext, id: U256) -> Option<GarlemliaMessage> {
        let nodes = if id == context.self_node.id {
            vec![context.self_node.clone()]
        } else {
            context
                .routing_table
                .lock()
                .await
                .find_closest_nodes(id, DEFAULT_K)
                .await
        };

        Some(GarlemliaMessage::Response {
            nodes,
            value: None,
            sender: context.self_node.clone(),
        })
    }

    async fn handle_validator_storage(context: &GarlemliaContext,
                                      sender_node: &Node,
                                      key: U256,
                                      value: &GarlemliaStoreRequest) -> Option<GarlemliaData> {
        let store_val;
        if value.is_validator() {
            let current;
            {
                current = context.data_store.lock().await.get(&key).cloned();
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

        store_val
    }

    async fn handle_store(context: &GarlemliaContext, sender_node: &Node,
                          key: U256, value: GarlemliaStoreRequest) -> Option<GarlemliaMessage> {
        // Check whether this node is storing validator information
        let mut store_val = Self::handle_validator_storage(context,
                                                           sender_node, key, &value).await;

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
            context.chunk_part_associations.lock().await
                .add_to_chunk_storage(value.get_file_chunk_info().unwrap());
        } else if value.is_chunk_part() {
            // Lock the pending chunk part information
            let mut cpa = context.chunk_part_associations.lock().await;
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
                    let _ = context.file_storage.lock().await
                        .store_chunk_part(chunk_id, index, chunk_part_data).await;
                }

                // Check if received all chunk parts for this chunk
                if chunk_info.parts_info.len() == chunk_info.parts_count {
                    // Assemble the whole chunk from its parts
                    let check = context.file_storage.lock().await
                        .assemble_chunk(chunk_id, chunk_info.parts_count).await;

                    // Verify that the chunk was assembled properly
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
            context.data_store.lock().await.insert(key, store_val.clone().unwrap());
        }

        None
    }

    async fn handle_find_value(
        context: &GarlemliaContext,
        request: GarlemliaFindRequest,
    ) -> Option<GarlemliaMessage> {
        let key = request.get_id();
        let value = context.data_store.lock().await.get(&key).cloned();

        if let Some(val) = value {
            if val.is_chunk() {
                let chunk_data = context.file_storage.lock().await.get_chunk(val.get_id()).await.ok()?;
                let response_info = val.get_chunk_info(
                    chunk_data,
                    request.get_request_id().unwrap(),
                    context.self_node.clone(),
                );

                return Some(GarlemliaMessage::Response {
                    nodes: vec![],
                    value: response_info,
                    sender: context.self_node.clone(),
                });
            }

            return Some(GarlemliaMessage::Response {
                nodes: vec![],
                value: val.get_response(Some(request)),
                sender: context.self_node.clone(),
            });
        }

        let closest_nodes = context
            .routing_table
            .lock()
            .await
            .find_closest_nodes(key, DEFAULT_K)
            .await;

        Some(GarlemliaMessage::Response {
            nodes: closest_nodes,
            value: None,
            sender: context.self_node.clone(),
        })
    }

    async fn maybe_send_is_alive(context: &GarlemliaContext,
                                 sender_node: &Node,
                                 msg: &GarlicMessage) {
        match msg {
            GarlicMessage::FindProxy { .. } |
            GarlicMessage::Forward { .. } |
            GarlicMessage::ProxyAgree { .. } |
            GarlicMessage::RefreshAlt { .. } |
            GarlicMessage::UpdateAlt { .. } |
            GarlicMessage::UpdateAltNextOrLast { .. } => {
                {
                    if let Err(e) = context.message_handler
                        .send_no_recv(&Arc::from(Arc::clone(&context.socket)),
                                      context.self_node.clone(),
                                      &sender_node.address,
                                      &GarlicMessage::build_send_is_alive(context.self_node
                                          .clone())).await {
                        eprintln!("Failed to send IsAlive to {}: {:?}", sender_node.address, e);
                    }
                }
            }
            _ => {}
        }
    }

    async fn handle_clove_search_overlay(context: &GarlemliaContext,
                                         request_id: CloveRequestID,
                                         proxy_id: U256,
                                         search_term: String) -> Option<GarlemliaResponse> {
        // Searching overlay, need to first generate and store validator information
        GarlemliaFunctions::store_value(&context,
                                        GarlemliaStoreRequest::Validator { id: request_id.request_id, proxy_id },
                                        3).await;

        sleep(Duration::from_millis(100)).await;

        // Send a search for a file
        GarlemliaFunctions::search_file(Arc::clone(&context.data_store), search_term.clone()).await
    }

    async fn handle_clove_search_kademlia(context: &GarlemliaContext,
                                          request_id: CloveRequestID,
                                          key: U256) -> Option<GarlemliaResponse> {
        let mut response_data;
        // Wanting to find a key, so iterative find value
        response_data = GarlemliaFunctions::iterative_find_value(&context,
                                                                 GarlemliaFindRequest::Key
                                                                 { id: key, request_id: request_id.request_id }).await;

        // Check response
        if response_data.is_some() {
            // Got data from request
            let data = response_data.clone().unwrap();
            match data.clone() {
                // Check if the response has file chunk info
                GarlemliaResponse::FileChunkInfo { sender, .. } => {
                    // Don't have all file chunk info
                    let mut send_and_process = false;
                    {
                        // Lock pending chunk info
                        let mut cpa = context.chunk_part_associations.lock().await;
                        // Check whether we already have the chunk info
                        if !cpa.already_has.contains_key(&data.get_chunk_id().unwrap()) {
                            // Add the chunk info to the list
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
                            context.garlic.lock().await.send_chunk_part(data.get_request_id().unwrap(), data, false).await;
                        }

                        // Prepare the message to request chunk parts
                        let download_chunk_msg = GarlemliaMessage::DownloadFileChunk {
                            sender: context.self_node.clone(),
                            request: GarlemliaFindRequest::Key { id: key, request_id: request_id.request_id }
                        };

                        {
                            // Send the message to request chunk parts
                            if let Err(e) = context.message_handler
                                .send_no_recv(&Arc::from(Arc::clone(&context.socket)),
                                              context.self_node.clone(),
                                              &sender.address, &download_chunk_msg).await {
                                eprintln!("Failed to send IsAlive to {}: {:?}", sender.address, e);
                            }
                        }
                    }

                    response_data = None;
                }
                _ => {}
            }
        }

        response_data
    }

    async fn handle_clove_store_chunk_info(context: &GarlemliaContext,
                                           data: GarlemliaStoreRequest,
                                           id: U256,
                                           request_id: U256,
                                           chunk_size: usize,
                                           parts_count: usize) {
        let mut send_and_process = false;
        {
            let mut cpa = context.chunk_part_associations.lock().await;
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
                // Add the chunk info to the temporary list
                cpa.add_to_chunk_proxy(proxy_chunk_info);
                // Add this to our list of already having
                cpa.already_has.insert(id, request_id);
                send_and_process = true;
            }
        }

        // Send the store request for the chunk info
        if send_and_process {
            GarlemliaFunctions::store_value(&context, data, 2).await;
        }
    }

    async fn handle_clove_store_chunk_part(context: &GarlemliaContext, id: U256, index: usize, part_size: usize, data: Vec<u8>) {
        let mut cpa = context.chunk_part_associations.lock().await;
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

            // If we have all the chunk parts
            if proxy_chunk_info.parts_info.len() == proxy_chunk_info.parts_count {
                // Get all chunk parts
                let parts_data = proxy_chunk_info.parts_info.clone();

                // Loop through all chunk parts
                for i in 0..parts_data.len() {
                    let mut remove_me = false;
                    // Check if this is the last part
                    if i == parts_data.len() - 1 {
                        // If so, then set the flag for removing at the end
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
                    GarlemliaFunctions::store_value(&context, send_store_req, 2).await;

                    // Remove chunk info from the list if all parts sent
                    if remove_me {
                        cpa.remove_from_chunk_proxy(id);
                        cpa.already_has.remove(&id);
                    }
                }
            }
        }
    }

    async fn handle_clove_store(context: &GarlemliaContext,
                                data: GarlemliaStoreRequest) {
        match data.clone() {
            // Storing File Name information
            GarlemliaStoreRequest::FileName { .. } => {
                GarlemliaFunctions::store_value(&context, data, 20).await;
            }
            // Storing File Chunk info
            GarlemliaStoreRequest::FileChunkInfo { id, request_id, chunk_size, parts_count } => {
                GarlemliaFunctions::handle_clove_store_chunk_info(context, data, id, request_id,
                                                                  chunk_size, parts_count).await;
            }
            // Storing a file chunk part
            GarlemliaStoreRequest::FileChunkPart { id, index, part_size, data } => {
                GarlemliaFunctions::handle_clove_store_chunk_part(context, id, index,
                                                                  part_size, data).await;
            }
            _ => {
                GarlemliaFunctions::store_value(&context, data, 2).await;
            }
        }
    }

    async fn handle_clove_chunk_part(context: &GarlemliaContext, data: GarlemliaResponse) {
        match data {
            // Verify that this is actually a chunk part
            GarlemliaResponse::ChunkPart { .. } => {
                let mut cpa = context.chunk_part_associations.lock().await;
                // Get the overall chunk ID
                let chunk_id = data.get_chunk_id().unwrap();
                // Verify that we are a proxy for the chunk part
                if !cpa.am_proxy_for_chunk(chunk_id) {
                    return;
                }
                // Add the chunk part to the pending list of chunk parts
                let proxy_chunk_info = cpa.get_mut_chunk_proxy(chunk_id).unwrap();
                proxy_chunk_info.parts_info.push(data.get_proxy_chunk_part_info().unwrap());

                // Check if we have all chunk parts
                if proxy_chunk_info.parts_info.len() == proxy_chunk_info.parts_count {
                    // Get all chunk parts
                    let parts_data = proxy_chunk_info.parts_info.clone();

                    // Loop through chunk parts
                    for i in 0..parts_data.len() {
                        let mut remove_me = false;
                        // Check if this is the final chunk part
                        if i == parts_data.len() - 1 {
                            // Final chunk part, set the flag to remove
                            remove_me = true;
                        }

                        // Generate the message for sending this chunk part
                        let response = GarlemliaResponse::ChunkPart {
                            request_id: data.get_request_id().unwrap(),
                            chunk_id,
                            part_size: parts_data[i].size,
                            index: parts_data[i].index,
                            data: parts_data[i].clone().data
                        };

                        {
                            // Actually send this chunk part
                            context.garlic.lock().await.send_chunk_part(data.get_request_id().unwrap(), response, remove_me).await;
                        }

                        // Remove chunk information from the pending list if
                        // all parts sent
                        if remove_me {
                            cpa.remove_from_chunk_proxy(chunk_id);
                            cpa.already_has.remove(&chunk_id);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    async fn handle_clove_response(context: &GarlemliaContext,
                                   sender_node: &Node, data: GarlemliaResponse) {
        match data {
            // Initiator receiving chunk parts
            GarlemliaResponse::ChunkPart { .. } => {
                // Lock pending chunks
                let mut cpa = context.chunk_part_associations.lock().await;
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
                        let _ = context.file_storage.lock().await.store_temp_chunk_part(chunk_id, index, chunk_part_data).await;
                    }

                    // Check if we already have all the chunk parts
                    if temp_chunk_info.parts_info.len() == temp_chunk_info.parts_count {
                        // Assemble the entire chunk from parts
                        let _ = context.file_storage.lock().await.assemble_temp_chunk(chunk_id, temp_chunk_info.parts_count).await;

                        {
                            // Set the chunk flag to downloaded
                            context.garlic.lock().await.file_chunk_downloaded(data.get_request_id().unwrap(), chunk_id, sender_node).await;
                        }
                    }
                }
            }
            // Receiving file chunk info as initiator
            GarlemliaResponse::FileChunkInfo { .. } => {
                // Lock pending chunk parts info
                let mut cpa = context.chunk_part_associations.lock().await;
                // Check if the chunk info has already been set to pending
                if !cpa.already_has.contains_key(&data.get_chunk_id().unwrap()) {
                    // Add the chunk info to pending
                    cpa.add_to_chunk_downloads(data.get_file_chunk_info().unwrap());
                    cpa.already_has.insert(data.get_chunk_id().unwrap(), data.get_request_id().unwrap());
                }
            }
            _ => {}
        }
    }

    async fn handle_clove_action(context: &GarlemliaContext,
                                 sender_node: &Node,
                                 action: CloveMessage) -> Option<GarlemliaMessage> {
        let mut response_data = None;
        match action.clone() {
            CloveMessage::SearchOverlay { request_id, proxy_id, search_term, .. } => {
                response_data = GarlemliaFunctions::handle_clove_search_overlay(context,
                                                                                request_id,
                                                                                proxy_id, search_term).await;
            }
            CloveMessage::SearchGarlemlia { key, request_id, .. } => {
                response_data = GarlemliaFunctions::handle_clove_search_kademlia(context,
                                                                                 request_id,
                                                                                 key).await;
            }
            CloveMessage::ResponseWithValidator { request_id, proxy_id, .. } => {
                // Get forward proxy
                response_data = GarlemliaFunctions::iterative_find_value(&context, GarlemliaFindRequest::Validator { id: request_id.request_id, proxy_id }).await;
            }
            // Storing Garlic info
            CloveMessage::Store { data, .. } => {
                GarlemliaFunctions::handle_clove_store(context, data).await;
            }
            // FileChunkPart message
            CloveMessage::FileChunkPart { data, .. } => {
                GarlemliaFunctions::handle_clove_chunk_part(context, data).await;
            }
            // Garlic Cast responses
            CloveMessage::Response { data, .. } => {
                GarlemliaFunctions::handle_clove_response(context, sender_node, data).await;
            }
            _ => {}
        }

        context.garlic.lock().await.run_proxy_message(action, response_data).await
    }

    async fn handle_garlic(
        context: &GarlemliaContext,
        check_processing: Arc<Mutex<ProcessingCheck>>,
        sender_node: Node,
        sender: Node,
        msg: GarlicMessage,
    ) -> Option<GarlemliaMessage> {
        Self::maybe_send_is_alive(context, &sender_node, &msg).await;

        ProcessingCheck::wait_and_acquire(&check_processing).await;

        let action_res = context.garlic.lock().await.recv(sender, msg).await;
        let send_search_nodes = context.routing_table.lock().await.flat_nodes().await;

        let send_info = match action_res {
            Ok(Some(action)) => {
                Self::handle_clove_action(context, &sender_node, action).await
            }
            _ => None,
        };

        check_processing.lock().await.set(false);

        if let Some(send_info) = send_info {
            GarlicCast::send_search(
                Arc::clone(&context.socket),
                context.self_node.clone(),
                Arc::clone(&context.message_handler),
                send_search_nodes,
                send_info,
            )
                .await;
        }

        None
    }

    async fn handle_search_file(context: &GarlemliaContext,
                                check_processing: Arc<Mutex<ProcessingCheck>>,
                                request_id: CloveRequestID,
                                proxy_id: U256,
                                search_term: String,
                                public_key: String,
                                ttl: u8) -> Option<GarlemliaMessage> {
        // Need to access shared memory, wait for available lock
        ProcessingCheck::wait_and_acquire(&check_processing).await;

        let already_checked;
        {
            // Check if this is a search that we have already done
            let mut garlic_locked = context.garlic.lock().await;
            already_checked = garlic_locked.has_search_checked(request_id.clone());

            // If we haven't already done the search
            if !already_checked {
                // Set this to having been searched
                garlic_locked.check_search(request_id.clone());
            }
        }

        // Get the flat routing table
        let send_search_nodes;
        {
            send_search_nodes = context.routing_table.lock().await.flat_nodes().await;
        }

        let mut send_info = None;
        // See if we have already checked for this file / forwarded request
        if !already_checked {
            // Search for this file in our storage
            let response_data = GarlemliaFunctions::search_file(Arc::clone(&context.data_store), search_term.clone()).await;

            // Forward search message
            let new_clove_msg = CloveMessage::SearchOverlay { request_id, proxy_id, search_term, public_key, ttl };

            {
                // Get forward search info
                send_info = context.garlic.lock().await.run_proxy_message(new_clove_msg, response_data).await;
            }
        }

        {
            // Stop the lock on shared data
            check_processing.lock().await.set(false);
        }

        // Check if we are forwarding
        if send_info.is_some() {
            // Forward search
            GarlicCast::send_search(Arc::clone(&context.socket),
                                    context.self_node.clone(),
                                    Arc::clone(&context.message_handler),
                                    send_search_nodes,
                                    send_info.unwrap()).await;
        }

        None
    }

    async fn handle_download_file_chunk(context: &GarlemliaContext,
                                        sender_node: Node,
                                        request: GarlemliaFindRequest) -> Option<GarlemliaMessage> {
        // Get key / value for the request
        let key = request.get_id();
        let value = context.data_store.lock().await.get(&key).cloned();
        // Check if we have the value
        if value.is_some() {
            let val = value.unwrap();

            // Check if this really is chunk data
            if val.is_chunk() {
                // Get all the chunk data from the stored file
                let chunk_data = context.file_storage.lock().await.get_chunk(val.get_id()).await;

                if chunk_data.is_ok() {
                    let chunk_data_clean = chunk_data.unwrap();
                    // Generate a set of responses including the chunk info and chunk part messages
                    let response_data = val.get_chunk_responses(chunk_data_clean.clone(), request.get_request_id().unwrap()).unwrap();

                    // Actually send the chunk info and parts
                    GarlemliaFunctions::send_chunk_parts(Arc::clone(&context.socket),
                                                         context.self_node.clone(),
                                                         Arc::clone(&context.message_handler),
                                                         CloveRequestID::new(request.get_request_id().unwrap(),
                                                                             rand::random::<u64>()),
                                                         response_data,
                                                         sender_node.address).await;
                }
            }
        } else {
            println!("COULD NOT FIND DESIGNATED FILE CHUNK!");
        }

        None
    }
}