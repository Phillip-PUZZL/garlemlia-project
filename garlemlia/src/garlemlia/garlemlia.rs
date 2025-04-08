use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr};
use std::path::Path;
use std::sync::{Arc};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
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
use tokio::time::sleep;
use crate::file_utils::garlemlia_files::FileStorage;
use crate::garlemlia_structs::garlemlia_structs::{ChunkPartAssociations, CloveMessage, CloveRequestID, GarlemliaData, GarlemliaFindRequest, GarlemliaResponse, GarlemliaStoreRequest, GarlicMessage, ProcessingCheck, ProxyChunkPartInfo, ProxyFileChunkInfo, SOCKET_DATA_MAX};
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
                garlic.lock().await.update_known(new_nodes.clone());
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
                return val.get_response(Some(request));
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
                             chunk_part_associations: Arc<Mutex<ChunkPartAssociations>>,
                             request: GarlemliaStoreRequest, store_count: usize) -> Vec<Node> {
        // Find the closest nodes to store the value
        let mut closest_nodes = GarlemliaFunctions::iterative_find_node(Arc::clone(&socket), self_node.clone(), Arc::clone(&routing_table), Arc::clone(&message_handler), Arc::clone(&garlic), request.get_id()).await;
        closest_nodes.truncate(store_count);

        for node in closest_nodes.clone() {
            if node.id == self_node.id {
                let mut store_val = request.to_store_data();

                if request.is_chunk_info() {
                    chunk_part_associations.lock().await.add_store_chunk(request.get_file_chunk_info().unwrap());
                } else if request.is_chunk_part() {
                    let mut cpa = chunk_part_associations.lock().await;
                    let chunk_id = request.get_id();
                    if cpa.is_store_chunk(chunk_id) {
                        let chunk_info = cpa.get_store_chunk_mut(chunk_id).unwrap();
                        chunk_info.parts_info.push(request.get_chunk_part_info().unwrap());

                        let index = request.get_chunk_part_index().unwrap();
                        let chunk_part_data = request.get_chunk_part_data().unwrap();

                        {
                            let _ = file_storage.lock().await.store_chunk_part(chunk_id, index, chunk_part_data).await;
                        }

                        if chunk_info.parts_info.len() == chunk_info.parts_count {
                            let check = file_storage.lock().await.assemble_chunk(chunk_id, chunk_info.parts_count).await;

                            if check.is_ok() {
                                cpa.remove_store_chunk(chunk_id);
                            }
                        }
                    }

                    store_val = None;
                }
                
                if store_val.is_some() {
                    let mut check = store_val.unwrap();
                    check.store();
                    
                    store_val = Some(check);
                }

                // Store the value locally if this node is among the closest
                if store_val.is_some() {
                    data_store.lock().await.insert(request.get_id(), store_val.unwrap());
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

    pub async fn send_chunk_parts(socket: Arc<UdpSocket>,
                                  self_node: Node,
                                  message_handler: Arc<Box<dyn GMessage>>,
                                  request_id: CloveRequestID,
                                  chunks: Vec<GarlemliaResponse>,
                                  requester: SocketAddr) {
        for chunk in chunks {
            sleep(Duration::from_millis(200)).await;
            let response = GarlemliaMessage::Garlic {
                sender: self_node.clone(),
                msg: GarlicMessage::FileChunkPart {
                    request_id: request_id.clone(),
                    data: chunk.clone(),
                }
            };

            {
                if let Err(e) = message_handler.send_no_recv(&Arc::clone(&socket), self_node.clone(), &requester, &response).await {
                    eprintln!("Failed to send SearchFile to {}: {:?}", requester, e);
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

                if value.is_chunk_info() {
                    chunk_part_associations.lock().await.add_store_chunk(value.get_file_chunk_info().unwrap());
                } else if value.is_chunk_part() {
                    let mut cpa = chunk_part_associations.lock().await;
                    let chunk_id = value.get_id();
                    if cpa.is_store_chunk(chunk_id) {
                        let chunk_info = cpa.get_store_chunk_mut(chunk_id).unwrap();
                        chunk_info.parts_info.push(value.get_chunk_part_info().unwrap());

                        let index = value.get_chunk_part_index().unwrap();
                        let chunk_part_data = value.get_chunk_part_data().unwrap();

                        {
                            let _ = file_storage.lock().await.store_chunk_part(chunk_id, index, chunk_part_data).await;
                        }

                        if chunk_info.parts_info.len() == chunk_info.parts_count {
                            let check = file_storage.lock().await.assemble_chunk(chunk_id, chunk_info.parts_count).await;

                            if check.is_ok() {
                                cpa.remove_store_chunk(chunk_id);
                            }
                        }
                    }

                    store_val = None;
                }

                if store_val.is_some() {
                    data_store.lock().await.insert(key, store_val.clone().unwrap());
                }

                match value {
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
                                GarlemliaFunctions::iterative_find_node(get_global_socket().unwrap(), self_node.clone(),
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
                }

                None
            }

            // Use find_closest_nodes() if value is not found
            GarlemliaMessage::FindValue { request, .. } => {
                let key = request.get_id();
                let value = data_store.lock().await.get(&key).cloned();

                let mut response = None;

                if value.is_some() {
                    let val = value.unwrap();

                    if val.is_chunk() {
                        let chunk_data = file_storage.lock().await.get_chunk(val.get_id()).await;

                        if chunk_data.is_ok() {
                            let chunk_data_clean = chunk_data.unwrap();
                            let response_info = val.get_chunk_info(chunk_data_clean.clone(), request.get_request_id().unwrap(), self_node.clone());

                            response = Some(GarlemliaMessage::Response {
                                nodes: vec![],
                                value: response_info,
                                sender: self_node.clone(),
                            });
                        }
                    } else {
                        response = Some(GarlemliaMessage::Response {
                            nodes: vec![],
                            value: val.get_response(Some(request)),
                            sender: self_node.clone(),
                        });
                    }
                } else {
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

                loop {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    let mut check = check_processing.lock().await;
                    if !check.check() {
                        check.set(true);
                        break;
                    }
                }

                let action_res;
                {
                    action_res = garlic.lock().await.recv(sender, msg).await;
                }

                let send_search_nodes;
                {
                    send_search_nodes = routing_table.lock().await.flat_nodes().await;
                }

                let mut send_info = None;
                if action_res.is_ok() {
                    let action_opt = action_res.unwrap();
                    if action_opt.is_some() {
                        let action = action_opt.unwrap();

                        let mut response_data = None;
                        match action.clone() {
                            CloveMessage::SearchOverlay { request_id, proxy_id, search_term, .. } => {
                                GarlemliaFunctions::store_value(Arc::clone(&socket), self_node.clone(),
                                                                Arc::clone(&routing_table),
                                                                Arc::clone(&message_handler),
                                                                Arc::clone(&data_store),
                                                                Arc::clone(&garlic),
                                                                Arc::clone(&file_storage),
                                                                Arc::clone(&chunk_part_associations),
                                                                GarlemliaStoreRequest::Validator { id: request_id.request_id, proxy_id },
                                                                3).await;

                                sleep(Duration::from_millis(100)).await;

                                response_data = GarlemliaFunctions::search_file(Arc::clone(&data_store), search_term.clone()).await;
                            }
                            CloveMessage::SearchGarlemlia { key, request_id, .. } => {
                                response_data = GarlemliaFunctions::iterative_find_value(Arc::clone(&socket), self_node.clone(),
                                                                                         Arc::clone(&routing_table),
                                                                                         Arc::clone(&message_handler),
                                                                                         Arc::clone(&data_store),
                                                                                         GarlemliaFindRequest::Key { id: key, request_id: request_id.request_id }).await;

                                if response_data.is_some() {
                                    let data = response_data.clone().unwrap();
                                    match data.clone() {
                                        GarlemliaResponse::FileChunkInfo { sender, .. } => {
                                            let mut send_and_process = false;
                                            {
                                                let mut cpa = chunk_part_associations.lock().await;
                                                if !cpa.already_has.contains_key(&data.get_chunk_id().unwrap()) {
                                                    cpa.add_proxy_chunk(data.get_proxy_file_chunk_info().unwrap());
                                                    cpa.already_has.insert(data.get_chunk_id().unwrap(), data.get_request_id().unwrap());
                                                    send_and_process = true;
                                                }
                                            }

                                            if send_and_process {
                                                {
                                                    garlic.lock().await.send_chunk_part(data.get_request_id().unwrap(), data, false).await;
                                                }

                                                let download_chunk_msg = GarlemliaMessage::DownloadFileChunk {
                                                    sender: self_node.clone(),
                                                    request: GarlemliaFindRequest::Key { id: key, request_id: request_id.request_id }
                                                };

                                                {
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
                                response_data = GarlemliaFunctions::iterative_find_value(Arc::clone(&socket), self_node.clone(),
                                                                                         Arc::clone(&routing_table),
                                                                                         Arc::clone(&message_handler),
                                                                                         Arc::clone(&data_store),
                                                                                         GarlemliaFindRequest::Validator { id: request_id.request_id, proxy_id }).await;
                            }
                            CloveMessage::Store { data, .. } => {
                                match data.clone() {
                                    GarlemliaStoreRequest::FileName { .. } => {
                                        GarlemliaFunctions::store_value(Arc::clone(&socket), self_node.clone(),
                                                                        Arc::clone(&routing_table),
                                                                        Arc::clone(&message_handler),
                                                                        Arc::clone(&data_store),
                                                                        Arc::clone(&garlic),
                                                                        Arc::clone(&file_storage),
                                                                        Arc::clone(&chunk_part_associations),
                                                                        data,
                                                                        20).await;
                                    }
                                    GarlemliaStoreRequest::FileChunkInfo { id , request_id, chunk_size, parts_count } => {
                                        let mut send_and_process = false;
                                        {
                                            let mut cpa = chunk_part_associations.lock().await;
                                            if !cpa.already_has.contains_key(&id) {
                                                let proxy_chunk_info = ProxyFileChunkInfo {
                                                    request_id,
                                                    chunk_id: id,
                                                    chunk_size,
                                                    parts_count,
                                                    parts_info: vec![],
                                                };
                                                cpa.add_proxy_chunk(proxy_chunk_info);
                                                cpa.already_has.insert(id, request_id);
                                                send_and_process = true;
                                            }
                                        }

                                        if send_and_process {
                                            GarlemliaFunctions::store_value(Arc::clone(&socket), self_node.clone(),
                                                                            Arc::clone(&routing_table),
                                                                            Arc::clone(&message_handler),
                                                                            Arc::clone(&data_store),
                                                                            Arc::clone(&garlic),
                                                                            Arc::clone(&file_storage),
                                                                            Arc::clone(&chunk_part_associations),
                                                                            data,
                                                                            2).await;
                                        }
                                    }
                                    GarlemliaStoreRequest::FileChunkPart { id, index, part_size, data } => {
                                        let mut cpa = chunk_part_associations.lock().await;
                                        if cpa.is_proxy_chunk(id) {
                                            let proxy_chunk_part = ProxyChunkPartInfo {
                                                index,
                                                size: part_size,
                                                data
                                            };

                                            let proxy_chunk_info = cpa.get_proxy_chunk_mut(id).unwrap();
                                            proxy_chunk_info.parts_info.push(proxy_chunk_part);

                                            if proxy_chunk_info.parts_info.len() == proxy_chunk_info.parts_count {
                                                let parts_data = proxy_chunk_info.parts_info.clone();

                                                for i in 0..parts_data.len() {
                                                    let mut remove_me = false;
                                                    if i == parts_data.len() - 1 {
                                                        remove_me = true;
                                                    }

                                                    let send_store_req = GarlemliaStoreRequest::FileChunkPart {
                                                        id,
                                                        index: parts_data[i].index,
                                                        part_size: parts_data[i].size,
                                                        data: parts_data[i].clone().data
                                                    };

                                                    GarlemliaFunctions::store_value(Arc::clone(&socket), self_node.clone(),
                                                                                    Arc::clone(&routing_table),
                                                                                    Arc::clone(&message_handler),
                                                                                    Arc::clone(&data_store),
                                                                                    Arc::clone(&garlic),
                                                                                    Arc::clone(&file_storage),
                                                                                    Arc::clone(&chunk_part_associations),
                                                                                    send_store_req,
                                                                                    2).await;

                                                    if remove_me {
                                                        cpa.remove_proxy_chunk(id);
                                                        cpa.already_has.remove(&id);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    _ => {
                                        GarlemliaFunctions::store_value(Arc::clone(&socket), self_node.clone(),
                                                                        Arc::clone(&routing_table),
                                                                        Arc::clone(&message_handler),
                                                                        Arc::clone(&data_store),
                                                                        Arc::clone(&garlic),
                                                                        Arc::clone(&file_storage),
                                                                        Arc::clone(&chunk_part_associations),
                                                                        data,
                                                                        2).await;
                                    }
                                }
                            }
                            CloveMessage::FileChunkPart { data, .. } => {
                                match data {
                                    GarlemliaResponse::ChunkPart { .. } => {
                                        let mut cpa = chunk_part_associations.lock().await;
                                        let chunk_id = data.get_chunk_id().unwrap();
                                        if cpa.is_proxy_chunk(chunk_id) {
                                            let proxy_chunk_info = cpa.get_proxy_chunk_mut(chunk_id).unwrap();
                                            proxy_chunk_info.parts_info.push(data.get_proxy_chunk_part_info().unwrap());

                                            if proxy_chunk_info.parts_info.len() == proxy_chunk_info.parts_count {
                                                let parts_data = proxy_chunk_info.parts_info.clone();

                                                for i in 0..parts_data.len() {
                                                    let mut remove_me = false;
                                                    if i == parts_data.len() - 1 {
                                                        remove_me = true;
                                                    }

                                                    let response = GarlemliaResponse::ChunkPart {
                                                        request_id: data.get_request_id().unwrap(),
                                                        chunk_id,
                                                        part_size: parts_data[i].size,
                                                        index: parts_data[i].index,
                                                        data: parts_data[i].clone().data
                                                    };

                                                    {
                                                        garlic.lock().await.send_chunk_part(data.get_request_id().unwrap(), response, remove_me).await;
                                                    }

                                                    if remove_me {
                                                        cpa.remove_proxy_chunk(chunk_id);
                                                        cpa.already_has.remove(&chunk_id);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            CloveMessage::Response { data, .. } => {
                                match data {
                                    GarlemliaResponse::ChunkPart { .. } => {
                                        let mut cpa = chunk_part_associations.lock().await;
                                        let chunk_id = data.get_chunk_id().unwrap();
                                        if cpa.is_temp_chunk(chunk_id) {
                                            let temp_chunk_info = cpa.get_temp_chunk_mut(chunk_id).unwrap();
                                            temp_chunk_info.parts_info.push(data.get_chunk_part_info().unwrap());

                                            let index = data.get_chunk_part_index().unwrap();
                                            let chunk_part_data = data.get_chunk_part_data().unwrap();

                                            {
                                                let _ = file_storage.lock().await.store_temp_chunk_part(chunk_id, index, chunk_part_data).await;
                                            }

                                            if temp_chunk_info.parts_info.len() == temp_chunk_info.parts_count {
                                                let _ = file_storage.lock().await.assemble_temp_chunk(chunk_id, temp_chunk_info.parts_count).await;

                                                {
                                                    garlic.lock().await.file_chunk_downloaded(data.get_request_id().unwrap(), chunk_id, sender_node).await;
                                                }
                                            }
                                        }
                                    }
                                    GarlemliaResponse::FileChunkInfo { .. } => {
                                        let mut cpa = chunk_part_associations.lock().await;
                                        if !cpa.already_has.contains_key(&data.get_chunk_id().unwrap()) {
                                            cpa.add_temp_chunk(data.get_file_chunk_info().unwrap());
                                            cpa.already_has.insert(data.get_chunk_id().unwrap(), data.get_request_id().unwrap());
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            _ => {}
                        }

                        {
                            send_info = garlic.lock().await.run_proxy_message(action, response_data).await;
                        }
                    }
                }

                {
                    check_processing.lock().await.set(false);
                }

                if send_info.is_some() {
                    GarlicCast::send_search(Arc::clone(&socket), self_node, Arc::clone(&message_handler), send_search_nodes, send_info.unwrap()).await;
                }

                None
            }

            GarlemliaMessage::SearchFile { request_id, proxy_id, search_term, public_key, ttl, .. } => {
                loop {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    let mut check = check_processing.lock().await;
                    if !check.check() {
                        check.set(true);
                        break;
                    }
                }

                let already_checked;
                {
                    let mut garlic_locked = garlic.lock().await;
                    already_checked = garlic_locked.has_search_checked(request_id.clone());

                    if !already_checked {
                        garlic_locked.check_search(request_id.clone());
                    }
                }

                let send_search_nodes;
                {
                    send_search_nodes = routing_table.lock().await.flat_nodes().await;
                }

                let mut send_info = None;
                if !already_checked {
                    let response_data = GarlemliaFunctions::search_file(Arc::clone(&data_store), search_term.clone()).await;

                    let new_clove_msg = CloveMessage::SearchOverlay { request_id, proxy_id, search_term, public_key, ttl };

                    {
                        send_info = garlic.lock().await.run_proxy_message(new_clove_msg, response_data).await;
                    }
                }

                {
                    check_processing.lock().await.set(false);
                }

                if send_info.is_some() {
                    GarlicCast::send_search(Arc::clone(&socket), self_node, Arc::clone(&message_handler), send_search_nodes, send_info.unwrap()).await;
                }

                None
            }

            GarlemliaMessage::DownloadFileChunk { request, .. } => {
                let key = request.get_id();
                let value = data_store.lock().await.get(&key).cloned();
                if value.is_some() {
                    let val = value.unwrap();

                    if val.is_chunk() {
                        let chunk_data = file_storage.lock().await.get_chunk(val.get_id()).await;

                        if chunk_data.is_ok() {
                            let chunk_data_clean = chunk_data.unwrap();
                            let response_data = val.get_chunk_responses(chunk_data_clean.clone(), request.get_request_id().unwrap()).unwrap();

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
    pub chunk_part_associations: Arc<Mutex<ChunkPartAssociations>>,
    is_processing: Arc<Mutex<ProcessingCheck>>,
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
            chunk_part_associations: Arc::new(Mutex::new(ChunkPartAssociations::new())),
            is_processing: Arc::new(Mutex::new(ProcessingCheck::new(false))),
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
            chunk_part_associations: Arc::new(Mutex::new(ChunkPartAssociations::new())),
            is_processing: Arc::new(Mutex::new(ProcessingCheck::new(false))),
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
        self.garlic.lock().await.update_from(gc);
    }
    

    async fn get_node(&self) -> Node {
        let node;
        {
            node = self.node.lock().await;
        }
        node.clone()
    }

    async fn process_message(self_node: Node,
                             socket: Arc<UdpSocket>,
                             message_handler: Arc<Box<dyn GMessage>>,
                             routing_table: Arc<Mutex<RoutingTable>>,
                             data_store: Arc<Mutex<HashMap<U256, GarlemliaData>>>,
                             garlic: Arc<Mutex<GarlicCast>>,
                             file_storage: Arc<Mutex<FileStorage>>,
                             chunk_part_associations: Arc<Mutex<ChunkPartAssociations>>,
                             check_processing: Arc<Mutex<ProcessingCheck>>,
                             msg: GarlemliaMessage,
                             sender_node: Node,
                             src: SocketAddr) {
        match msg.clone() {
            GarlemliaMessage::Ping { .. } => {
                if let Err(e) = message_handler.send_no_recv(&socket, self_node.clone(), &src, &GarlemliaMessage::Pong { sender: self_node.clone() }).await {
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

            GarlemliaMessage::Response { nodes, value, sender, .. } => {
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

            _ => {
                {
                    routing_table.lock().await.add_node_from_responder(Arc::clone(&message_handler), sender_node.clone(), Arc::clone(&socket)).await;
                }

                let response = GarlemliaFunctions::run_message(self_node.clone(),
                                                               Arc::clone(&socket),
                                                               Arc::clone(&message_handler),
                                                               routing_table,
                                                               Arc::clone(&data_store),
                                                               garlic,
                                                               Arc::clone(&file_storage),
                                                               chunk_part_associations,
                                                               check_processing,
                                                               msg.clone(),
                                                               sender_node.clone()).await;

                if response.is_some() {
                    if let Err(e) = message_handler.send_no_recv(&socket, self_node.clone(), &src, &response.unwrap()).await {
                        eprintln!("Failed to send response to {}: {:?}", src, e);
                    }
                }
            }
        }
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
        let chunk_part_associations = Arc::clone(&self.chunk_part_associations);
        let check_processing = Arc::clone(&self.is_processing);
        let stop_clone = Arc::clone(&self.stop_signal);
        println!("STARTING {}", socket.local_addr().unwrap());

        let handle = tokio::spawn(async move {
            let mut buf = [0; SOCKET_DATA_MAX];
            while !stop_clone.load(Ordering::Relaxed) {
                if let Ok((size, src)) = socket.recv_from(&mut buf).await {
                    let self_ref;
                    {
                        self_ref = self_node.lock().await.clone();
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
                        GarlemliaMessage::Stop {} => {
                            if sender_node.address == self_ref.address {
                                break;
                            }
                        }
                        _ => {}
                    }

                    let self_node_clone = self_node.lock().await.clone();
                    let socket_clone = Arc::clone(&socket);
                    let message_handler_clone = Arc::clone(&message_handler);
                    let routing_table_clone = Arc::clone(&routing_table);
                    let data_store_clone = Arc::clone(&data_store);
                    let garlic_clone = Arc::clone(&garlic);
                    let file_storage_clone = Arc::clone(&file_storage);
                    let chunk_part_associations_clone = Arc::clone(&chunk_part_associations);
                    let check_processing_clone = Arc::clone(&check_processing);

                    tokio::spawn(async move {
                        Garlemlia::process_message(self_node_clone,
                                                   socket_clone,
                                                   message_handler_clone,
                                                   routing_table_clone,
                                                   data_store_clone,
                                                   garlic_clone,
                                                   file_storage_clone,
                                                   chunk_part_associations_clone,
                                                   check_processing_clone,
                                                   msg,
                                                   sender_node,
                                                   src).await;
                    });
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
                                        Arc::clone(&self.chunk_part_associations),
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
            match response.unwrap() {
                GarlemliaMessage::Response { nodes, .. } => {
                    for node in nodes {
                        if node.id != self_node.id {
                            self.routing_table.lock().await.add_node(Arc::clone(&self.message_handler), node, &*socket_clone.clone()).await;
                        }
                    }
                }
                _ => {}
            }

            self.iterative_find_node(socket_clone.clone(), self_node.id).await;
            self.refresh_buckets(socket_clone).await;
        } else {
            println!("FAILED TO JOIN NETWORK");
        }
    }

    pub async fn join_network_no_refresh(&mut self, socket: Arc<UdpSocket>, target: &SocketAddr) {
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
            match response.unwrap() {
                GarlemliaMessage::Response { nodes, .. } => {
                    for node in nodes {
                        if node.id != self_node.id {
                            self.routing_table.lock().await.add_node(Arc::clone(&self.message_handler), node, &*socket_clone.clone()).await;
                        }
                    }
                }
                _ => {}
            }

            self.iterative_find_node(socket_clone.clone(), self_node.id).await;
        } else {
            println!("FAILED TO JOIN NETWORK");
        }
    }
}