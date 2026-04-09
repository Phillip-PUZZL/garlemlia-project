use crate::data::file_chunks::{ProcessingCheck, ProxyChunkPartInfo, ProxyFileChunkInfo};
use crate::data::garlemlia_protocol::{
    GarlemliaFindRequest, GarlemliaMessage, GarlemliaResponse, GarlemliaStoreRequest,
};
use crate::garlic::dispatch::message_handling::{MessageHandling, TraitMessageHandling};
use crate::garlic::files::responses::{Responses, TraitResponses};
use crate::garlic::files::transfer::{TraitTransfer, Transfer};
use crate::garlic::forwarding::proxy_runtime::{ProxyRuntime, TraitProxyRuntime};
use crate::garlic::state::garlic_cast::GarlicCast;
use crate::garlic::{CloveMessage, CloveRequestID, GarlicMessage};
use crate::net::node::Node;
use crate::routing::dispatcher::file_search::FileSearchDispatch;
use crate::routing::dispatcher::garlemlia_dispatch::{GarlemliaContext, GarlemliaDispatch};
use crate::routing::lookup::iterative::Iterative;
use crate::routing::storage::store::Store;
use primitive_types::U256;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::sleep;

pub struct GarlicBridge;
impl GarlicBridge {
    pub(crate) async fn handle_garlic(
        context: &GarlemliaContext,
        check_processing: Arc<Mutex<ProcessingCheck>>,
        sender_node: Node,
        sender: Node,
        msg: GarlicMessage,
    ) -> Option<GarlemliaMessage> {
        GarlemliaDispatch::maybe_send_is_alive(context, &sender_node, &msg).await;

        ProcessingCheck::wait_and_acquire(&check_processing).await;

        let mut garlic = context.garlic.lock().await;
        let action_res = MessageHandling::recv(&mut garlic, sender, msg).await;
        let send_search_nodes = context.routing_table.lock().await.flat_nodes().await;

        let send_info = match action_res {
            Ok(Some(action)) => Self::handle_clove_action(context, &sender_node, action).await,
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

    async fn handle_clove_search_overlay(
        context: &GarlemliaContext,
        request_id: CloveRequestID,
        proxy_id: U256,
        search_term: String,
    ) -> Option<GarlemliaResponse> {
        // Searching overlay, need to first generate and store validator information
        Store::store_value(
            &context,
            GarlemliaStoreRequest::Validator {
                id: request_id.request_id,
                proxy_id,
            },
            3,
        )
        .await;

        sleep(Duration::from_millis(100)).await;

        // Send a search for a file
        FileSearchDispatch::search_file(Arc::clone(&context.data_store), search_term.clone()).await
    }

    async fn handle_clove_search_kademlia(
        context: &GarlemliaContext,
        request_id: CloveRequestID,
        key: U256,
    ) -> Option<GarlemliaResponse> {
        let mut response_data;
        // Wanting to find a key, so iterative find value
        response_data = Iterative::find_value(
            &context,
            GarlemliaFindRequest::Key {
                id: key,
                request_id: request_id.request_id,
            },
        )
        .await;

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
                            cpa.already_has.insert(
                                data.get_chunk_id().unwrap(),
                                data.get_request_id().unwrap(),
                            );
                            send_and_process = true;
                        }
                    }

                    // Check whether to forward chunk info
                    if send_and_process {
                        {
                            // Forward chunk info
                            let mut garlic = context.garlic.lock().await;
                            Transfer::send_chunk_part(
                                &mut garlic,
                                data.get_request_id().unwrap(),
                                data,
                                false,
                            )
                            .await;
                        }

                        // Prepare the message to request chunk parts
                        let download_chunk_msg = GarlemliaMessage::DownloadFileChunk {
                            sender: context.self_node.clone(),
                            request: GarlemliaFindRequest::Key {
                                id: key,
                                request_id: request_id.request_id,
                            },
                        };

                        {
                            // Send the message to request chunk parts
                            if let Err(e) = context
                                .message_handler
                                .send_no_recv(
                                    &Arc::from(Arc::clone(&context.socket)),
                                    context.self_node.clone(),
                                    &sender.address,
                                    &download_chunk_msg,
                                )
                                .await
                            {
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

    async fn handle_clove_store_chunk_info(
        context: &GarlemliaContext,
        data: GarlemliaStoreRequest,
        id: U256,
        request_id: U256,
        chunk_size: usize,
        parts_count: usize,
    ) {
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
            Store::store_value(&context, data, 2).await;
        }
    }

    async fn handle_clove_store_chunk_part(
        context: &GarlemliaContext,
        id: U256,
        index: usize,
        part_size: usize,
        data: Vec<u8>,
    ) {
        let mut cpa = context.chunk_part_associations.lock().await;
        // Verify whether this is actually a file chunk part that we are missing
        if cpa.am_proxy_for_chunk(id) {
            let proxy_chunk_part = ProxyChunkPartInfo {
                index,
                size: part_size,
                data,
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
                        data: parts_data[i].clone().data,
                    };

                    // Send store request for chunk part
                    Store::store_value(&context, send_store_req, 2).await;

                    // Remove chunk info from the list if all parts sent
                    if remove_me {
                        cpa.remove_from_chunk_proxy(id);
                        cpa.already_has.remove(&id);
                    }
                }
            }
        }
    }

    async fn handle_clove_store(context: &GarlemliaContext, data: GarlemliaStoreRequest) {
        match data.clone() {
            // Storing File Name information
            GarlemliaStoreRequest::FileName { .. } => {
                Store::store_value(&context, data, 20).await;
            }
            // Storing File Chunk info
            GarlemliaStoreRequest::FileChunkInfo {
                id,
                request_id,
                chunk_size,
                parts_count,
            } => {
                Self::handle_clove_store_chunk_info(
                    context,
                    data,
                    id,
                    request_id,
                    chunk_size,
                    parts_count,
                )
                .await;
            }
            // Storing a file chunk part
            GarlemliaStoreRequest::FileChunkPart {
                id,
                index,
                part_size,
                data,
            } => {
                Self::handle_clove_store_chunk_part(context, id, index, part_size, data).await;
            }
            _ => {
                Store::store_value(&context, data, 2).await;
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
                proxy_chunk_info
                    .parts_info
                    .push(data.get_proxy_chunk_part_info().unwrap());

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
                            data: parts_data[i].clone().data,
                        };

                        {
                            // Actually send this chunk part
                            let mut garlic = context.garlic.lock().await;
                            Transfer::send_chunk_part(
                                &mut garlic,
                                data.get_request_id().unwrap(),
                                response,
                                remove_me,
                            )
                            .await;
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

    async fn handle_clove_response(
        context: &GarlemliaContext,
        sender_node: &Node,
        data: GarlemliaResponse,
    ) {
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
                    temp_chunk_info
                        .parts_info
                        .push(data.get_chunk_part_info().unwrap());

                    // Get the chunk part index
                    let index = data.get_chunk_part_index().unwrap();
                    let chunk_part_data = data.get_chunk_part_data().unwrap();

                    {
                        // Store the chunk part on the disk
                        let _ = context
                            .file_storage
                            .lock()
                            .await
                            .store_temp_chunk_part(chunk_id, index, chunk_part_data)
                            .await;
                    }

                    // Check if we already have all the chunk parts
                    if temp_chunk_info.parts_info.len() == temp_chunk_info.parts_count {
                        // Assemble the entire chunk from parts
                        let _ = context
                            .file_storage
                            .lock()
                            .await
                            .assemble_temp_chunk(chunk_id, temp_chunk_info.parts_count)
                            .await;

                        {
                            // Set the chunk flag to downloaded
                            let mut garlic = context.garlic.lock().await;
                            Responses::file_chunk_downloaded(
                                &mut garlic,
                                data.get_request_id().unwrap(),
                                chunk_id,
                                sender_node,
                            )
                            .await;
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
                    cpa.already_has
                        .insert(data.get_chunk_id().unwrap(), data.get_request_id().unwrap());
                }
            }
            _ => {}
        }
    }

    async fn handle_clove_action(
        context: &GarlemliaContext,
        sender_node: &Node,
        action: CloveMessage,
    ) -> Option<GarlemliaMessage> {
        let mut response_data = None;
        match action.clone() {
            CloveMessage::SearchOverlay {
                request_id,
                proxy_id,
                search_term,
                ..
            } => {
                response_data =
                    Self::handle_clove_search_overlay(context, request_id, proxy_id, search_term)
                        .await;
            }
            CloveMessage::SearchGarlemlia {
                key, request_id, ..
            } => {
                response_data = Self::handle_clove_search_kademlia(context, request_id, key).await;
            }
            CloveMessage::ResponseWithValidator {
                request_id,
                proxy_id,
                ..
            } => {
                // Get forward proxy
                response_data = Iterative::find_value(
                    &context,
                    GarlemliaFindRequest::Validator {
                        id: request_id.request_id,
                        proxy_id,
                    },
                )
                .await;
            }
            // Storing Garlic info
            CloveMessage::Store { data, .. } => {
                Self::handle_clove_store(context, data).await;
            }
            // FileChunkPart message
            CloveMessage::FileChunkPart { data, .. } => {
                Self::handle_clove_chunk_part(context, data).await;
            }
            // Garlic Cast responses
            CloveMessage::Response { data, .. } => {
                Self::handle_clove_response(context, sender_node, data).await;
            }
            _ => {}
        }

        let mut garlic = context.garlic.lock().await;
        ProxyRuntime::run_proxy_message(&mut garlic, action, response_data).await
    }
}
