use crate::core::constants::DEFAULT_K;
use crate::data::file_chunks::{ChunkPartAssociations, ProcessingCheck};
use crate::data::garlemlia_data::GarlemliaData;
use crate::data::garlemlia_protocol::{GarlemliaFindRequest, GarlemliaMessage};
use crate::files::storage::FileStorage;
use crate::garlic::state::garlic_cast::GarlicCast;
use crate::garlic::GarlicMessage;
use crate::net::message_handler::GMessage;
use crate::net::node::Node;
use crate::routing::dispatcher::file_download::FileDownloadDispatch;
use crate::routing::dispatcher::file_search::FileSearchDispatch;
use crate::routing::dispatcher::garlic_bridge::GarlicBridge;
use crate::routing::runtime::Garlemlia;
use crate::routing::storage::store::Store;
use crate::routing::table::routing_table::RoutingTable;
use primitive_types::U256;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

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
            chunk_part_associations: Arc::clone(&garlemlia.chunk_part_associations),
        }
    }
}

pub struct GarlemliaDispatch;
impl GarlemliaDispatch {
    /// Function to match a request / response and run the appropriate action
    pub async fn run_message(
        self_node: Node,
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
    ) -> Option<GarlemliaMessage> {
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
                Store::handle_storage(&context, &sender_node, key, value).await
            }
            GarlemliaMessage::FindValue { request, .. } => {
                Self::handle_find_value(&context, request).await
            }
            GarlemliaMessage::Garlic { msg, sender } => {
                GarlicBridge::handle_garlic(&context, check_processing, sender_node, sender, msg)
                    .await
            }
            GarlemliaMessage::SearchFile {
                request_id,
                proxy_id,
                search_term,
                public_key,
                ttl,
                ..
            } => {
                FileSearchDispatch::handle_search_file(
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
                FileDownloadDispatch::handle_download_chunk(&context, sender_node, request).await
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

    async fn handle_find_value(
        context: &GarlemliaContext,
        request: GarlemliaFindRequest,
    ) -> Option<GarlemliaMessage> {
        let key = request.get_id();
        let value = context.data_store.lock().await.get(&key).cloned();

        if let Some(val) = value {
            if val.is_chunk() {
                let chunk_data = context
                    .file_storage
                    .lock()
                    .await
                    .get_chunk(val.get_id())
                    .await
                    .ok()?;
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

    pub(crate) async fn maybe_send_is_alive(
        context: &GarlemliaContext,
        sender_node: &Node,
        msg: &GarlicMessage,
    ) {
        match msg {
            GarlicMessage::FindProxy { .. }
            | GarlicMessage::Forward { .. }
            | GarlicMessage::ProxyAgree { .. }
            | GarlicMessage::RefreshAlt { .. }
            | GarlicMessage::UpdateAlt { .. }
            | GarlicMessage::UpdateAltNextOrLast { .. } => {
                if let Err(e) = context
                    .message_handler
                    .send_no_recv(
                        &Arc::from(Arc::clone(&context.socket)),
                        context.self_node.clone(),
                        &sender_node.address,
                        &GarlicMessage::build_send_is_alive(context.self_node.clone()),
                    )
                    .await
                {
                    eprintln!("Failed to send IsAlive to {}: {:?}", sender_node.address, e);
                }
            }
            _ => {}
        }
    }
}
