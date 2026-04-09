use crate::data::garlemlia_protocol::{GarlemliaFindRequest, GarlemliaMessage, GarlemliaResponse};
use crate::garlic::{CloveRequestID, GarlicMessage};
use crate::net::message_handler::GMessage;
use crate::net::node::Node;
use crate::routing::dispatcher::garlemlia_dispatch::GarlemliaContext;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::sleep;

pub struct FileDownloadDispatch;
impl FileDownloadDispatch {
    pub async fn handle_download_chunk(
        context: &GarlemliaContext,
        sender_node: Node,
        request: GarlemliaFindRequest,
    ) -> Option<GarlemliaMessage> {
        // Get key / value for the request
        let key = request.get_id();
        let value = context.data_store.lock().await.get(&key).cloned();
        // Check if we have the value
        if value.is_some() {
            let val = value.unwrap();

            // Check if this really is chunk data
            if val.is_chunk() {
                // Get all the chunk data from the stored file
                let chunk_data = context
                    .file_storage
                    .lock()
                    .await
                    .get_chunk(val.get_id())
                    .await;

                if chunk_data.is_ok() {
                    let chunk_data_clean = chunk_data.unwrap();
                    // Generate a set of responses including the chunk info and chunk part messages
                    let response_data = val
                        .get_chunk_responses(
                            chunk_data_clean.clone(),
                            request.get_request_id().unwrap(),
                        )
                        .unwrap();

                    // Actually send the chunk info and parts
                    FileDownloadDispatch::send_chunk_parts(
                        Arc::clone(&context.socket),
                        context.self_node.clone(),
                        Arc::clone(&context.message_handler),
                        CloveRequestID::new(
                            request.get_request_id().unwrap(),
                            rand::random::<u64>(),
                        ),
                        response_data,
                        sender_node.address,
                    )
                    .await;
                }
            }
        } else {
            println!("COULD NOT FIND DESIGNATED FILE CHUNK!");
        }

        None
    }

    pub async fn send_chunk_parts(
        socket: Arc<UdpSocket>,
        self_node: Node,
        message_handler: Arc<Box<dyn GMessage>>,
        request_id: CloveRequestID,
        chunks: Vec<GarlemliaResponse>,
        requester: SocketAddr,
    ) {
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
                },
            };

            {
                // Send Message
                if let Err(e) = message_handler
                    .send_no_recv(
                        &Arc::clone(&socket),
                        self_node.clone(),
                        &requester,
                        &response,
                    )
                    .await
                {
                    eprintln!("Failed to send Chunk Part to {}: {:?}", requester, e);
                }
            }
        }
    }
}
