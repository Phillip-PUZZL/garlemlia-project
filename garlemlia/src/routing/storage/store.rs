use crate::data::garlemlia_protocol::{GarlemliaMessage, GarlemliaStoreRequest};
use crate::net::node::Node;
use crate::routing::dispatcher::garlemlia_dispatch::GarlemliaContext;
use crate::routing::lookup::iterative::Iterative;
use crate::routing::storage::local_store::LocalStore;
use crate::routing::storage::validator::Validator;
use primitive_types::U256;

pub struct Store;

impl Store {
    async fn send_store_to_node(
        context: &GarlemliaContext,
        node: &Node,
        request: &GarlemliaStoreRequest,
    ) {
        let message = GarlemliaMessage::Store {
            key: request.get_id(),
            value: request.clone(),
            sender: context.self_node.clone(),
        };

        if let Err(e) = context
            .message_handler
            .send_no_recv(
                &context.socket,
                context.self_node.clone(),
                &node.address,
                &message,
            )
            .await
        {
            eprintln!("Failed to send Store to {}: {:?}", node.address, e);
        }
    }

    pub async fn store_value(
        context: &GarlemliaContext,
        request: GarlemliaStoreRequest,
        store_count: usize,
    ) -> Vec<Node> {
        let mut closest_nodes = Iterative::find_node(context, request.get_id()).await;
        closest_nodes.truncate(store_count);

        for node in closest_nodes.clone() {
            if node.id == context.self_node.id {
                LocalStore::store_value(context, &request).await;
                continue;
            }

            Self::send_store_to_node(context, &node, &request).await;
        }

        closest_nodes
    }

    pub async fn handle_storage(
        context: &GarlemliaContext,
        sender_node: &Node,
        key: U256,
        value: GarlemliaStoreRequest,
    ) -> Option<GarlemliaMessage> {
        // Check whether this node is storing validator information
        let mut store_val = Validator::handle_storage(context, sender_node, key, &value).await;

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
            context
                .chunk_part_associations
                .lock()
                .await
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
                chunk_info
                    .parts_info
                    .push(value.get_chunk_part_info().unwrap());

                // Get the chunk part index
                let index = value.get_chunk_part_index().unwrap();
                // Get the actual chunk part data
                let chunk_part_data = value.get_chunk_part_data().unwrap();

                {
                    // Store the chunk part on the disk for later assembly
                    let _ = context
                        .file_storage
                        .lock()
                        .await
                        .store_chunk_part(chunk_id, index, chunk_part_data)
                        .await;
                }

                // Check if received all chunk parts for this chunk
                if chunk_info.parts_info.len() == chunk_info.parts_count {
                    // Assemble the whole chunk from its parts
                    let check = context
                        .file_storage
                        .lock()
                        .await
                        .assemble_chunk(chunk_id, chunk_info.parts_count)
                        .await;

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
            context
                .data_store
                .lock()
                .await
                .insert(key, store_val.clone().unwrap());
        }

        None
    }
}
