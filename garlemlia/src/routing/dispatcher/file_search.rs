use crate::data::file_chunks::ProcessingCheck;
use crate::data::garlemlia_data::GarlemliaData;
use crate::data::garlemlia_protocol::{GarlemliaMessage, GarlemliaResponse};
use crate::garlic::forwarding::proxy_runtime::{ProxyRuntime, TraitProxyRuntime};
use crate::garlic::state::garlic_cast::GarlicCast;
use crate::garlic::{CloveMessage, CloveRequestID};
use crate::routing::dispatcher::garlemlia_dispatch::GarlemliaContext;
use primitive_types::U256;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct FileSearchDispatch;
impl FileSearchDispatch {
    pub async fn search_file(
        data_store: Arc<Mutex<HashMap<U256, GarlemliaData>>>,
        file_name: String,
    ) -> Option<GarlemliaResponse> {
        let ds = data_store.lock().await;

        ds.values().find_map(|data| match data {
            GarlemliaData::FileName { name, .. } if *name == file_name => data.get_response(None),
            _ => None,
        })
    }
    pub async fn handle_search_file(
        context: &GarlemliaContext,
        check_processing: Arc<Mutex<ProcessingCheck>>,
        request_id: CloveRequestID,
        proxy_id: U256,
        search_term: String,
        public_key: String,
        ttl: u8,
    ) -> Option<GarlemliaMessage> {
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
            let response_data =
                Self::search_file(Arc::clone(&context.data_store), search_term.clone()).await;

            // Forward search message
            let new_clove_msg = CloveMessage::SearchOverlay {
                request_id,
                proxy_id,
                search_term,
                public_key,
                ttl,
            };

            {
                // Get forward search info
                let mut garlic = context.garlic.lock().await;
                send_info =
                    ProxyRuntime::run_proxy_message(&mut garlic, new_clove_msg, response_data)
                        .await;
            }
        }

        {
            // Stop the lock on shared data
            check_processing.lock().await.set(false);
        }

        // Check if we are forwarding
        if send_info.is_some() {
            // Forward search
            GarlicCast::send_search(
                Arc::clone(&context.socket),
                context.self_node.clone(),
                Arc::clone(&context.message_handler),
                send_search_nodes,
                send_info.unwrap(),
            )
            .await;
        }

        None
    }
}
