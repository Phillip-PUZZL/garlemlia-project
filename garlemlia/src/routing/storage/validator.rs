use crate::data::garlemlia_data::GarlemliaData;
use crate::data::garlemlia_protocol::GarlemliaStoreRequest;
use crate::net::node::Node;
use crate::routing::dispatcher::garlemlia_dispatch::GarlemliaContext;
use primitive_types::U256;
use std::collections::HashMap;

pub struct Validator;
impl Validator {
    pub async fn handle_storage(
        context: &GarlemliaContext,
        sender_node: &Node,
        key: U256,
        value: &GarlemliaStoreRequest,
    ) -> Option<GarlemliaData> {
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
                    GarlemliaData::Validator {
                        id,
                        proxy_ids,
                        proxies,
                    } => {
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
                            proxies: new_proxies,
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
                    proxies: set_proxies,
                });
            }
        } else {
            // Get the data to store from the request
            store_val = value.to_store_data();
        }

        store_val
    }
}
