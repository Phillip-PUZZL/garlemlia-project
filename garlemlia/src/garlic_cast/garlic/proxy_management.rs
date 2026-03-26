use super::GarlicCast;

use std::sync::Arc;
use chrono::Utc;
use primitive_types::U256;
use rsa::pkcs8::EncodePublicKey;
use tokio::task::JoinHandle;
use crate::garlic_cast::garlic::clove_operations::CloveOperations;
use crate::helper_functions::helper_functions::u256_random;
use crate::structs::constants::{MIN_PROXY_COUNT, PROXY_REQUEST_MESSAGE, PROXY_RESPONSE_TIMEOUT_MS};
use crate::structs::garlic_message::{Clove, CloveMessage, CloveNode, GarlicMessage};
use crate::structs::node::Node;
use crate::garlic_cast::request_info::Proxy;

#[derive(Debug)]
pub struct ProxyDiscoveryResult {
    pub node: Node,
    pub clove: Clove,
}

pub(crate) trait ProxyManagement {
    async fn discover_proxies(&mut self, count: u8);
    async fn handle_discovery_result(&mut self, task_result: Result<Result<Node, (Node, Clove)>, tokio::task::JoinError>, sequence_number: U256) -> Result<(), ProxyDiscoveryResult>;
    fn create_discovery_tasks(
        &self,
        available_nodes: &mut Vec<Node>,
        pending_cloves: &mut Vec<Clove>,
        count: u8,
        sequence_number: U256,
    ) -> Vec<JoinHandle<Result<Node, (Node, Clove)>>>;
    fn update_cache(&mut self, new_clove: CloveNode, sequence_number: U256);
    fn replace_proxy(&mut self, old_proxy: &Proxy, new_proxy: &Proxy);
    fn remove_proxy(&mut self, proxy: &Proxy);
    fn remove_proxy_from_requests(&mut self, proxy: &Proxy);
    fn remove_proxy_from_initiator_requests(&mut self, proxy: &Proxy);
    fn filter_proxies(&self, proxy_id_pool: Vec<U256>) -> Vec<Proxy>;
}

impl ProxyManagement for GarlicCast {
    async fn discover_proxies(&mut self, count: u8) {
        let target_count = count.max(MIN_PROXY_COUNT);
        let sequence_number = u256_random();

        let proxy_request = CloveMessage::RequestProxy {
            msg: PROXY_REQUEST_MESSAGE.to_string(),
            public_key: self.public_key
                .clone()
                .unwrap()
                .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
                .unwrap(),
        };

        let mut available_nodes = self.known_nodes.clone();
        self.do_not_forward.insert(sequence_number, Utc::now());

        let mut pending_cloves = GarlicCast::generate_cloves(
            proxy_request,
            target_count,
            sequence_number,
            None,
            None,
        ).unwrap();

        let mut successful_proxies = 0;
        while successful_proxies < target_count {
            let discovery_tasks = self.create_discovery_tasks(
                &mut available_nodes,
                &mut pending_cloves,
                target_count - successful_proxies,
                sequence_number,
            );

            for task in discovery_tasks {
                match self.handle_discovery_result(task.await, sequence_number).await {
                    Ok(()) => successful_proxies += 1,
                    Err(failed_attempt) => {
                        pending_cloves.push(failed_attempt.clove);
                        self.known_nodes.retain(|x| *x != failed_attempt.node);
                    }
                }
            }
        }
    }

    async fn handle_discovery_result(
        &mut self,
        task_result: Result<Result<Node, (Node, Clove)>, tokio::task::JoinError>,
        sequence_number: U256,
    ) -> Result<(), ProxyDiscoveryResult> {
        match task_result {
            Ok(Ok(successful_node)) => {
                let new_clove = CloveNode {
                    sequence_number,
                    node: successful_node,
                };
                self.update_cache(new_clove, sequence_number);
                Ok(())
            }
            Ok(Err((failed_node, clove))) => {
                Err(ProxyDiscoveryResult { node: failed_node, clove })
            }
            Err(e) => {
                log::error!(
                "Unexpected error in proxy discovery for {}: {}",
                self.local_node.address,
                e
            );
                Err(ProxyDiscoveryResult {
                    node: self.local_node.clone(),
                    clove: Clove::default(),
                })
            }
        }
    }

    fn create_discovery_tasks(
        &self,
        available_nodes: &mut Vec<Node>,
        pending_cloves: &mut Vec<Clove>,
        count: u8,
        sequence_number: U256,
    ) -> Vec<JoinHandle<Result<Node, (Node, Clove)>>> {
        let mut tasks = Vec::new();

        for _ in 0..count {
            let socket = Arc::clone(&self.socket);
            let message_handler = Arc::clone(&self.message_handler);
            let local_node = self.local_node.clone();
            let target_node = available_nodes.remove(rand::random_range(0..available_nodes.len()));
            let clove = pending_cloves.pop().unwrap();

            tasks.push(tokio::spawn(async move {
                let find_proxy_message = GarlicMessage::FindProxy {
                    sequence_number,
                    clove: clove.clone(),
                };

                if let Err(e) = message_handler.send(
                    &Arc::from(socket.clone()),
                    local_node.clone(),
                    &target_node.address,
                    &GarlicMessage::build_send(local_node.clone(), find_proxy_message),
                ).await {
                    log::error!("Failed to send Forward to {}: {:?}", target_node.address, e);
                }

                match message_handler.recv(PROXY_RESPONSE_TIMEOUT_MS, &target_node.address).await {
                    Ok(_) => Ok(target_node),
                    _ => Err((target_node, clove))
                }
            }));
        }
        tasks
    }

    fn update_cache(&mut self, new_clove: CloveNode, sequence_number: U256) {
        self.cache.insert_next_hop(new_clove.clone(), None);
        self.cache.insert_association(sequence_number, new_clove);
        self.cache.seen(sequence_number);
    }

    /// Replaces an existing `old_proxy` with a new `new_proxy` across multiple collections within a struct.
    ///
    /// This function updates the internal state of the struct by replacing references
    /// to the given `old_proxy` with `new_proxy` in the following areas:
    /// - `proxies`: A vector holding a collection of proxies in the struct.
    /// - `initiators`: A vector that tracks proxies acting as initiators.
    /// - `requests_as_proxy`: A mapping of request IDs to requests where the proxy acts as an intermediary.
    /// - `requests_as_initiator`: A mapping of request IDs to requests where the proxy acts as an initiator.
    ///
    /// # Arguments
    ///
    /// * `old_proxy` - A reference to the `Proxy` instance that is to be replaced.
    /// * `new_proxy` - A reference to the `Proxy` instance that will replace the `old_proxy`.
    ///
    /// # Details
    ///
    /// The replacement is executed in multiple steps:
    /// 1. **Vector Updates**:
    ///    - Within `proxies` and `initiators`, `old_proxy` is removed (if found) and replaced with `new_proxy`.
    /// 2. **Proxy Requests**:
    ///    - For `requests_as_proxy`: Any requests where the `old_proxy` is the `initiator` are updated to reference `new_proxy`.
    /// 3. **Initiator Requests**:
    ///    - For `requests_as_initiator`: Any requests where the `old_proxy` exists within the `proxies` vector are updated to replace the `old_proxy` with `new_proxy`.
    ///
    ///
    /// # Example
    ///
    /// // Given `proxies`, `initiators`, and request mappings in self:
    /// // Assume `old_proxy` has sequence_number = 42 and `new_proxy` is a replacement proxy.
    /// self.replace_proxy(&old_proxy, &new_proxy);
    ///
    /// // Post execution:
    /// // - All instances of `old_proxy` with sequence_number 42 will be replaced by `new_proxy`
    /// // across the relevant collections.
    ///
    ///
    /// # Notes
    /// - The function performs deep cloning and updates to ensure all references to the old proxy are replaced.
    /// - Changes are applied consistently across multiple collections to maintain state integrity.
    ///
    /// # Assumptions
    /// - The `Proxy` struct includes a field `sequence_number` that serves as a unique identifier.
    /// - The `requests_as_proxy` and `requests_as_initiator` mappings involve deep cloning of data, which assumes
    ///   `Proxy` implements the `Clone` trait.
    fn replace_proxy(&mut self, old_proxy: &Proxy, new_proxy: &Proxy) {
        // Helper function to replace proxy in a vector
        fn replace_in_vec(proxies: &mut Vec<Proxy>, old_proxy: &Proxy, new_proxy: &Proxy) {
            if let Some(index) = proxies.iter()
                .position(|p| p.sequence_number == old_proxy.sequence_number) {
                proxies.remove(index);
                proxies.push(new_proxy.clone());
            }
        }

        // Replace it in proxies and initiator vectors
        replace_in_vec(&mut self.proxies, old_proxy, new_proxy);
        replace_in_vec(&mut self.initiators, old_proxy, new_proxy);

        // Update proxy requests
        let updates: Vec<_> = self.requests_as_proxy
            .iter()
            .filter(|(&_request_id, proxy_request)|
                proxy_request.initiator.sequence_number == old_proxy.sequence_number)
            .map(|(&request_id, proxy_request)| {
                let mut updated_request = proxy_request.clone();
                updated_request.initiator = new_proxy.clone();
                (request_id, updated_request)
            })
            .collect();

        for (request_id, updated_request) in updates {
            self.requests_as_proxy.insert(request_id, updated_request);
        }

        // Update initiator requests
        let updates: Vec<_> = self.requests_as_initiator
            .iter()
            .filter(|(&_request_id, initiator_request)|
                initiator_request.proxies.iter().any(|p| p.sequence_number == old_proxy.sequence_number))
            .map(|(&request_id, initiator_request)| {
                let mut updated_request = initiator_request.clone();
                if let Some(index) = updated_request.proxies.iter()
                    .position(|p| p.sequence_number == old_proxy.sequence_number) {
                    updated_request.proxies.remove(index);
                    updated_request.proxies.push(new_proxy.clone());
                }
                (request_id, updated_request)
            })
            .collect();

        for (request_id, updated_request) in updates {
            self.requests_as_initiator.insert(request_id, updated_request);
        }
    }

    /// Removes a proxy from multiple collections and associated data structures.
    ///
    /// This function removes a `Proxy` instance from the `proxies` and `initiators` collections
    /// based on its `sequence_number`. After removal from these collections, it also ensures
    /// the proxy is removed from associated requests and initiator requests by calling the
    /// respective helper garlemlia.
    ///
    /// # Parameters
    /// - `proxy`: A reference to the `Proxy` instance that needs to be removed.
    ///
    /// # Behavior
    /// - Searches for the given proxy in the `proxies` collection by matching its `sequence_number`.
    ///   If found, it is removed from the collection.
    /// - Searches for the given proxy in the `initiators` collection by matching its `sequence_number`.
    ///   If found, it is removed from the collection.
    /// - Calls `self.remove_proxy_from_requests()` to handle removal of the proxy from requests.
    /// - Calls `self.remove_proxy_from_initiator_requests()` to handle removal of the proxy from
    ///   initiator-specific requests.
    ///
    /// # Example
    ///
    /// let mut manager = Manager::new();
    /// let proxy = Proxy::new(42);
    /// manager.add_proxy(proxy.clone());
    ///
    /// manager.remove_proxy(&proxy);
    ///
    /// // Proxy with sequence_number `42` is removed from all relevant collections.
    ///
    ///
    /// # Notes
    /// - The function assumes that the `sequence_number` uniquely identifies a `Proxy` in the
    ///   `proxies` and `initiators` collections.
    /// - The `remove_proxy_from_requests` and `remove_proxy_from_initiator_requests` methods
    ///   should be implemented to handle cleanup of any related data.
    ///
    /// # Panics
    /// This function does not explicitly panic. However, ensure that the related helper garlemlia
    /// (`remove_proxy_from_requests` and `remove_proxy_from_initiator_requests`) handle edge cases
    /// gracefully to avoid unexpected behavior.
    fn remove_proxy(&mut self, proxy: &Proxy) {
        if let Some(index) = self.proxies.iter()
            .position(|p| p.sequence_number == proxy.sequence_number) {
            self.proxies.remove(index);
        }
        if let Some(index) = self.initiators.iter()
            .position(|p| p.sequence_number == proxy.sequence_number) {
            self.initiators.remove(index);
        }
        self.remove_proxy_from_requests(proxy);
        self.remove_proxy_from_initiator_requests(proxy);
    }

    /// Removes all request entries that were associated with the given proxy from the `requests_as_proxy` map.
    ///
    /// # Parameters
    /// - `proxy`: A reference to a `Proxy` instance. The function uses the `sequence_number`
    ///   property of the given proxy to identify and remove matching entries from the map.
    ///
    /// # How it Works
    /// - It iterates over the `requests_as_proxy` map and filters entries where the `sequence_number`
    ///   of the request matches the `sequence_number` of the given proxy.
    /// - The keys of the matching entries are collected into a vector, `keys_to_remove`.
    /// - Finally, it removes all entries in `requests_as_proxy` with the collected keys.
    ///
    /// # Example
    ///
    /// let mut object = MyStruct::new();
    /// let proxy = Proxy::new(sequence_number);
    /// object.remove_proxy_from_requests(&proxy);
    ///
    ///
    /// After calling this function, all requests in `requests_as_proxy` that correspond
    /// to the specified proxy will be removed.
    fn remove_proxy_from_requests(&mut self, proxy: &Proxy) {
        let keys_to_remove: Vec<U256> = self.requests_as_proxy
            .iter()
            .filter(|(_, req)| req.sequence_number == proxy.sequence_number)
            .map(|(key, _)| *key)
            .collect();

        for key in keys_to_remove {
            self.requests_as_proxy.remove(&key);
        }
    }

    /// Removes the given proxy from all requests where the current entity is the initiator.
    ///
    /// This function iterates over all requests in which this entity is the initiator (`requests_as_initiator`),
    /// and for each request, it checks if the specified proxy exists in the list of proxies associated with the request.
    /// If the proxy is found, it is removed from the list of proxies in the request, resulting in an updated version
    /// of the request. The updated request then replaces the original request in the `requests_as_initiator` map.
    ///
    /// # Parameters
    /// - `proxy`: A reference to the `Proxy` instance that needs to be removed from the requests.
    ///
    /// # Behavior
    /// - The function searches for the given proxy in the `proxies` list of each request by comparing
    ///   their `sequence_number`.
    /// - If the proxy exists in the list of a request, it is removed, and the modified request is created.
    /// - The `requests_as_initiator` map is then updated with the modified requests.
    ///
    /// # Example
    ///
    /// let mut some_struct = MyStruct::new(); // Assume `MyStruct` contains `requests_as_initiator`.
    /// let proxy = Proxy { sequence_number: 42 };
    ///
    /// // Removes `proxy` from all applicable initiator requests.
    /// some_struct.remove_proxy_from_initiator_requests(&proxy);
    ///
    ///
    /// # Notes
    /// - If the proxy does not exist in the `proxies` list of a request, the request remains unmodified.
    /// - Clones of the requests are made to produce updated versions, ensuring immutability of the original requests.
    ///
    fn remove_proxy_from_initiator_requests(&mut self, proxy: &Proxy) {
        let updates: Vec<_> = self.requests_as_initiator.iter()
            .filter_map(|(request_id, request)| {
                if let Some(proxy_index) = request.proxies
                    .iter()
                    .position(|p| p.sequence_number == proxy.sequence_number) {
                    let mut updated_request = request.clone();
                    updated_request.proxies.remove(proxy_index);
                    Some((*request_id, updated_request))
                } else {
                    None
                }
            })
            .collect();

        for (request_id, updated_request) in updates {
            self.requests_as_initiator.insert(request_id, updated_request);
        }
    }

    fn filter_proxies(&self, proxy_id_pool: Vec<U256>) -> Vec<Proxy> {
        self.proxies.clone()
            .into_iter()
            .filter(|proxy| proxy_id_pool.contains(&proxy.sequence_number))
            .collect()
    }
}