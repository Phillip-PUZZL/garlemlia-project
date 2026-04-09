use crate::core::{u256_random, MessageError};
use crate::data::garlemlia_protocol::{GarlemliaMessage, GarlemliaResponse};
use crate::garlic::crypto::sharding::Sharding;
use crate::garlic::forwarding::alt_routes::{AltRoutes, TraitAltRoutes};
use crate::garlic::forwarding::forwarding::{Forwarding, TraitForwarding};
use crate::garlic::forwarding::proxy_discovery::{ProxyDiscovery, TraitProxyDiscovery};
use crate::garlic::state::garlic_cast::GarlicCast;
use crate::garlic::state::request_state::{InitiatorRequest, Proxy};
use crate::garlic::{
    Clove, CloveMessage, CloveNode, CloveProtocol, CloveRequestID, GarlicMessage,
    TraitCloveProtocol,
};
use crate::net::node::Node;
use chrono::Utc;
use primitive_types::U256;
use rand::prelude::IndexedRandom;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;
use std::sync::Arc;
use tokio::task::JoinHandle;

pub(crate) trait TraitProxyRuntime {
    // validator pool creations or searches
    async fn run_proxy_message(
        garlic: &mut GarlicCast,
        req: CloveMessage,
        response: Option<GarlemliaResponse>,
    ) -> Option<GarlemliaMessage>;
    async fn manage_proxy_message(req: CloveMessage) -> Option<CloveMessage>;
    async fn accept_proxy(
        garlic: &mut GarlicCast,
        sequence_number: U256,
        second_clove: Clove,
        node: Node,
    ) -> Result<Proxy, MessageError>;
    fn update_proxy(garlic: &mut GarlicCast, old_proxy: Proxy, new_proxy: Proxy) -> Proxy;
    async fn handle_proxy_forwarding(
        garlic: &mut GarlicCast,
        forward_type: u8,
        proxy: Proxy,
        cloves: Vec<Clove>,
    ) -> Option<Proxy>;
    async fn spawn_proxy_task(
        garlic: &GarlicCast,
        msg: CloveMessage,
        proxy_id: U256,
        temp_proxy: Proxy,
        request_id_full: CloveRequestID,
    ) -> JoinHandle<Result<(U256, Proxy), (u8, Proxy, Vec<Clove>, U256)>>;
    async fn handle_proxy_task_result(
        garlic: &mut GarlicCast,
        task: JoinHandle<Result<(U256, Proxy), (u8, Proxy, Vec<Clove>, U256)>>,
        proxy_request: &mut InitiatorRequest,
    ) -> Result<(), String>;
}

pub struct ProxyRuntime;
impl TraitProxyRuntime for ProxyRuntime {
    /// Handles proxy message processing for the validator pool by interpreting incoming `CloveMessage`
    /// requests and generating appropriate responses or actions.
    ///
    /// This function takes a clone of the incoming `CloveMessage` request and an optional associated response
    /// to determine the required operation. Depending on the message type (`SearchOverlay`, `SearchGarlemlia`,
    /// `ResponseWithValidator`, `Store`, etc.), it constructs and sends messages, updates proxy actions,
    /// or handles request expirations.
    ///
    /// # Parameters
    /// - `garlic`: A mutable reference to the current instance of the validator pool.
    /// - `req`: The incoming `CloveMessage` request to process.
    /// - `response`: An optional `GarlemliaResponse` containing additional response information, if provided.
    ///
    /// # Returns
    /// - An `Option<GarlemliaMessage>` that might contain a follow-up message or be `None` if no further action
    ///   is required.
    ///
    /// # Behavior
    /// 1. When receiving a `SearchOverlay` request:
    ///     - Retrieves the current request if it exists to determine the proxy initiator.
    ///     - If a response is provided, prepares and generates cloves with the appropriate information.
    ///     - Sends the cloves to the determined proxy and forwards the request for further hops if TTL (`time-to-live`) > 0.
    ///
    /// 2. When receiving a `SearchGarlemlia` request:
    ///     - Ensures the request is associated with a proxy and prepares cloves if a response exists.
    ///     - Sends the response cloves to the proxy.
    ///     - Handles cleanup of expired or completed requests depending on the response type.
    ///
    /// 3. When receiving a `ResponseWithValidator` request:
    ///     - Verifies the response and forwards a `ResponseDirect` message to the provided proxy,
    ///       performing additional validation handling if needed.
    ///
    /// 4. When receiving a `Store` request:
    ///     - Simply removes the request from the active proxy requests list.
    ///
    /// 5. Ignores unsupported or unknown message types and safely returns `None`.
    ///
    /// # Message Types Handled
    /// - `CloveMessage::SearchOverlay`: Facilitates recursive proxying and response handling for overlay searches.
    /// - `CloveMessage::SearchGarlemlia`: Handles intermediate responses specific to Garlemlia searches.
    /// - `CloveMessage::ResponseWithValidator`: Processes direct responses associated with validation logic.
    /// - `CloveMessage::Store`: Cleans up stored proxy requests to avoid stale references.
    /// - Any other message types are ignored.
    ///
    /// # Notes
    /// - The function interacts with other systems like `GarlicCast` for wrapping (clove) generation
    ///   and communication with proxies via `send_to_proxy`.
    /// - Uses `garlic.proxies` and `garlic.requests_as_proxy` for proxy selection and request management.
    /// - TTL (time-to-live) decremental logic ensures cyclic or excessive proxying is avoided.
    ///
    /// # Error Handling
    /// - The function logs errors during message sending to proxies or validators.
    /// - Expects all cryptographic operations (`RSA`, `PEM parsing`) and `GarlicCast` utilities to succeed; otherwise, panics may occur.
    ///
    /// # Example
    ///
    /// let req = CloveMessage::SearchOverlay {
    ///     request_id: ...,
    ///     proxy_id: ...,
    ///     public_key: ...,
    ///     search_term: ...,
    ///     ttl: 5
    /// };
    /// let response = Some(GarlemliaResponse::FileChunkInfo { ... });
    ///
    /// let result = instance.run_proxy_message(req, response).await;
    /// match result {
    ///     Some(message) => println!("Next GarlemliaMessage: {:?}", message),
    ///     None => println!("No action required."),
    /// }
    // validator pool creations or searches
    async fn run_proxy_message(
        garlic: &mut GarlicCast,
        req: CloveMessage,
        response: Option<GarlemliaResponse>,
    ) -> Option<GarlemliaMessage> {
        match req.clone() {
            CloveMessage::SearchOverlay {
                request_id,
                proxy_id,
                public_key,
                search_term,
                ttl,
            } => {
                let current_request = garlic
                    .requests_as_proxy
                    .get(&request_id.request_id)
                    .cloned();

                if response.is_some() {
                    let response_unwrapped = response.unwrap();
                    let proxy;
                    let cloves;

                    if current_request.is_some() {
                        proxy = current_request.unwrap().initiator.clone();

                        let msg = CloveMessage::Response {
                            request_id: request_id.clone(),
                            data: response_unwrapped,
                        };

                        cloves = CloveProtocol::generate(
                            msg.clone(),
                            2,
                            proxy.sequence_number,
                            Some(RsaPublicKey::from_public_key_pem(&*public_key).unwrap()),
                            Some(request_id.clone()),
                        )
                        .unwrap();
                    } else {
                        proxy = garlic.proxies.choose(&mut rand::rng()).unwrap().clone();

                        let res_msg = CloveMessage::Response {
                            request_id: request_id.clone(),
                            data: response_unwrapped,
                        };

                        let res_cloves = CloveProtocol::generate(
                            res_msg.clone(),
                            2,
                            request_id.request_id,
                            Some(RsaPublicKey::from_public_key_pem(&*public_key).unwrap()),
                            Some(request_id.clone()),
                        )
                        .unwrap();

                        let msg = CloveMessage::ResponseWithValidator {
                            request_id: request_id.clone(),
                            proxy_id,
                            clove_1: res_cloves[0].clone(),
                            clove_2: res_cloves[1].clone(),
                        };

                        cloves = CloveProtocol::generate(
                            msg.clone(),
                            2,
                            proxy.sequence_number,
                            Some(proxy.clone().public_key),
                            Some(CloveRequestID::new(u256_random(), rand::random::<u64>())),
                        )
                        .unwrap();
                    }

                    garlic.send_to_proxy(proxy, cloves).await;
                }

                if ttl > 0 {
                    return Some(GarlemliaMessage::SearchFile {
                        request_id: request_id.clone(),
                        proxy_id,
                        search_term,
                        public_key,
                        sender: garlic.local_node.clone(),
                        ttl: ttl - 1,
                    });
                }

                None
            }
            CloveMessage::SearchGarlemlia { request_id, .. } => {
                let current_request = garlic
                    .requests_as_proxy
                    .get(&request_id.request_id)
                    .cloned();

                if current_request.is_some() {
                    let proxy = current_request.unwrap().initiator.clone();

                    if response.is_none() {
                        return None;
                    }

                    let response_unwrapped = response.unwrap();

                    let msg = CloveMessage::Response {
                        request_id: request_id.clone(),
                        data: response_unwrapped.clone(),
                    };

                    let cloves = CloveProtocol::generate(
                        msg.clone(),
                        2,
                        proxy.sequence_number,
                        Some(proxy.clone().public_key),
                        Some(request_id.clone()),
                    )
                    .unwrap();

                    garlic.send_to_proxy(proxy, cloves).await;

                    match response_unwrapped {
                        GarlemliaResponse::FileChunkInfo { .. } => {}
                        _ => {
                            garlic.requests_as_proxy.remove(&request_id.request_id);
                        }
                    }
                }

                None
            }
            CloveMessage::ResponseWithValidator {
                request_id,
                clove_1,
                clove_2,
                ..
            } => {
                if response.is_none() {
                    return None;
                }

                let msg = GarlicMessage::ResponseDirect {
                    request_id,
                    clove_1,
                    clove_2,
                };

                match response.unwrap() {
                    GarlemliaResponse::Validator { proxy } => {
                        if proxy.is_some() {
                            {
                                if let Err(e) = garlic
                                    .message_handler
                                    .send_no_recv(
                                        &Arc::clone(&garlic.socket),
                                        garlic.local_node.clone(),
                                        &proxy.unwrap(),
                                        &GarlicMessage::build_send(garlic.local_node.clone(), msg),
                                    )
                                    .await
                                {
                                    eprintln!(
                                        "Failed to send IsAlive to {}: {:?}",
                                        proxy.unwrap(),
                                        e
                                    );
                                }
                            }
                        }
                    }
                    _ => {}
                }

                None
            }
            CloveMessage::Store { request_id, .. } => {
                garlic.requests_as_proxy.remove(&request_id.request_id);
                None
            }
            _ => None,
        }
    }

    async fn manage_proxy_message(req: CloveMessage) -> Option<CloveMessage> {
        match req.clone() {
            CloveMessage::SearchOverlay { .. } => Some(req),
            CloveMessage::SearchGarlemlia { .. } => Some(req),
            CloveMessage::ResponseWithValidator { .. } => {
                // This only gets sent to the proxy of the responder to a request
                // The responder proxy uses ResponseDirect when sending the response
                // to the proxy of the initiator
                Some(req)
            }
            CloveMessage::Store { .. } => Some(req),
            _ => None,
        }
    }

    async fn accept_proxy(
        garlic: &mut GarlicCast,
        sequence_number: U256,
        second_clove: Clove,
        node: Node,
    ) -> Result<Proxy, MessageError> {
        let first_clove = garlic.cache.cloves.get(&sequence_number).unwrap().clone();
        let msg_from_initiator_check =
            CloveProtocol::reconstruct(first_clove.clone().clove, second_clove.clone());

        let msg_from_initiator = msg_from_initiator_check.ok().unwrap();

        if first_clove.from.id == node.id {
            println!(
                "COULD NOT ACCEPT PROXY, RECEIVED FROM SAME NODE {}",
                node.address
            );
            garlic.cache.remove_clove(sequence_number);
            return Err(MessageError::AcceptError);
        }

        match msg_from_initiator {
            CloveMessage::RequestProxy { public_key, .. } => {
                let new_sequence = u256_random();
                let proxy = Proxy {
                    sequence_number: new_sequence,
                    neighbor_1: CloveNode {
                        sequence_number: new_sequence,
                        node: first_clove.from.clone(),
                    },
                    neighbor_2: CloveNode {
                        sequence_number: new_sequence,
                        node: node.clone(),
                    },
                    neighbor_1_hops: 0,
                    neighbor_2_hops: 0,
                    public_key: RsaPublicKey::from_public_key_pem(&*public_key).unwrap(),
                    used_last: Utc::now(),
                };

                garlic.initiators.push(proxy.clone());
                garlic.do_not_forward.insert(sequence_number, Utc::now());

                garlic.cache.insert_next_hop(
                    CloveNode {
                        sequence_number: new_sequence,
                        node: node.clone(),
                    },
                    None,
                );
                garlic.cache.insert_next_hop(
                    CloveNode {
                        sequence_number: new_sequence,
                        node: first_clove.clone().from,
                    },
                    None,
                );
                // Insert associations
                garlic.cache.insert_association(
                    new_sequence,
                    CloveNode {
                        sequence_number: new_sequence,
                        node: node.clone(),
                    },
                );
                garlic.cache.insert_association(
                    new_sequence,
                    CloveNode {
                        sequence_number: new_sequence,
                        node: first_clove.from,
                    },
                );
                // Insert seen last
                garlic.cache.seen(new_sequence);
                // Remove old clove
                garlic.cache.remove_clove(sequence_number);

                //println!("{} :: PROXY :: {}", Utc::now(), garlic.local_node.address);
                Forwarding::forward_proxy_accept(garlic, proxy.clone(), sequence_number).await;

                Ok(proxy)
            }
            _ => Err(MessageError::AcceptError),
        }
    }

    fn update_proxy(garlic: &mut GarlicCast, old_proxy: Proxy, new_proxy: Proxy) -> Proxy {
        ProxyDiscovery::replace_proxy(garlic, &old_proxy, &new_proxy);
        new_proxy
    }

    /// Handles proxy forwarding by processing potential neighbor failures and updating the proxy accordingly.
    ///
    /// This asynchronous function is used to manage and forward the proxy object to the appropriate neighbor
    /// while considering forwarding types, neighbor-specific failures, and alternative routing in case of errors.
    /// It updates the proxy state and may return a new version of the proxy if changes are made during processing.
    ///
    /// # Arguments
    ///
    /// * `forward_type` - A `u8` indicating the type of forwarding to be performed. This determines
    ///   the behavior for neighbor error handling.
    /// * `proxy` - The `Proxy` instance that holds the current state and neighbor information.
    /// * `cloves` - A vector of `Clove` objects used in the forwarding process, where each element
    ///   corresponds to one of the neighbors.
    ///
    /// # Returns
    ///
    /// Returns an `Option<Proxy>`:
    /// - `Some(proxy)`: The updated proxy after handling forwarding and potential changes.
    /// - `None`: If critical failures occur during handling, resulting in an inability to forward the proxy.
    ///
    /// # Behavior
    ///
    /// 1. Extracts the `neighbor_1` and `neighbor_2` from the provided `proxy` object.
    /// 2. Checks if there's a simulated error for the first neighbor using `send_error_neighbor1`.
    ///    - If an error is detected:
    ///      a. Calls `process_neighbor_failure` asynchronously for `neighbor_1` along with the first clove.
    ///      b. If successful and a new proxy is returned, updates the proxy.
    ///      c. If an error occurs, falls back to handle an alternative forward failure using `handle_alt_forward_failure`
    ///         and the second neighbor.
    /// 3. Similarly, checks for simulated errors on the second neighbor using `send_error_neighbor2`.
    ///    - If an error is detected:
    ///      a. Calls `process_neighbor_failure` asynchronously for `neighbor_2` with the second clove.
    ///      b. Updates the proxy if successful.
    ///      c. Handles forward failure using `handle_alt_forward_failure` and the first neighbor in case of errors.
    /// 4. If no errors occur for the second neighbor, returns the current state of the proxy.
    ///
    /// # Error Handling
    ///
    /// Errors are handled by invoking alternative processing methods such as `handle_alt_forward_failure`. This ensures
    /// the function attempts recovery and offers the most viable forwarding route, even in case of neighbor failures.
    ///
    /// # Examples
    ///
    /// let mut handler = Handler::new();
    /// let proxy = Proxy { neighbor_1: "NodeA".into(), neighbor_2: "NodeB".into(), ... };
    /// let cloves = vec![clove1, clove2];
    /// let result = handler.handle_proxy_forwarding(1, proxy, cloves).await;
    ///
    /// if let Some(updated_proxy) = result {
    ///     println!("Forwarding successful: {:?}", updated_proxy);
    /// } else {
    ///     println!("Forwarding failed");
    /// }
    ///
    ///
    /// # Notes
    ///
    /// - Ensure that the `cloves` vector contains valid elements, where each clove corresponds properly
    ///   to the neighbors (e.g., `cloves[0]` for `neighbor_1` and `cloves[1]` for `neighbor_2`).
    /// - This function assumes that `send_error_neighbor1` and `send_error_neighbor2` are utility garlemlia
    ///   that simulate or check for errors in forwarding attempts.
    async fn handle_proxy_forwarding(
        garlic: &mut GarlicCast,
        forward_type: u8,
        mut proxy: Proxy,
        cloves: Vec<Clove>,
    ) -> Option<Proxy> {
        let first_neighbor = proxy.neighbor_1.clone();
        let second_neighbor = proxy.neighbor_2.clone();

        if Sharding::send_error_neighbor1(forward_type) {
            match AltRoutes::process_neighbor_failure(garlic, &first_neighbor, &cloves[0], &proxy)
                .await
            {
                Ok(maybe_new_proxy) => {
                    if let Some(new_proxy) = maybe_new_proxy {
                        proxy = ProxyRuntime::update_proxy(garlic, proxy, new_proxy);
                    }
                }
                Err(_) => {
                    return AltRoutes::handle_alt_forward_failure(garlic, &proxy, &second_neighbor)
                }
            }
        }

        if Sharding::send_error_neighbor2(forward_type) {
            match AltRoutes::process_neighbor_failure(garlic, &second_neighbor, &cloves[1], &proxy)
                .await
            {
                Ok(maybe_new_proxy) => {
                    if let Some(new_proxy) = maybe_new_proxy {
                        proxy = ProxyRuntime::update_proxy(garlic, proxy, new_proxy);
                    }
                    Some(proxy)
                }
                Err(_) => AltRoutes::handle_alt_forward_failure(garlic, &proxy, &first_neighbor),
            }
        } else {
            Some(proxy)
        }
    }

    /// Creates an asynchronous download task for retrieving chunks through the Garlic routing network
    /// This function is intended to handle a proxy's forwarding mechanism by sending and receiving messages
    /// to/from two neighboring nodes while maintaining their sequence numbers and error handling.
    ///
    /// # Parameters
    /// - `msg`: A `CloveMessage` instance representing the payload to be forwarded.
    /// - `request_id`: Unique identifier for the overall download request
    /// - `chunks_requested`: Total number of chunks being requested
    /// - `chunk_id`: Unique identifier for the specific chunk being downloaded
    /// - `proxies`: List of available proxy nodes that can be used for routing
    /// - `proxy_index`: Index into the proxies array to select which proxy to use
    /// - `temp_proxy`: A `Proxy` object used for routing information and sequence handling during task execution.
    /// - `request_id_full`: A `CloveRequestID` associated with the full request data.
    ///
    /// # Returns
    /// JoinHandle that resolves to either:
    /// - Ok((U256, Proxy)): Success case with chunk ID and used proxy
    /// - Err((u8, Proxy, Vec<Clove>, U256)): Error case containing:
    ///   - `u8`: Return code indicating failure state (e.g., 1: first neighbor failure, 2: second neighbor failure, 3: both neighbors failed).
    ///   - `Proxy`: The proxy state at the time of the error.
    ///   - `Vec<Clove>`: The cloves generated during the process.
    ///   - `U256`: The original proxy ID.
    ///
    /// # Task Behavior
    /// - Clones are generated using `GarlicCast::generate_cloves`, with one destined for each neighbor.
    /// - Sends cloves to `neighbor_1` and awaits a response. If sending or receiving fails, an error is logged, and a return code is updated.
    /// - Repeats the above for `neighbor_2`, modifying the return code accordingly if errors occur.
    /// - The task ensures proper sequencing and routing logic with fallbacks in case of communication issues.
    ///
    /// # Error Handling
    /// - Logs errors for failed sending attempts to each neighbor.
    /// - Updates the task's return code based on the errors encountered during the forwarding process.
    /// - Consolidates errors into a well-structured `Err` result with sufficient context for debugging.
    ///
    /// # Examples
    ///
    /// let join_handle = proxy_system.spawn_proxy_task(
    ///     clove_message,
    ///     proxy_id,
    ///     temp_proxy,
    ///     request_id_full,
    /// );
    ///
    /// match join_handle.await.unwrap() {
    ///     Ok((id, proxy)) => println!("Proxy task completed successfully with ID: {:?}", id),
    ///     Err((code, proxy, cloves, id)) => eprintln!(
    ///         "Proxy task failed with code {:?} for proxy ID {:?}. Cloves: {:?}",
    ///         code, id, cloves
    ///     ),
    /// }
    ///
    ///
    /// # Requirements
    /// - Tokio runtime must be in place to spawn asynchronous tasks.
    /// - Both `message_handler` and `socket` need to be properly initialized and thread-safe.
    ///
    /// # Notes
    /// - `message_handler.send` and `message_handler.recv` handle the communication exchanges between nodes.
    /// - Failures in one or both neighbors propagate through the result as an error variant.
    /// - The provided timeout duration for message receipt is 200 milliseconds.
    ///
    /// # See Also
    /// - `GarlicCast::generate_cloves`: For clove generation.
    /// - `GarlicMessage::Forward`: For the clove forwarding message format.
    async fn spawn_proxy_task(
        garlic: &GarlicCast,
        msg: CloveMessage,
        proxy_id: U256,
        temp_proxy: Proxy,
        request_id_full: CloveRequestID,
    ) -> JoinHandle<Result<(U256, Proxy), (u8, Proxy, Vec<Clove>, U256)>> {
        let socket = Arc::clone(&garlic.socket);
        let message_handler = Arc::clone(&garlic.message_handler);
        let local_node = garlic.local_node.clone();

        tokio::spawn(async move {
            let n_1 = temp_proxy.neighbor_1.node.clone();
            let n_2 = temp_proxy.neighbor_2.node.clone();

            let cloves = CloveProtocol::generate(
                msg.clone(),
                2,
                temp_proxy.sequence_number,
                Some(temp_proxy.clone().public_key),
                Some(request_id_full),
            )
            .unwrap();

            let n_1_msg = GarlicMessage::Forward {
                sequence_number: temp_proxy.neighbor_1.sequence_number,
                clove: cloves[0].clone(),
            };
            let n_2_msg = GarlicMessage::Forward {
                sequence_number: temp_proxy.neighbor_2.sequence_number,
                clove: cloves[1].clone(),
            };

            let mut return_code = 0;

            // Send it to the first neighbor
            if let Err(e) = message_handler
                .send(
                    &Arc::from(socket.clone()),
                    local_node.clone(),
                    &n_1.address,
                    &GarlicMessage::build_send(local_node.clone(), n_1_msg.clone()),
                )
                .await
            {
                eprintln!("Failed to send Forward to {}: {:?}", n_1.address, e);
                return_code = 1;
            }

            // Wait for the first response
            let response = message_handler.recv(200, &n_1.address).await;
            if response.is_err() {
                return_code = 1;
            }

            // Send it to the second neighbor
            if let Err(e) = message_handler
                .send(
                    &Arc::from(socket.clone()),
                    local_node.clone(),
                    &n_2.address,
                    &GarlicMessage::build_send(local_node.clone(), n_2_msg.clone()),
                )
                .await
            {
                eprintln!("Failed to send Forward to {}: {:?}", n_2.address, e);
                return_code = if return_code == 1 { 3 } else { 2 };
            }

            // Wait for a second response
            let response2 = message_handler.recv(200, &n_2.address).await;
            if response2.is_err() {
                return_code = if return_code == 1 { 3 } else { 2 };
            }

            match return_code {
                0 => Ok((proxy_id, temp_proxy.clone())),
                _ => Err((return_code as u8, temp_proxy.clone(), cloves, proxy_id)),
            }
        })
    }

    /// Handles the result of a proxy task and updates the proxy request accordingly.
    ///
    /// # Parameters
    /// - `garlic`: A mutable reference to the current instance of the implementing type.
    /// - `task`: An asynchronous task represented as a `JoinHandle` that resolves to a `Result`.
    ///   - On success, the task returns a tuple containing a `U256` proxy ID and a `Proxy` instance.
    ///   - On failure, the task returns a tuple with:
    ///   - Error code (u8)
    ///   - Proxy used in the attempt
    ///   - Generated cloves
    ///   - Original chunk ID
    /// - `proxy_request`: A mutable reference to an `InitiatorRequest` that tracks the proxies and associations.
    ///
    /// # Behavior
    /// - Awaits the result of the given task.
    /// - If the task is successful:
    ///   - It retrieves the proxy ID and proxy instance from the result.
    ///   - The proxy is cloned and appended to the `proxies` field of `proxy_request`.
    ///   - The proxy ID and its corresponding proxy are inserted into the `proxy_id_associations` map in `proxy_request`.
    /// - If the task fails:
    ///   - The method attempts to handle the failure by calling `handle_proxy_forwarding` with the error code, the proxy, and the `Clove` objects.
    ///   - If a modified proxy (`changed`) is returned by `handle_proxy_forwarding`:
    ///     - The modified proxy is cloned and appended to the `proxies` field of `proxy_request`.
    ///     - The proxy ID and the modified proxy are inserted into the `proxy_id_associations` map in `proxy_request`.
    ///   - If `handle_proxy_forwarding` does not successfully resolve the failure, an error is returned.
    /// - If the task fails with a join error, the error message is returned.
    ///
    /// # Returns
    /// - `Ok(())` if the task result (success or handled failure) is processed successfully.
    /// - `Err(String)` if there is a join error or the failure could not be resolved.
    ///
    /// # Errors
    /// - Returns an error string containing the failure cause:
    ///   - If the task fails to resolve (`Err(e)`), the join error is captured.
    ///   - If `handle_proxy_forwarding` cannot resolve the proxy failure, an error message indicating the failure is returned.
    ///
    /// # Dependencies
    /// - This method relies on the asynchronous function `handle_proxy_forwarding` to manage failed proxies.
    ///
    /// # Example
    ///
    /// let task_result = handle_proxy_task_result(task, &mut proxy_request).await;
    /// match task_result {
    ///     Ok(()) => println!("Proxy task handled successfully"),
    ///     Err(e) => eprintln!("Failed to process proxy task result: {}", e),
    /// }
    ///
    async fn handle_proxy_task_result(
        garlic: &mut GarlicCast,
        task: JoinHandle<Result<(U256, Proxy), (u8, Proxy, Vec<Clove>, U256)>>,
        proxy_request: &mut InitiatorRequest,
    ) -> Result<(), String> {
        match task.await {
            Ok(result) => match result {
                Ok((proxy_id, proxy)) => {
                    proxy_request.proxies.push(proxy.clone());
                    proxy_request.proxy_id_associations.insert(proxy_id, proxy);
                    Ok(())
                }
                Err((code, proxy, cloves, proxy_id)) => {
                    if let Some(changed) =
                        ProxyRuntime::handle_proxy_forwarding(garlic, code, proxy, cloves).await
                    {
                        proxy_request.proxies.push(changed.clone());
                        proxy_request
                            .proxy_id_associations
                            .insert(proxy_id, changed);
                        Ok(())
                    } else {
                        Err("Failed to handle proxy failure".to_string())
                    }
                }
            },
            Err(e) => Err(format!("Task join error: {}", e)),
        }
    }
}
