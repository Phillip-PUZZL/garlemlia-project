use crate::core::MessageError;
use crate::data::garlemlia_protocol::{GarlemliaMessage, GarlemliaResponse};
use crate::garlic::constants::{CloveResult, DEFAULT_RESPONSE};
use crate::garlic::forwarding::alt_routes::{AltRoutes, TraitAltRoutes};
use crate::garlic::forwarding::forwarding::{Forwarding, TraitForwarding};
use crate::garlic::forwarding::proxy_discovery::{ProxyDiscovery, TraitProxyDiscovery};
use crate::garlic::forwarding::proxy_runtime::{ProxyRuntime, TraitProxyRuntime};
use crate::garlic::state::garlic_cast::{GarlicCast, FORWARD_P};
use crate::garlic::state::request_state::{InitiatorRequest, Proxy, ProxyRequest};
use crate::garlic::{
    Clove, CloveMessage, CloveNode, CloveProtocol, CloveRequestID, GarlicMessage,
    TraitCloveProtocol,
};
use crate::net::node::Node;
use chrono::Utc;
use primitive_types::U256;
use rand::random_bool;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;
use std::sync::Arc;
use tokio::net::UdpSocket;

pub(crate) trait TraitMessageHandling {
    async fn recv(
        garlic: &mut GarlicCast,
        node: Node,
        garlic_msg: GarlicMessage,
    ) -> Result<Option<CloveMessage>, MessageError>;
    fn determine_source_node(garlic: &GarlicCast, original_node: &Node, clove: &Clove) -> Node;
    fn is_existing_non_duplicate_clove(
        garlic: &GarlicCast,
        sequence_number: U256,
        clove: &Clove,
    ) -> bool;
    async fn handle_existing_clove(
        garlic: &mut GarlicCast,
        node: Node,
        sequence_number: U256,
        clove: Clove,
        source_node: Node,
    ) -> CloveResult;
    fn cache_new_clove(
        garlic: &mut GarlicCast,
        sequence_number: U256,
        source_node: Node,
        clove: Clove,
    );
    async fn handle_alternative_route(
        garlic: &mut GarlicCast,
        clove_node: &CloveNode,
        node: &Node,
    ) -> Result<(), MessageError>;
    async fn update_proxy_references(
        garlic: &mut GarlicCast,
        old_node: &CloveNode,
        new_node: &CloveNode,
        sequence: U256,
    ) -> Result<(), MessageError>;
    fn create_updated_proxy(proxy: &Proxy, old_node: &CloveNode, new_node: &CloveNode) -> Proxy;
    async fn update_alt_node_state(
        garlic: &mut GarlicCast,
        old_node: &CloveNode,
        new_node: &CloveNode,
        sequence: U256,
        node: &Node,
    ) -> Result<(), MessageError>;
    fn get_actual_sequence_number(
        garlic: &GarlicCast,
        sequence_number: U256,
        clove_node: &CloveNode,
    ) -> U256;
    async fn process_forward(
        garlic: &mut GarlicCast,
        next_info: Option<CloveNode>,
        node: Node,
        sequence_number: U256,
        am_alt: bool,
        sn_actual: U256,
        msg: &GarlicMessage,
        clove: Clove,
    ) -> Result<Option<CloveMessage>, MessageError>;
    async fn handle_forward_to_next(
        garlic: &mut GarlicCast,
        node: Node,
        next_node: CloveNode,
        sequence_number: U256,
        am_alt: bool,
        sn_actual: U256,
        msg: &Clove,
    ) -> Result<Option<CloveMessage>, MessageError>;
    async fn handle_message_collection(
        garlic: &mut GarlicCast,
        request_id: CloveRequestID,
        garlic_msg: GarlicMessage,
        sequence_number: U256,
    ) -> Result<Option<CloveMessage>, MessageError>;
    async fn process_collected_messages(
        garlic: &mut GarlicCast,
        messages: Vec<GarlicMessage>,
        request_id: CloveRequestID,
        sequence_number: U256,
    ) -> Result<Option<CloveMessage>, MessageError>;
    async fn handle_initiator_message(
        request_info: &mut InitiatorRequest,
        msg: CloveMessage,
    ) -> Result<Option<CloveMessage>, MessageError>;
    async fn handle_proxy_message(
        garlic: &mut GarlicCast,
        sequence_number: U256,
        msg: CloveMessage,
    ) -> Result<Option<CloveMessage>, MessageError>;
    async fn handle_find_proxy(
        garlic: &mut GarlicCast,
        node: Node,
        sequence_number: U256,
        clove: Clove,
    ) -> CloveResult;
    async fn handle_forward(
        garlic: &mut GarlicCast,
        node: Node,
        garlic_msg: GarlicMessage,
        sequence_number: U256,
        clove: Clove,
    ) -> Result<Option<CloveMessage>, MessageError>;
    async fn handle_proxy_agree(
        garlic: &mut GarlicCast,
        node: Node,
        garlic_msg: GarlicMessage,
        socket: Arc<UdpSocket>,
        sequence_number: U256,
        updated_sequence_number: U256,
        hops: u16,
        clove: Clove,
    ) -> Result<Option<CloveMessage>, MessageError>;
    async fn handle_collected_messages(
        garlic: &mut GarlicCast,
        clove: Clove,
        garlic_msg: GarlicMessage,
        node: Node,
        updated_sequence_number: U256,
        hops: u16,
    ) -> Result<Option<CloveMessage>, MessageError>;
}

pub struct MessageHandling;
impl TraitMessageHandling for MessageHandling {
    /// Handles an incoming GarlicMessage asynchronously and performs actions based on the type of message.
    ///
    /// # Arguments
    /// - `node`: The `Node` instance associated with the sender of the message. Provides critical information about the sender.
    /// - `garlic_msg`: The `GarlicMessage` received that needs to be processed.
    ///
    /// # Returns
    /// - `Ok(Some(CloveMessage))`: If a `CloveMessage` is generated as a result of the processing.
    /// - `Ok(None)`: If no `CloveMessage` is produced as a result of the processing.
    /// - `Err(MessageError)`: If an error occurs while processing the message.
    ///
    /// # GarlicMessage Variants and Behavior
    /// 1. `FindProxy`: Delegates to `handle_find_proxy` to manage requests pertaining to finding a proxy.
    /// 2. `Forward`: Delegates to `handle_forward` for handling forwarding of the message.
    /// 3. `ProxyAgree`: Delegates to `handle_proxy_agree` to manage agreement for establishing a proxy chain.
    /// 4. `RequestAlt`: Handles adding alternate (backup) nodes to the network and sends an `AgreeAlt` message to confirm.
    ///    - Updates internal cache with alternate node data.
    /// 5. `RefreshAlt`: Marks the `sequence_number` in the cache as "seen" for refreshing alternate node persistence.
    /// 6. `UpdateAlt`: Updates an alternate node for a given `sequence_number` in the cache.
    /// 7. `UpdateAltNextOrLast`: Updates the next or last node for an alternation chain in the cache, replacing with an alternate if needed.
    /// 8. `ResponseDirect`: Handles direct response from a request, updating relevant proxy data and forwarding it to the initiator.
    /// 9. `FileChunkPart`: Returns a `CloveMessage` containing part of a file chunk from an ongoing file transfer.
    ///
    /// # Error Handling
    /// Any issues during processing, such as sending a message or cache-related behavior, result in a `MessageError`.
    ///
    /// # Notes
    /// - Some variants such as `RequestAlt` contain placeholder `TODO` for more advanced decision-making logic.
    /// - Internal mechanisms include updating the `cache`, invoking helper methods like `send_to_proxy`, and communication via sockets.
    async fn recv(
        garlic: &mut GarlicCast,
        node: Node,
        garlic_msg: GarlicMessage,
    ) -> Result<Option<CloveMessage>, MessageError> {
        let socket = Arc::clone(&garlic.socket);
        match garlic_msg.clone() {
            GarlicMessage::FindProxy {
                sequence_number,
                clove,
            } => Self::handle_find_proxy(garlic, node, sequence_number, clove).await,
            GarlicMessage::Forward {
                sequence_number,
                clove,
            } => Self::handle_forward(garlic, node, garlic_msg, sequence_number, clove).await,
            GarlicMessage::ProxyAgree {
                sequence_number,
                updated_sequence_number,
                hops,
                clove,
            } => {
                Self::handle_proxy_agree(
                    garlic,
                    node,
                    garlic_msg,
                    socket,
                    sequence_number,
                    updated_sequence_number,
                    hops,
                    clove,
                )
                .await
            }
            GarlicMessage::RequestAlt {
                alt_sequence_number,
                last_hop,
                next_hop,
            } => {
                // TODO: Include some logic so that this node can decide to be an alternate or backup node
                // For now, just add it

                let lh_clove = CloveNode {
                    sequence_number: alt_sequence_number,
                    node: last_hop.clone(),
                };
                let nh_clove = CloveNode {
                    sequence_number: alt_sequence_number,
                    node: next_hop.clone(),
                };

                garlic
                    .cache
                    .insert_next_hop(lh_clove.clone(), Some(nh_clove.clone()));
                garlic
                    .cache
                    .insert_next_hop(nh_clove.clone(), Some(lh_clove.clone()));
                // Insert associations
                garlic
                    .cache
                    .insert_association(alt_sequence_number, lh_clove.clone());
                garlic
                    .cache
                    .insert_association(alt_sequence_number, nh_clove.clone());
                // Insert am alt for
                garlic.cache.insert_am_alt(alt_sequence_number);
                // Insert seen last
                garlic.cache.seen(alt_sequence_number);

                let agree_alt = GarlemliaMessage::AgreeAlt {
                    alt_sequence_number,
                    sender: garlic.local_node.clone(),
                };

                {
                    if let Err(e) = garlic
                        .message_handler
                        .send_no_recv(
                            &Arc::from(socket),
                            garlic.local_node.clone(),
                            &node.address,
                            &agree_alt,
                        )
                        .await
                    {
                        eprintln!("Failed to send Forward to {}: {:?}", node.address, e);
                    }
                }

                Ok(None)
            }
            GarlicMessage::RefreshAlt { sequence_number } => {
                garlic.cache.seen(sequence_number);

                Ok(None)
            }
            GarlicMessage::UpdateAlt {
                sequence_number,
                alt_node,
            } => {
                let clove_node = CloveNode {
                    sequence_number,
                    node,
                };

                garlic
                    .cache
                    .insert_alt_node(clove_node.clone(), alt_node.clone());

                Ok(None)
            }
            GarlicMessage::UpdateAltNextOrLast {
                sequence_number,
                old_node,
                new_node,
            } => {
                garlic.cache.seen(sequence_number);

                let old_clove_node = CloveNode {
                    sequence_number,
                    node: old_node.clone(),
                };
                let new_clove_node = CloveNode {
                    sequence_number,
                    node: new_node.clone(),
                };

                if garlic.cache.am_alt_for.contains(&sequence_number) {
                    garlic
                        .cache
                        .insert_alt_node(old_clove_node.clone(), new_clove_node.clone());
                    garlic.cache.replace_with_alt_node(&old_clove_node);
                }

                Ok(None)
            }
            GarlicMessage::ResponseDirect {
                request_id,
                clove_1,
                clove_2,
            } => {
                let current_request = garlic
                    .requests_as_proxy
                    .get(&request_id.request_id)
                    .cloned();

                if current_request.is_some() {
                    let proxy = current_request.unwrap().initiator.clone();

                    let new_request_id_index = rand::random::<u64>();
                    let mut new_clove_1 = clove_1.clone();
                    let mut new_clove_2 = clove_2.clone();
                    new_clove_1.sequence_number = proxy.sequence_number;
                    new_clove_1.request_id.index = new_request_id_index;

                    new_clove_2.sequence_number = proxy.sequence_number;
                    new_clove_2.request_id.index = new_request_id_index;

                    garlic
                        .send_to_proxy(proxy, vec![new_clove_1, new_clove_2])
                        .await;
                }

                Ok(None)
            }
            GarlicMessage::FileChunkPart { request_id, data } => {
                Ok(Some(CloveMessage::FileChunkPart { request_id, data }))
            }
        }
    }

    fn determine_source_node(garlic: &GarlicCast, original_node: &Node, clove: &Clove) -> Node {
        let clove_data = garlic.cache.cloves.clone();

        for (_, data) in clove_data {
            if data.clove == *clove {
                return data.from;
            }
        }

        original_node.clone()
    }

    fn is_existing_non_duplicate_clove(
        garlic: &GarlicCast,
        sequence_number: U256,
        clove: &Clove,
    ) -> bool {
        let is_existing = garlic.cache.cloves.contains_key(&sequence_number);
        let mut has_same_clove = false;

        for (_, data) in garlic.cache.cloves.clone() {
            if data.clove == *clove {
                has_same_clove = true;
                break;
            }
        }

        is_existing && !has_same_clove
    }

    async fn handle_existing_clove(
        garlic: &mut GarlicCast,
        node: Node,
        sequence_number: U256,
        clove: Clove,
        source_node: Node,
    ) -> CloveResult {
        let new_proxy =
            ProxyRuntime::accept_proxy(garlic, sequence_number, clove, source_node).await?;
        let new_alt =
            AltRoutes::find_alt(garlic, Some(node.clone()), None, new_proxy.sequence_number).await;

        let clove_node = CloveNode {
            node,
            sequence_number: new_proxy.sequence_number,
        };

        AltRoutes::send_alt(garlic, Some(clove_node), None, new_alt).await;
        Ok(DEFAULT_RESPONSE)
    }

    fn cache_new_clove(
        garlic: &mut GarlicCast,
        sequence_number: U256,
        source_node: Node,
        clove: Clove,
    ) {
        let original_clove = CloveNode {
            sequence_number,
            node: source_node.clone(),
        };

        garlic.cache.insert_next_hop(original_clove.clone(), None);
        garlic.cache.insert_clove(clove, source_node.clone());
        garlic
            .cache
            .insert_association(sequence_number, original_clove);
        garlic.cache.seen(sequence_number);
    }

    async fn handle_alternative_route(
        garlic: &mut GarlicCast,
        clove_node: &CloveNode,
        node: &Node,
    ) -> Result<(), MessageError> {
        if let Some(sequence_try) = garlic.cache.alt_to_sequence.get(clove_node).cloned() {
            if let Some(old_node) = garlic.cache.get_old_from_alt(clove_node) {
                Self::update_proxy_references(garlic, &old_node, clove_node, sequence_try).await?;
                Self::update_alt_node_state(garlic, &old_node, clove_node, sequence_try, node)
                    .await?;
            }
        }
        Ok(())
    }

    async fn update_proxy_references(
        garlic: &mut GarlicCast,
        old_node: &CloveNode,
        new_node: &CloveNode,
        sequence: U256,
    ) -> Result<(), MessageError> {
        let proxies = garlic.proxies.clone();
        let initiators = garlic.initiators.clone();

        // Update proxy references
        for proxy in proxies {
            if proxy.sequence_number == sequence {
                let updated_proxy = Self::create_updated_proxy(&proxy, old_node, new_node);
                ProxyDiscovery::replace_proxy(garlic, &proxy, &updated_proxy);
            }
        }

        // Update initiator references
        for initiator in initiators {
            if initiator.sequence_number == sequence {
                let updated_initiator = Self::create_updated_proxy(&initiator, old_node, new_node);
                ProxyDiscovery::replace_proxy(garlic, &initiator, &updated_initiator);
            }
        }

        Ok(())
    }

    fn create_updated_proxy(proxy: &Proxy, old_node: &CloveNode, new_node: &CloveNode) -> Proxy {
        let mut updated = proxy.clone();
        if proxy.neighbor_1 == *old_node {
            updated.neighbor_1 = new_node.clone();
        } else if proxy.neighbor_2 == *old_node {
            updated.neighbor_2 = new_node.clone();
        }
        updated
    }

    async fn update_alt_node_state(
        garlic: &mut GarlicCast,
        old_node: &CloveNode,
        new_node: &CloveNode,
        sequence: U256,
        node: &Node,
    ) -> Result<(), MessageError> {
        garlic.cache.replace_with_alt_node(old_node);

        if let Some(my_alt_for_seq) = garlic.cache.my_alt_nodes.get(&sequence).cloned() {
            AltRoutes::send_alt(garlic, Some(new_node.clone()), None, my_alt_for_seq.clone()).await;
            AltRoutes::update_my_alt_next_or_last(
                garlic,
                my_alt_for_seq,
                old_node.node.clone(),
                node.clone(),
            )
            .await;
        }

        Ok(())
    }

    fn get_actual_sequence_number(
        garlic: &GarlicCast,
        sequence_number: U256,
        clove_node: &CloveNode,
    ) -> U256 {
        garlic
            .cache
            .get_sequence_from_alt(clove_node.clone())
            .unwrap_or(sequence_number)
    }

    async fn process_forward(
        garlic: &mut GarlicCast,
        next_info: Option<CloveNode>,
        node: Node,
        sequence_number: U256,
        am_alt: bool,
        sn_actual: U256,
        msg: &GarlicMessage,
        clove: Clove,
    ) -> Result<Option<CloveMessage>, MessageError> {
        match next_info {
            Some(next_node) => {
                Self::handle_forward_to_next(
                    garlic,
                    node,
                    next_node,
                    sequence_number,
                    am_alt,
                    sn_actual,
                    &clove,
                )
                .await
            }
            None => {
                Self::handle_message_collection(
                    garlic,
                    clove.request_id,
                    msg.clone(),
                    sequence_number,
                )
                .await
            }
        }
    }

    async fn handle_forward_to_next(
        garlic: &mut GarlicCast,
        node: Node,
        next_node: CloveNode,
        sequence_number: U256,
        am_alt: bool,
        sn_actual: U256,
        msg: &Clove,
    ) -> Result<Option<CloveMessage>, MessageError> {
        if am_alt {
            let new_alt = AltRoutes::find_alt(
                garlic,
                Some(node.clone()),
                Some(next_node.node.clone()),
                sn_actual,
            )
            .await;
            AltRoutes::send_alt(
                garlic,
                Some(CloveNode {
                    node,
                    sequence_number,
                }),
                Some(next_node.clone()),
                new_alt,
            )
            .await;
            garlic.cache.am_alt_for.remove(&sequence_number);
        }

        Forwarding::forward(garlic, &next_node, msg).await;
        Ok(None)
    }

    async fn handle_message_collection(
        garlic: &mut GarlicCast,
        request_id: CloveRequestID,
        garlic_msg: GarlicMessage,
        sequence_number: U256,
    ) -> Result<Option<CloveMessage>, MessageError> {
        let existing_msg = garlic.collected_messages.get(&request_id);

        match existing_msg {
            Some(message) => {
                let messages = vec![message.clone(), garlic_msg.clone()];
                Self::process_collected_messages(garlic, messages, request_id, sequence_number)
                    .await
            }
            None => {
                garlic.collected_messages.insert(request_id, garlic_msg);
                Ok(None)
            }
        }
    }

    async fn process_collected_messages(
        garlic: &mut GarlicCast,
        messages: Vec<GarlicMessage>,
        request_id: CloveRequestID,
        sequence_number: U256,
    ) -> Result<Option<CloveMessage>, MessageError> {
        let cloves = vec![messages[0].clove().unwrap(), messages[1].clove().unwrap()];

        if cloves.len() != 2 {
            log::error!(
                "{}: Invalid number of cloves for reconstruction",
                garlic.local_node.address
            );
            return Ok(None);
        }

        // Reconstruct the encrypted clove message
        let msg_from_proxy = CloveProtocol::reconstruct_encrypted(
            cloves[0].clone(),
            cloves[1].clone(),
            garlic.private_key.clone().unwrap(),
        )
        .map_err(|_| MessageError::InvalidMessage)?;

        if !msg_from_proxy.is_request() {
            log::error!(
                "{}: Expected request message but got response",
                garlic.local_node.address
            );
            return Ok(None);
        }

        // Clean up collected messages
        garlic.collected_messages.remove(&request_id);

        // Handle the message based on role (initiator or proxy)
        let request_id = msg_from_proxy.request_id().unwrap().request_id;
        if let Some(request_info) = garlic.requests_as_initiator.get_mut(&request_id) {
            // This node is the initiator
            let mut request_info = request_info.clone();
            let result = Self::handle_initiator_message(&mut request_info, msg_from_proxy).await;
            garlic
                .requests_as_initiator
                .insert(request_id, request_info);
            result
        } else {
            // This node is the proxy
            Self::handle_proxy_message(garlic, sequence_number, msg_from_proxy).await
        }
    }

    async fn handle_initiator_message(
        request_info: &mut InitiatorRequest,
        msg: CloveMessage,
    ) -> Result<Option<CloveMessage>, MessageError> {
        let mut trimmed_msg = Some(msg.clone());

        // Handle special message types that don't need to be stored
        if let CloveMessage::Response { data, .. } = msg.clone() {
            match data {
                GarlemliaResponse::ChunkPart { .. }
                | GarlemliaResponse::ChunkPartInfo { .. }
                | GarlemliaResponse::FileChunkInfo { .. } => {
                    trimmed_msg = None;
                }
                _ => {}
            }
        }

        // Store the response if needed
        if let Some(msg) = trimmed_msg {
            request_info.responses.push(msg.clone());
        }

        Ok(Some(msg))
    }

    async fn handle_proxy_message(
        garlic: &mut GarlicCast,
        sequence_number: U256,
        msg: CloveMessage,
    ) -> Result<Option<CloveMessage>, MessageError> {
        let request_id = msg.request_id().unwrap().request_id;
        let initiator = garlic
            .get_initiator(sequence_number)
            .ok_or(MessageError::MissingNode)?;

        let garlic_proxy_id = msg.proxy_id();
        let validator_required = garlic_proxy_id.is_some();

        // Store proxy request information
        garlic.requests_as_proxy.insert(
            request_id,
            ProxyRequest {
                sequence_number,
                request_id,
                validator_required,
                initiator,
                sent: Utc::now(),
                request: msg.clone(),
                self_proxy_id: None,
            },
        );

        Ok(ProxyRuntime::manage_proxy_message(msg).await)
    }

    async fn handle_find_proxy(
        garlic: &mut GarlicCast,
        node: Node,
        sequence_number: U256,
        clove: Clove,
    ) -> CloveResult {
        if garlic.do_not_forward.contains_key(&sequence_number) {
            return Ok(DEFAULT_RESPONSE);
        }

        let actual_source_node = Self::determine_source_node(garlic, &node, &clove);
        garlic.cache.seen(sequence_number);

        // Handle existing clove case
        if Self::is_existing_non_duplicate_clove(garlic, sequence_number, &clove) {
            return Self::handle_existing_clove(
                garlic,
                node,
                sequence_number,
                clove,
                actual_source_node,
            )
            .await;
        }

        // Handle new clove case
        if random_bool(FORWARD_P) {
            Forwarding::forward_find_proxy(garlic, sequence_number, actual_source_node, clove)
                .await;
        } else {
            Self::cache_new_clove(garlic, sequence_number, actual_source_node, clove);
        }

        Ok(DEFAULT_RESPONSE)
    }

    async fn handle_forward(
        garlic: &mut GarlicCast,
        node: Node,
        garlic_msg: GarlicMessage,
        sequence_number: U256,
        clove: Clove,
    ) -> Result<Option<CloveMessage>, MessageError> {
        let clove_node = CloveNode {
            sequence_number,
            node: node.clone(),
        };

        garlic.cache.seen(sequence_number);
        let am_alt = garlic.cache.am_alt_for.contains(&sequence_number);

        // Try to handle alternative route if initial forward fails
        if let Err(_) = garlic.cache.get_forward_node(clove_node.clone()) {
            Self::handle_alternative_route(garlic, &clove_node, &node).await?;
        }

        // Get actual sequence number after potential alt route handling
        let sn_actual = Self::get_actual_sequence_number(garlic, sequence_number, &clove_node);

        // Handle message forwarding or processing
        match garlic.cache.get_forward_node(clove_node.clone()) {
            Ok(next_info) => {
                Self::process_forward(
                    garlic,
                    next_info,
                    node,
                    sequence_number,
                    am_alt,
                    sn_actual,
                    &garlic_msg,
                    clove,
                )
                .await
            }
            Err(_) => {
                log::warn!("{} :: COULD NOT FIND ANYWHERE TO FORWARD THIS AND I AM NOT AN INITIATOR OR PROXY :: {}",
                      Utc::now(), garlic.local_node.address);
                Ok(None)
            }
        }
    }

    /// Handles a ProxyAgree message received from another node
    async fn handle_proxy_agree(
        garlic: &mut GarlicCast,
        node: Node,
        garlic_msg: GarlicMessage,
        socket: Arc<UdpSocket>,
        sequence_number: U256,
        updated_sequence_number: U256,
        hops: u16,
        clove: Clove,
    ) -> Result<Option<CloveMessage>, MessageError> {
        // Update cache with sequence numbers
        let old_clove_node = CloveNode {
            sequence_number,
            node: node.clone(),
        };
        garlic
            .cache
            .update_sequence_number(updated_sequence_number, old_clove_node.clone());
        garlic.cache.seen(sequence_number);
        garlic.cache.seen(updated_sequence_number);

        // Create new proxy agree message for forwarding
        let new_proxy_agree = GarlicMessage::ProxyAgree {
            sequence_number,
            updated_sequence_number,
            hops: hops + 1,
            clove: clove.clone(),
        };

        // Get next node in forwarding chain
        let next = garlic.cache.get_forward_node(CloveNode {
            sequence_number: updated_sequence_number,
            node: node.clone(),
        });

        match next {
            Ok(Some(next_node)) => {
                // Forward to next node
                if let Err(e) = garlic
                    .message_handler
                    .send(
                        &Arc::from(socket.clone()),
                        garlic.local_node.clone(),
                        &next_node.node.address,
                        &GarlicMessage::build_send(garlic.local_node.clone(), new_proxy_agree),
                    )
                    .await
                {
                    log::error!(
                        "Failed to send Forward to {}: {:?}",
                        next_node.node.address,
                        e
                    );
                    return Ok(None);
                }

                // Wait for response
                let response = garlic
                    .message_handler
                    .recv(200, &next_node.node.address)
                    .await;

                match response {
                    Ok(_) => {
                        let new_alt = AltRoutes::find_alt(
                            garlic,
                            Some(node.clone()),
                            Some(next_node.node.clone()),
                            updated_sequence_number,
                        )
                        .await;

                        AltRoutes::send_alt(
                            garlic,
                            Some(CloveNode {
                                node,
                                sequence_number: updated_sequence_number,
                            }),
                            Some(next_node),
                            new_alt,
                        )
                        .await;
                    }
                    Err(_) => {
                        log::error!(
                            "{} FAILED TO SEND TO {}",
                            garlic.local_node.address,
                            next_node.node.address
                        );
                        garlic.cache.remove_sequence(sequence_number);
                        garlic.cache.remove_sequence(updated_sequence_number);
                    }
                }
                Ok(None)
            }
            _ => {
                // Handle end of chain
                let new_alt =
                    AltRoutes::find_alt(garlic, Some(node.clone()), None, updated_sequence_number)
                        .await;
                AltRoutes::send_alt(
                    garlic,
                    Some(CloveNode {
                        node: node.clone(),
                        sequence_number: updated_sequence_number,
                    }),
                    None,
                    new_alt,
                )
                .await;

                Self::handle_collected_messages(
                    garlic,
                    clove,
                    garlic_msg,
                    node,
                    updated_sequence_number,
                    hops,
                )
                .await
            }
        }
    }

    async fn handle_collected_messages(
        garlic: &mut GarlicCast,
        clove: Clove,
        garlic_msg: GarlicMessage,
        node: Node,
        updated_sequence_number: U256,
        hops: u16,
    ) -> Result<Option<CloveMessage>, MessageError> {
        let messages_from =
            if let Some(message) = garlic.collected_messages.get(&clove.request_id).cloned() {
                garlic.collected_messages.remove(&clove.request_id);
                vec![message, garlic_msg]
            } else {
                garlic
                    .collected_messages
                    .insert(clove.request_id.clone(), garlic_msg);
                return Ok(None);
            };

        if messages_from.len() != 2 {
            return Ok(None);
        }

        let mut cloves = vec![clove];
        let mut neighbor_1_hops = 0;

        if let GarlicMessage::ProxyAgree { hops, clove, .. } = messages_from[0].clone() {
            neighbor_1_hops = hops;
            cloves.push(clove);
        }

        if cloves.len() != 2 {
            log::error!("{}: Invalid number of cloves", garlic.local_node.address);
            return Ok(None);
        }

        // Try to get the neighbor from partial proxies
        let neighbor_1 = garlic
            .partial_proxies
            .remove(&updated_sequence_number)
            .ok_or_else(|| {
                log::error!("{}: No partial proxy found", garlic.local_node.address);
                MessageError::MissingNode
            })?;

        // Reconstruct the encrypted message
        let msg_from_initiator = CloveProtocol::reconstruct_encrypted(
            cloves[0].clone(),
            cloves[1].clone(),
            garlic.private_key.clone().unwrap(),
        )
        .map_err(|_| MessageError::InvalidMessage)?;

        if let CloveMessage::ProxyInfo {
            public_key,
            starting_hops,
        } = msg_from_initiator
        {
            // Validate hop counts
            if hops <= starting_hops || neighbor_1_hops <= starting_hops {
                return Ok(None);
            }

            // Create and store the proxy
            let proxy = Proxy {
                sequence_number: updated_sequence_number,
                neighbor_1: CloveNode {
                    sequence_number: updated_sequence_number,
                    node: neighbor_1,
                },
                neighbor_2: CloveNode {
                    sequence_number: updated_sequence_number,
                    node,
                },
                neighbor_1_hops: neighbor_1_hops - starting_hops,
                neighbor_2_hops: hops - starting_hops,
                public_key: RsaPublicKey::from_public_key_pem(&public_key)
                    .map_err(|_| MessageError::InvalidKey)?,
                used_last: Utc::now(),
            };

            garlic.proxies.push(proxy);
        } else {
            log::error!(
                "{}: Invalid reconstructed message type",
                garlic.local_node.address
            );
        }

        Ok(None)
    }
}
