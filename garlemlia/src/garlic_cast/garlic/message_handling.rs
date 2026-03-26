use std::sync::Arc;
use chrono::Utc;
use primitive_types::U256;
use rand::random_bool;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;
use tokio::net::UdpSocket;
use crate::garlic_cast::garlic::alt_route_management::AltRouteManagement;
use crate::garlic_cast::garlic::clove_operations::CloveOperations;
use crate::garlic_cast::garlic::forwarding::Forwarding;
use crate::garlic_cast::garlic::proxy_management::ProxyManagement;
use crate::garlic_cast::garlic::proxy_request::ProxyRequest as OtherProxyRequest;
use crate::garlic_cast::request_info::{InitiatorRequest, Proxy, ProxyRequest};
use crate::structs::constants::{CloveResult, DEFAULT_RESPONSE};
use crate::structs::error::MessageError;
use crate::structs::garlemlia_message::{GarlemliaMessage, GarlemliaResponse};
use crate::structs::garlic_message::{Clove, CloveMessage, CloveNode, CloveRequestID, GarlicMessage};
use crate::structs::node::Node;
use super::{GarlicCast, FORWARD_P};

pub(crate) trait MessageHandling {
    async fn recv(&mut self, node: Node, garlic_msg: GarlicMessage) -> Result<Option<CloveMessage>, MessageError>;
    fn determine_source_node(&self, original_node: &Node, clove: &Clove) -> Node;
    fn is_existing_non_duplicate_clove(&self, sequence_number: U256, clove: &Clove) -> bool;
    async fn handle_existing_clove(&mut self, node: Node, sequence_number: U256,
                                   clove: Clove, source_node: Node) -> CloveResult;
    fn cache_new_clove(&mut self, sequence_number: U256, source_node: Node, clove: Clove);
    async fn handle_alternative_route(&mut self, clove_node: &CloveNode, node: &Node) -> Result<(), MessageError>;
    async fn update_proxy_references(&mut self, old_node: &CloveNode, new_node: &CloveNode, sequence: U256)
                                     -> Result<(), MessageError>;
    fn create_updated_proxy(&self, proxy: &Proxy, old_node: &CloveNode, new_node: &CloveNode) -> Proxy;
    async fn update_alt_node_state(&mut self, old_node: &CloveNode, new_node: &CloveNode,
                                   sequence: U256, node: &Node) -> Result<(), MessageError>;
    fn get_actual_sequence_number(&self, sequence_number: U256, clove_node: &CloveNode) -> U256;
    async fn process_forward(&mut self, next_info: Option<CloveNode>, node: Node,
                             sequence_number: U256, am_alt: bool, sn_actual: U256, msg: &GarlicMessage, clove: Clove)
                             -> Result<Option<CloveMessage>, MessageError>;
    async fn handle_forward_to_next(&mut self, node: Node, next_node: CloveNode,
                                    sequence_number: U256, am_alt: bool, sn_actual: U256, msg: &Clove)
                                    -> Result<Option<CloveMessage>, MessageError>;
    async fn handle_message_collection(&mut self, request_id: CloveRequestID,
                                       garlic_msg: GarlicMessage, sequence_number: U256)
                                       -> Result<Option<CloveMessage>, MessageError>;
    async fn process_collected_messages(&mut self, messages: Vec<GarlicMessage>, request_id: CloveRequestID, sequence_number: U256)
                                        -> Result<Option<CloveMessage>, MessageError>;
    async fn handle_initiator_message(&mut self, request_info: &mut InitiatorRequest, msg: CloveMessage)
                                      -> Result<Option<CloveMessage>, MessageError>;
    async fn handle_proxy_message(&mut self, sequence_number: U256, msg: CloveMessage)
                                  -> Result<Option<CloveMessage>, MessageError>;
    async fn handle_find_proxy(&mut self, node: Node, sequence_number: U256, clove: Clove) -> CloveResult;
    async fn handle_forward(&mut self, node: Node, garlic_msg: GarlicMessage, sequence_number: U256, clove: Clove)
                            -> Result<Option<CloveMessage>, MessageError>;
    async fn handle_proxy_agree(
        &mut self,
        node: Node,
        garlic_msg: GarlicMessage,
        socket: Arc<UdpSocket>,
        sequence_number: U256,
        updated_sequence_number: U256,
        hops: u16,
        clove: Clove
    ) -> Result<Option<CloveMessage>, MessageError>;
    async fn handle_collected_messages(
        &mut self,
        clove: Clove,
        garlic_msg: GarlicMessage,
        node: Node,
        updated_sequence_number: U256,
        hops: u16,
    ) -> Result<Option<CloveMessage>, MessageError>;
}

impl MessageHandling for GarlicCast {
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
    async fn recv(&mut self, node: Node, garlic_msg: GarlicMessage) -> Result<Option<CloveMessage>, MessageError> {
        let socket = Arc::clone(&self.socket);
        match garlic_msg.clone() {
            GarlicMessage::FindProxy { sequence_number, clove } => {
                self.handle_find_proxy(node, sequence_number, clove).await
            }
            GarlicMessage::Forward { sequence_number, clove } => {
                self.handle_forward(node, garlic_msg, sequence_number, clove).await
            }
            GarlicMessage::ProxyAgree { sequence_number, updated_sequence_number, hops, clove } => {
                self.handle_proxy_agree(node, garlic_msg, socket, sequence_number, updated_sequence_number, hops, clove).await
            }
            GarlicMessage::RequestAlt { alt_sequence_number, last_hop, next_hop } => {
                // TODO: Include some logic so that this node can decide to be an alternate or backup node
                // For now, just add it

                let lh_clove = CloveNode { sequence_number: alt_sequence_number, node: last_hop.clone() };
                let nh_clove = CloveNode { sequence_number: alt_sequence_number, node: next_hop.clone() };

                self.cache.insert_next_hop(lh_clove.clone(), Some(nh_clove.clone()));
                self.cache.insert_next_hop(nh_clove.clone(), Some(lh_clove.clone()));
                // Insert associations
                self.cache.insert_association(alt_sequence_number, lh_clove.clone());
                self.cache.insert_association(alt_sequence_number, nh_clove.clone());
                // Insert am alt for
                self.cache.insert_am_alt(alt_sequence_number);
                // Insert seen last
                self.cache.seen(alt_sequence_number);

                let agree_alt = GarlemliaMessage::AgreeAlt {
                    alt_sequence_number,
                    sender: self.local_node.clone(),
                };

                {
                    if let Err(e) = self.message_handler.send_no_recv(&Arc::from(socket), self.local_node.clone(), &node.address, &agree_alt).await {
                        eprintln!("Failed to send Forward to {}: {:?}", node.address, e);
                    }
                }

                Ok(None)
            }
            GarlicMessage::RefreshAlt { sequence_number } => {
                self.cache.seen(sequence_number);

                Ok(None)
            }
            GarlicMessage::UpdateAlt { sequence_number, alt_node } => {
                let clove_node = CloveNode { sequence_number, node };

                self.cache.insert_alt_node(clove_node.clone(), alt_node.clone());

                Ok(None)
            }
            GarlicMessage::UpdateAltNextOrLast { sequence_number, old_node, new_node } => {
                self.cache.seen(sequence_number);

                let old_clove_node = CloveNode { sequence_number, node: old_node.clone() };
                let new_clove_node = CloveNode { sequence_number, node: new_node.clone() };

                if self.cache.am_alt_for.contains(&sequence_number) {
                    self.cache.insert_alt_node(old_clove_node.clone(), new_clove_node.clone());
                    self.cache.replace_with_alt_node(&old_clove_node);
                }

                Ok(None)
            }
            GarlicMessage::ResponseDirect { request_id, clove_1, clove_2 } => {
                let current_request = self.requests_as_proxy.get(&request_id.request_id).cloned();

                if current_request.is_some() {
                    let proxy = current_request.unwrap().initiator.clone();

                    let new_request_id_index = rand::random::<u64>();
                    let mut new_clove_1 = clove_1.clone();
                    let mut new_clove_2 = clove_2.clone();
                    new_clove_1.sequence_number = proxy.sequence_number;
                    new_clove_1.request_id.index = new_request_id_index;

                    new_clove_2.sequence_number = proxy.sequence_number;
                    new_clove_2.request_id.index = new_request_id_index;

                    self.send_to_proxy(proxy, vec![new_clove_1, new_clove_2]).await;
                }

                Ok(None)
            }
            GarlicMessage::FileChunkPart { request_id, data } => {
                Ok(Some(CloveMessage::FileChunkPart {
                    request_id,
                    data,
                }))
            }
        }
    }

    fn determine_source_node(&self, original_node: &Node, clove: &Clove) -> Node {
        let clove_data = self.cache.cloves.clone();

        for (_, data) in clove_data {
            if data.clove == *clove {
                return data.from;
            }
        }

        original_node.clone()
    }

    fn is_existing_non_duplicate_clove(&self, sequence_number: U256, clove: &Clove) -> bool {
        let is_existing = self.cache.cloves.contains_key(&sequence_number);
        let mut has_same_clove = false;

        for (_, data) in self.cache.cloves.clone() {
            if data.clove == *clove {
                has_same_clove = true;
                break;
            }
        }

        is_existing && !has_same_clove
    }

    async fn handle_existing_clove(&mut self, node: Node, sequence_number: U256,
                                   clove: Clove, source_node: Node) -> CloveResult {
        let new_proxy = self.accept_proxy(sequence_number, clove, source_node).await?;
        let new_alt = self.find_alt(Some(node.clone()), None, new_proxy.sequence_number).await;

        let clove_node = CloveNode {
            node,
            sequence_number: new_proxy.sequence_number
        };

        self.send_alt(Some(clove_node), None, new_alt).await;
        Ok(DEFAULT_RESPONSE)
    }

    fn cache_new_clove(&mut self, sequence_number: U256, source_node: Node, clove: Clove) {
        let original_clove = CloveNode {
            sequence_number,
            node: source_node.clone()
        };

        self.cache.insert_next_hop(original_clove.clone(), None);
        self.cache.insert_clove(clove, source_node.clone());
        self.cache.insert_association(sequence_number, original_clove);
        self.cache.seen(sequence_number);
    }

    async fn handle_alternative_route(&mut self, clove_node: &CloveNode, node: &Node) -> Result<(), MessageError> {
        if let Some(sequence_try) = self.cache.alt_to_sequence.get(clove_node).cloned() {
            if let Some(old_node) = self.cache.get_old_from_alt(clove_node) {
                self.update_proxy_references(&old_node, clove_node, sequence_try).await?;
                self.update_alt_node_state(&old_node, clove_node, sequence_try, node).await?;
            }
        }
        Ok(())
    }

    async fn update_proxy_references(&mut self, old_node: &CloveNode, new_node: &CloveNode, sequence: U256)
                                     -> Result<(), MessageError>
    {
        let proxies = self.proxies.clone();
        let initiators = self.initiators.clone();

        // Update proxy references
        for proxy in proxies {
            if proxy.sequence_number == sequence {
                let updated_proxy = self.create_updated_proxy(&proxy, old_node, new_node);
                self.replace_proxy(&proxy, &updated_proxy);
            }
        }

        // Update initiator references
        for initiator in initiators {
            if initiator.sequence_number == sequence {
                let updated_initiator = self.create_updated_proxy(&initiator, old_node, new_node);
                self.replace_proxy(&initiator, &updated_initiator);
            }
        }

        Ok(())
    }

    fn create_updated_proxy(&self, proxy: &Proxy, old_node: &CloveNode, new_node: &CloveNode) -> Proxy {
        let mut updated = proxy.clone();
        if proxy.neighbor_1 == *old_node {
            updated.neighbor_1 = new_node.clone();
        } else if proxy.neighbor_2 == *old_node {
            updated.neighbor_2 = new_node.clone();
        }
        updated
    }

    async fn update_alt_node_state(&mut self, old_node: &CloveNode, new_node: &CloveNode,
                                   sequence: U256, node: &Node) -> Result<(), MessageError>
    {
        self.cache.replace_with_alt_node(old_node);

        if let Some(my_alt_for_seq) = self.cache.my_alt_nodes.get(&sequence).cloned() {
            self.send_alt(Some(new_node.clone()), None, my_alt_for_seq.clone()).await;
            self.update_my_alt_next_or_last(my_alt_for_seq, old_node.node.clone(), node.clone()).await;
        }

        Ok(())
    }

    fn get_actual_sequence_number(&self, sequence_number: U256, clove_node: &CloveNode) -> U256 {
        self.cache.get_sequence_from_alt(clove_node.clone())
            .unwrap_or(sequence_number)
    }

    async fn process_forward(&mut self, next_info: Option<CloveNode>, node: Node,
                             sequence_number: U256, am_alt: bool, sn_actual: U256, msg: &GarlicMessage, clove: Clove)
                             -> Result<Option<CloveMessage>, MessageError>
    {
        match next_info {
            Some(next_node) => self.handle_forward_to_next(node, next_node, sequence_number, am_alt, sn_actual, &clove).await,
            None => self.handle_message_collection(clove.request_id, msg.clone(), sequence_number).await
        }
    }

    async fn handle_forward_to_next(&mut self, node: Node, next_node: CloveNode,
                                    sequence_number: U256, am_alt: bool, sn_actual: U256, msg: &Clove)
                                    -> Result<Option<CloveMessage>, MessageError>
    {
        if am_alt {
            let new_alt = self.find_alt(Some(node.clone()), Some(next_node.node.clone()), sn_actual).await;
            self.send_alt(
                Some(CloveNode { node, sequence_number }),
                Some(next_node.clone()),
                new_alt
            ).await;
            self.cache.am_alt_for.remove(&sequence_number);
        }

        self.forward(&next_node, msg).await;
        Ok(None)
    }

    async fn handle_message_collection(&mut self, request_id: CloveRequestID,
                                       garlic_msg: GarlicMessage, sequence_number: U256)
                                       -> Result<Option<CloveMessage>, MessageError>
    {
        let existing_msg = self.collected_messages.get(&request_id);

        match existing_msg {
            Some(message) => {
                let messages = vec![message.clone(), garlic_msg.clone()];
                self.process_collected_messages(messages, request_id, sequence_number).await
            }
            None => {
                self.collected_messages.insert(request_id, garlic_msg);
                Ok(None)
            }
        }
    }

    async fn process_collected_messages(&mut self, messages: Vec<GarlicMessage>, request_id: CloveRequestID, sequence_number: U256)
                                        -> Result<Option<CloveMessage>, MessageError>
    {
        let cloves = vec![
            messages[0].clove().unwrap(),
            messages[1].clove().unwrap()
        ];

        if cloves.len() != 2 {
            log::error!("{}: Invalid number of cloves for reconstruction", self.local_node.address);
            return Ok(None);
        }

        // Reconstruct the encrypted clove message
        let msg_from_proxy = GarlicCast::reconstruct_encrypted_clove_message(
            cloves[0].clone(),
            cloves[1].clone(),
            self.private_key.clone().unwrap()
        ).map_err(|_| MessageError::InvalidMessage)?;

        if !msg_from_proxy.is_request() {
            log::error!("{}: Expected request message but got response", self.local_node.address);
            return Ok(None);
        }

        // Clean up collected messages
        self.collected_messages.remove(&request_id);

        // Handle the message based on role (initiator or proxy)
        let request_id = msg_from_proxy.request_id().unwrap().request_id;
        if let Some(request_info) = self.requests_as_initiator.get_mut(&request_id) {
            // This node is the initiator
            let mut request_info = request_info.clone();
            let result = self.handle_initiator_message(&mut request_info, msg_from_proxy).await;
            self.requests_as_initiator.insert(request_id, request_info);
            result
        } else {
            // This node is the proxy
            self.handle_proxy_message(sequence_number, msg_from_proxy).await
        }
    }

    async fn handle_initiator_message(&mut self, request_info: &mut InitiatorRequest, msg: CloveMessage)
                                      -> Result<Option<CloveMessage>, MessageError>
    {
        let mut trimmed_msg = Some(msg.clone());

        // Handle special message types that don't need to be stored
        if let CloveMessage::Response { data, .. } = msg.clone() {
            match data {
                GarlemliaResponse::ChunkPart { .. } |
                GarlemliaResponse::ChunkPartInfo { .. } |
                GarlemliaResponse::FileChunkInfo { .. } => {
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

    async fn handle_proxy_message(&mut self, sequence_number: U256, msg: CloveMessage)
                                  -> Result<Option<CloveMessage>, MessageError>
    {
        let request_id = msg.request_id().unwrap().request_id;
        let initiator = self.get_initiator(sequence_number)
            .ok_or(MessageError::MissingNode)?;

        let self_proxy_id = msg.proxy_id();
        let validator_required = self_proxy_id.is_some();

        // Store proxy request information
        self.requests_as_proxy.insert(request_id, ProxyRequest {
            sequence_number,
            request_id,
            self_proxy_id,
            validator_required,
            initiator,
            sent: Utc::now(),
            request: msg.clone()
        });

        Ok(self.manage_proxy_message(msg).await)
    }

    async fn handle_find_proxy(&mut self, node: Node, sequence_number: U256, clove: Clove) -> CloveResult {
        if self.do_not_forward.contains_key(&sequence_number) {
            return Ok(DEFAULT_RESPONSE);
        }

        let actual_source_node = self.determine_source_node(&node, &clove);
        self.cache.seen(sequence_number);

        // Handle existing clove case
        if self.is_existing_non_duplicate_clove(sequence_number, &clove) {
            return self.handle_existing_clove(node, sequence_number, clove, actual_source_node).await;
        }

        // Handle new clove case
        if random_bool(FORWARD_P) {
            self.forward_find_proxy(sequence_number, actual_source_node, clove).await;
        } else {
            self.cache_new_clove(sequence_number, actual_source_node, clove);
        }

        Ok(DEFAULT_RESPONSE)
    }

    async fn handle_forward(&mut self, node: Node, garlic_msg: GarlicMessage, sequence_number: U256, clove: Clove)
                            -> Result<Option<CloveMessage>, MessageError>
    {
        let clove_node = CloveNode { sequence_number, node: node.clone() };

        self.cache.seen(sequence_number);
        let am_alt = self.cache.am_alt_for.contains(&sequence_number);

        // Try to handle alternative route if initial forward fails
        if let Err(_) = self.cache.get_forward_node(clove_node.clone()) {
            self.handle_alternative_route(&clove_node, &node).await?;
        }

        // Get actual sequence number after potential alt route handling
        let sn_actual = self.get_actual_sequence_number(sequence_number, &clove_node);

        // Handle message forwarding or processing
        match self.cache.get_forward_node(clove_node.clone()) {
            Ok(next_info) => self.process_forward(next_info, node, sequence_number, am_alt, sn_actual, &garlic_msg, clove).await,
            Err(_) => {
                log::warn!("{} :: COULD NOT FIND ANYWHERE TO FORWARD THIS AND I AM NOT AN INITIATOR OR PROXY :: {}",
                      Utc::now(), self.local_node.address);
                Ok(None)
            }
        }
    }

    /// Handles a ProxyAgree message received from another node
    async fn handle_proxy_agree(
        &mut self,
        node: Node,
        garlic_msg: GarlicMessage,
        socket: Arc<UdpSocket>,
        sequence_number: U256,
        updated_sequence_number: U256,
        hops: u16,
        clove: Clove
    ) -> Result<Option<CloveMessage>, MessageError> {
        // Update cache with sequence numbers
        let old_clove_node = CloveNode { sequence_number, node: node.clone() };
        self.cache.update_sequence_number(updated_sequence_number, old_clove_node.clone());
        self.cache.seen(sequence_number);
        self.cache.seen(updated_sequence_number);

        // Create new proxy agree message for forwarding
        let new_proxy_agree = GarlicMessage::ProxyAgree {
            sequence_number,
            updated_sequence_number,
            hops: hops + 1,
            clove: clove.clone(),
        };

        // Get next node in forwarding chain
        let next = self.cache.get_forward_node(CloveNode {
            sequence_number: updated_sequence_number,
            node: node.clone()
        });

        match next {
            Ok(Some(next_node)) => {
                // Forward to next node
                if let Err(e) = self.message_handler.send(
                    &Arc::from(socket.clone()),
                    self.local_node.clone(),
                    &next_node.node.address,
                    &GarlicMessage::build_send(self.local_node.clone(), new_proxy_agree)
                ).await {
                    log::error!("Failed to send Forward to {}: {:?}", next_node.node.address, e);
                    return Ok(None);
                }

                // Wait for response
                let response = self.message_handler.recv(200, &next_node.node.address).await;

                match response {
                    Ok(_) => {
                        let new_alt = self.find_alt(
                            Some(node.clone()),
                            Some(next_node.node.clone()),
                            updated_sequence_number
                        ).await;

                        self.send_alt(
                            Some(CloveNode { node, sequence_number: updated_sequence_number }),
                            Some(next_node),
                            new_alt
                        ).await;
                    }
                    Err(_) => {
                        log::error!("{} FAILED TO SEND TO {}", self.local_node.address, next_node.node.address);
                        self.cache.remove_sequence(sequence_number);
                        self.cache.remove_sequence(updated_sequence_number);
                    }
                }
                Ok(None)
            }
            _ => {
                // Handle end of chain
                let new_alt = self.find_alt(Some(node.clone()), None, updated_sequence_number).await;
                self.send_alt(
                    Some(CloveNode { node: node.clone(), sequence_number: updated_sequence_number }),
                    None,
                    new_alt
                ).await;

                self.handle_collected_messages(clove, garlic_msg, node, updated_sequence_number, hops).await
            }
        }
    }

    async fn handle_collected_messages(
        &mut self,
        clove: Clove,
        garlic_msg: GarlicMessage,
        node: Node,
        updated_sequence_number: U256,
        hops: u16,
    ) -> Result<Option<CloveMessage>, MessageError> {
        let messages_from = if let Some(message) = self.collected_messages.get(&clove.request_id).cloned() {
            self.collected_messages.remove(&clove.request_id);
            vec![message, garlic_msg]
        } else {
            self.collected_messages.insert(clove.request_id.clone(), garlic_msg);
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
            log::error!("{}: Invalid number of cloves", self.local_node.address);
            return Ok(None);
        }

        // Try to get the neighbor from partial proxies
        let neighbor_1 = self.partial_proxies.remove(&updated_sequence_number)
            .ok_or_else(|| {
                log::error!("{}: No partial proxy found", self.local_node.address);
                MessageError::MissingNode
            })?;

        // Reconstruct the encrypted message
        let msg_from_initiator = GarlicCast::reconstruct_encrypted_clove_message(
            cloves[0].clone(),
            cloves[1].clone(),
            self.private_key.clone().unwrap()
        ).map_err(|_| MessageError::InvalidMessage)?;

        if let CloveMessage::ProxyInfo { public_key, starting_hops } = msg_from_initiator {
            // Validate hop counts
            if hops <= starting_hops || neighbor_1_hops <= starting_hops {
                return Ok(None);
            }

            // Create and store the proxy
            let proxy = Proxy {
                sequence_number: updated_sequence_number,
                neighbor_1: CloveNode { sequence_number: updated_sequence_number, node: neighbor_1 },
                neighbor_2: CloveNode { sequence_number: updated_sequence_number, node },
                neighbor_1_hops: neighbor_1_hops - starting_hops,
                neighbor_2_hops: hops - starting_hops,
                public_key: RsaPublicKey::from_public_key_pem(&public_key)
                    .map_err(|_| MessageError::InvalidKey)?,
                used_last: Utc::now(),
            };

            self.proxies.push(proxy);
        } else {
            log::error!("{}: Invalid reconstructed message type", self.local_node.address);
        }

        Ok(None)
    }
}