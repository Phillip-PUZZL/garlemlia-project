use chrono::{DateTime, Utc};
use primitive_types::U256;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::net::UdpSocket;

use crate::garlic_cast::clove_cache::{CloveCache, SerializableCloveCache};
use crate::garlic_cast::request_info::{InitiatorRequest, Proxy, ProxyRequest, SerializableInitiatorRequest, SerializableProxy, SerializableProxyRequest};
use crate::structs::error::MessageError;
use crate::structs::garlemlia_message::{GMessage, GarlemliaMessage, GarlemliaMessageHandler};
use crate::structs::garlic_message::{Clove, CloveNode, CloveRequestID, GarlicMessage};
use crate::structs::node::Node;

mod proxy_management;
mod alt_route_management;
mod clove_operations;
pub(crate) mod file_operations;
mod forwarding;
pub(crate) mod message_handling;
mod search_operations;
mod utils;
pub(crate) mod proxy_request;
pub(crate) mod response_handling;

use forwarding::Forwarding;
use proxy_management::ProxyManagement;

pub const FORWARD_P: f64 = 0.95;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableGarlicCast {
    local_node: Node,
    pub known_nodes: Vec<Node>,
    proxies: Vec<SerializableProxy>,
    initiators: Vec<SerializableProxy>,
    partial_proxies: HashMap<U256, Node>,
    cache: SerializableCloveCache,
    requests_as_initiator: HashMap<U256, SerializableInitiatorRequest>,
    requests_as_proxy: HashMap<U256, SerializableProxyRequest>,
    do_not_forward: HashMap<U256, DateTime<Utc>>,
    pub public_key: String,
    pub private_key: String
}

impl SerializableGarlicCast {
    pub fn from(garlic: GarlicCast) -> SerializableGarlicCast {
        SerializableGarlicCast {
            local_node: garlic.local_node.clone(),
            known_nodes: garlic.known_nodes.clone(),
            proxies: SerializableProxy::vec_to_serializable(garlic.proxies.clone()),
            initiators: SerializableProxy::vec_to_serializable(garlic.initiators.clone()),
            partial_proxies: garlic.partial_proxies.clone(),
            cache: SerializableCloveCache::from(garlic.cache.clone()),
            requests_as_initiator: SerializableInitiatorRequest::hashmap_to_serializable(garlic.requests_as_initiator.clone()),
            requests_as_proxy: SerializableProxyRequest::hashmap_to_serializable(garlic.requests_as_proxy.clone()),
            do_not_forward: garlic.do_not_forward.clone(),
            public_key: garlic.public_key.unwrap().to_public_key_pem(rsa::pkcs8::LineEnding::LF).unwrap(),
            private_key: garlic.private_key.unwrap().to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap().to_string()
        }
    }

    pub fn to_garlic(self, socket: UdpSocket) -> GarlicCast {
        GarlicCast {
            socket: Arc::new(socket),
            local_node: self.local_node,
            message_handler: Arc::new(GarlemliaMessageHandler::create(0)),
            known_nodes: self.known_nodes,
            proxies: SerializableProxy::vec_to_proxy(self.proxies),
            initiators: SerializableProxy::vec_to_proxy(self.initiators),
            partial_proxies: self.partial_proxies,
            cache: self.cache.to_clove_cache(),
            collected_messages: HashMap::new(),
            searches_checked: HashSet::new(),
            requests_as_initiator: SerializableInitiatorRequest::hashmap_to_initiator_request(self.requests_as_initiator),
            requests_as_proxy: SerializableProxyRequest::hashmap_to_proxy_request(self.requests_as_proxy),
            do_not_forward: self.do_not_forward,
            public_key: Some(RsaPublicKey::from_public_key_pem(&*self.public_key).unwrap()),
            private_key: Some(RsaPrivateKey::from_pkcs8_pem(&*self.private_key).unwrap())
        }
    }
}

/// `GarlicCast` is a data structure that represents the state and behavior of a network communication entity
/// in a decentralized communication protocol. It uses mechanisms such as message handling,
/// node discovery, and message forwarding to enable secure and anonymous communication.
///
/// # Fields
///
/// * `socket` - A thread-safe reference to a UDP socket (`Arc<UdpSocket>`) used for network communication.
///
/// * `local_node` - The `Node` representing the local instance within the network.
///
/// * `message_handler` - A thread-safe boxed dynamic trait object (`Arc<Box<dyn GMessage>>`) used to handle
///   incoming and outgoing messages.
///
/// * `known_nodes` - A list of `Node` objects representing other known nodes in the network.
///
/// * `proxies` - A list of `Proxy` objects representing the nodes that act as fully established proxies
///   for the instance.
///
/// * `initiators` - A list of `Proxy` objects representing the nodes that act as communication initiators.
///
/// * `partial_proxies` - A mapping between partial proxy identifiers (`U256`) and associated `Node` objects,
///   representing nodes that are in the process of being established as proxies.
///
/// * `cache` - A `CloveCache` structure to store and manage cached data for improved performance and efficiency.
///
/// * `collected_messages` - A mapping of `CloveRequestID` to `GarlicMessage`, storing collected messages
///   for queries or requests.
///
/// * `searches_checked` - A `HashSet` containing `U256` identifiers that represent searches already checked
///   or processed.
///
/// * `requests_as_initiator` - A mapping of `U256` to `InitiatorRequest` objects, representing requests where
///   the local node acts as the initiator.
///
/// * `requests_as_proxy` - A mapping of `U256` to `ProxyRequest` objects, representing requests where the
///   local node acts as a proxy for message forwarding or relay.
///
/// * `do_not_forward` - A mapping of `U256` to `DateTime<Utc>`, representing requests or messages that should
///   not be forwarded and their expiration timestamps.
///
/// * `public_key` - An optional `RsaPublicKey` used for cryptographic operations, such as verifying signatures or
///   encrypting messages.
///
/// * `private_key` - An optional `RsaPrivateKey` used for cryptographic operations, such as signing or decrypting
///   messages.
///
/// # Functionality
///
/// The `GarlicCast` struct is designed to manage network communication, including
/// - Maintaining a list of known nodes and proxies in the network.
/// - Handling message routing, forwarding, and caching.
/// - Ensuring secure and anonymous communication using cryptographic public and private keys.
/// - Managing search queries and processing responses as an initiator or proxy.
/// - Avoiding message loops and redundant forwarding with the `do_not_forward` mechanism.
///
/// This struct is essential for coordinating decentralized network communication in protocols
/// that rely on garlemlia routing or similar mechanisms.
#[derive(Clone, Debug)]
pub struct GarlicCast {
    socket: Arc<UdpSocket>,
    local_node: Node,
    message_handler: Arc<Box<dyn GMessage>>,
    pub known_nodes: Vec<Node>,
    pub proxies: Vec<Proxy>,
    pub initiators: Vec<Proxy>,
    pub partial_proxies: HashMap<U256, Node>,
    pub cache: CloveCache,
    pub collected_messages: HashMap<CloveRequestID, GarlicMessage>,
    pub searches_checked: HashSet<U256>,
    pub requests_as_initiator: HashMap<U256, InitiatorRequest>,
    pub requests_as_proxy: HashMap<U256, ProxyRequest>,
    pub do_not_forward: HashMap<U256, DateTime<Utc>>,
    public_key: Option<RsaPublicKey>,
    private_key: Option<RsaPrivateKey>
}

impl GarlicCast {
    pub fn new(socket: Arc<UdpSocket>, local_node: Node, message_handler: Arc<Box<dyn GMessage>>, known_nodes: Vec<Node>, public_key: Option<RsaPublicKey>, private_key: Option<RsaPrivateKey>) -> GarlicCast {
        GarlicCast {
            socket,
            local_node,
            message_handler,
            known_nodes,
            proxies: Vec::new(),
            initiators: Vec::new(),
            partial_proxies: HashMap::new(),
            cache: CloveCache::new(),
            collected_messages: HashMap::new(),
            searches_checked: HashSet::new(),
            requests_as_initiator: HashMap::new(),
            requests_as_proxy: HashMap::new(),
            do_not_forward: HashMap::new(),
            public_key,
            private_key
        }
    }

    pub fn set_public_key(&mut self, public_key: RsaPublicKey) {
        self.public_key = Some(public_key);
    }

    pub fn set_private_key(&mut self, private_key: RsaPrivateKey) {
        self.private_key = Some(private_key);
    }

    pub fn update_from(&mut self, gc: GarlicCast) {
        self.socket =  gc.socket.clone();
        self.local_node = gc.local_node.clone();
        self.message_handler = gc.message_handler.clone();
        self.known_nodes = gc.known_nodes.clone();
        self.proxies = gc.proxies.clone();
        self.cache = gc.cache.clone();
        self.collected_messages = gc.collected_messages.clone();
        self.public_key = gc.public_key.clone();
        self.private_key = gc.private_key.clone();
    }

    pub fn update_known(&mut self, nodes: Vec<Node>) {
        self.known_nodes.extend(nodes);
        self.known_nodes.sort_by_key(|n| n.id);
        self.known_nodes.dedup();
        self.known_nodes.retain(|n| *n != self.local_node);
    }

    pub fn set_known(&mut self, nodes: Vec<Node>) {
        self.known_nodes.clear();
        self.known_nodes.extend(nodes);
    }

    // Example of removing async if not needed:
    pub fn get_proxies(&self) -> Vec<Proxy> {
        self.proxies.clone()
    }
    pub fn get_proxy(&self, sequence_number: U256) -> Option<Proxy> {
        self.proxies.iter().find(|p| p.sequence_number == sequence_number).cloned()
    }

    pub fn get_initiators(&self) -> Vec<Proxy> {
        self.initiators.clone()
    }

    pub fn get_initiator(&self, sequence_number: U256) -> Option<Proxy> {
        self.initiators.iter().find(|p| p.sequence_number == sequence_number).cloned()
    }

    pub fn check_search(&mut self, request_id: CloveRequestID) {
        self.searches_checked.insert(request_id.request_id);
    }

    pub fn has_search_checked(&self, request_id: CloveRequestID) -> bool {
        self.searches_checked.contains(&request_id.request_id)
    }

    fn create_initiator_request(&self, request_id: U256) -> InitiatorRequest {
        InitiatorRequest {
            request_id,
            validator_required: true,
            proxies: vec![],
            proxy_id_associations: HashMap::new(),
            responses: vec![],
        }
    }

    /// Sends cloves to a proxy and handles responses from neighboring clove nodes.
    ///
    /// This function forwards cloves to a proxy's neighboring nodes asynchronously. If the forward operation
    /// to a neighboring node fails, it performs recovery and cleanup actions, such as removing outdated
    /// sequences from the cache and updating or replacing the proxy if necessary.
    ///
    /// # Parameters
    /// - `&mut self`: Mutable reference to the current instance of the struct containing this method.
    /// - `proxy`: The `Proxy` object representing the target to which cloves are sent.
    /// - `cloves`: A vector of `Clove` objects that need to be forwarded.
    ///
    /// # Returns
    /// - `true` if all forwarding to the proxy's neighboring nodes succeeds.
    /// - `false` if any forwarding operation fails and recovery actions are performed.
    ///
    /// # Behavior
    /// 1. Extracts the first (`neighbor_1`) and second (`neighbor_2`) neighboring nodes from the proxy.
    /// 2. Sends the first clove to `neighbor_1` using the `forward_from_proxy` method:
    ///     - If the forwarding fails:
    ///         - Attempts to retrieve an alternative sequence for `neighbor_2` from the cache.
    ///         - Removes sequences related to `neighbor_2` and the proxy from the cache.
    ///         - Removes the proxy as it is no longer valid.
    ///         - Returns `false`.
    ///     - If successful and the response includes a replacement proxy:
    ///         - Updates the proxy to the new replacement proxy.
    /// 3. Sends the second clove to `neighbor_2` using the `forward_from_proxy` method:
    ///     - If the forwarding succeeds and the response includes a replacement proxy:
    ///         - Updates the proxy to the new replacement proxy.
    ///         - Returns `true`.
    ///     - If the forwarding fails:
    ///         - Attempts to retrieve an alternative sequence for `neighbor_1` from the cache.
    ///         - Removes sequences related to both neighbors and the proxy from the cache.
    ///         - Removes the proxy as it is no longer valid.
    ///         - Returns `false`.
    ///
    /// # Notes
    /// - The function leverages `async` functionality to perform asynchronous operations like forwarding cloves.
    /// - Proper error handling ensures that corrupted or invalid proxies and sequences are removed or updated,
    ///   maintaining system consistency.
    ///
    /// # Errors
    /// - This function relies on the outcome of the `forward_from_proxy` method, which indicates success or failure.
    /// - Errors during this operation trigger recovery steps to clean up invalid state and potentially replace the proxy.
    ///
    /// # Example
    ///
    /// let mut my_instance = MyStruct::new();
    /// let proxy = Proxy::new();
    /// let cloves = vec![Clove::new(1), Clove::new(2)];
    /// let success = my_instance.send_to_proxy(proxy, cloves).await;
    /// if success {
    ///     println!("Cloves sent to proxy successfully.");
    /// } else {
    ///     println!("Failed to send cloves to proxy.");
    /// }
    ///
    pub async fn send_to_proxy(&mut self, mut proxy: Proxy, cloves: Vec<Clove>) -> bool {
        let n_1_clove_node = proxy.neighbor_1.clone();
        let n_2_clove_node = proxy.neighbor_2.clone();

        let n_1_good = self.forward_from_proxy(&n_1_clove_node, &cloves[0], &proxy).await;

        if n_1_good.is_err() {
            let try_update = self.cache.get_alt(n_2_clove_node);

            match try_update {
                Some(updated) => {
                    self.cache.remove_sequence(updated.sequence_number);
                }
                None => {}
            }
            self.cache.remove_sequence(proxy.neighbor_2.sequence_number);
            self.remove_proxy(&proxy);

            return false;
        }

        let n_1_replaced = n_1_good.unwrap();

        if n_1_replaced.is_some() {
            let new_proxy_n_1 = n_1_replaced.unwrap();

            self.replace_proxy(&proxy, &new_proxy_n_1);
            proxy = new_proxy_n_1;
        }

        let n_2_good = self.forward_from_proxy(&n_2_clove_node, &cloves[1], &proxy).await;

        if n_2_good.is_ok() {
            let n_2_replaced = n_2_good.unwrap();

            if n_2_replaced.is_some() {
                let new_proxy_n_2 = n_2_replaced.unwrap();

                self.replace_proxy(&proxy, &new_proxy_n_2);
            }
            true
        } else {
            let try_update = self.cache.get_alt(n_1_clove_node);

            match try_update {
                Some(updated) => {
                    self.cache.remove_sequence(updated.sequence_number);
                }
                None => {}
            }
            self.cache.remove_sequence(proxy.neighbor_2.sequence_number);
            self.remove_proxy(&proxy);

            false
        }
    }

    async fn replace_with_alt(&mut self, next_node: CloveNode, mut alt_msg: GarlicMessage) -> Result<CloveNode, ()> {
        let updated_node = match self.cache.replace_with_alt_node(&next_node) {
            Some(node) => node,
            None => {
                self.handle_nonexistent_node(&next_node, &alt_msg);
                return Err(());
            }
        };

        alt_msg.update_sequence_number(updated_node.sequence_number);

        if let Err(e) = self.send_forward_message(&updated_node, &alt_msg).await {
            eprintln!("Failed to send Forward to {}: {:?}", updated_node.node.address, e);
        }

        match self.message_handler.recv(200, &updated_node.node.address).await {
            Ok(_) => Ok(updated_node),
            Err(_) => {
                self.handle_offline_node(&updated_node, &next_node);
                Err(())
            }
        }
    }

    async fn send_forward_message(&self, clove_node: &CloveNode, alt_msg: &GarlicMessage) -> Result<Option<GarlemliaMessage>, MessageError> {
        let socket = Arc::clone(&self.socket);
        let garlic_msg = GarlicMessage::build_send(self.local_node.clone(), alt_msg.clone());
        self.message_handler.send(&socket, self.local_node.clone(), &clove_node.node.address, &garlic_msg).await
    }

    fn handle_offline_node(&mut self, updated: &CloveNode, next_node: &CloveNode) {
        self.cache.remove_sequence(updated.sequence_number);
        self.cache.remove_sequence(next_node.sequence_number);
        println!(
            "{} :: REPLACEALT {} :: FAILURE : OFFLINE :: {} -> {}",
            Utc::now(),
            updated.sequence_number,
            self.local_node.address,
            updated.node.address
        );
    }

    fn handle_nonexistent_node(&mut self, next_node: &CloveNode, alt_msg: &GarlicMessage) {
        self.cache.remove_sequence(next_node.sequence_number);
        println!(
            "{} :: REPLACEALT {} :: FAILURE : NONEXISTENT :: {}",
            Utc::now(),
            alt_msg.sequence_number(),
            self.local_node.address
        );
    }

    /// Sends a search message (`GarlemliaMessage`) to a list of nodes over a UDP socket asynchronously.
    ///
    /// # Parameters
    ///
    /// * `socket` - An `Arc<UdpSocket>` used to send the search message over a UDP connection.
    /// * `local_node` - A `Node` instance representing the current (local) node sending the messages.
    /// * `message_handler` - An `Arc<Box<dyn GMessage>>` trait object responsible for handling the message transmission process.
    /// * `nodes` - A `Vec<Node>` containing the list of target nodes to which the search message should be sent.
    /// * `search_msg` - A `GarlemliaMessage` object representing the search message that will be sent to the target nodes.
    ///
    /// # Behavior
    ///
    /// The function loops through the list of `nodes` and attempts to send the provided `search_msg` to each node's
    /// address using the `message_handler`. For each node:
    /// - Utilizes the `send_no_recv` method provided by `message_handler` to send the search message without expecting a response.
    /// - If the message transmission fails, an error message is printed to the standard error output (`stderr`) detailing the failure, including the target node's address and the error description.
    ///
    /// # Errors
    ///
    /// Errors during message transmission will not cause the function to panic or halt execution. Instead:
    /// - The error is logged using `eprintln!()`.
    ///
    /// # Example
    ///
    /// let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    /// let local_node = Node::new("127.0.0.1:8080");
    /// let message_handler: Arc<Box<dyn GMessage>> = Arc::new(Box::new(MyMessageHandler::new()));
    /// let nodes = vec![Node::new("127.0.0.1:8081"), Node::new("127.0.0.1:8082")];
    /// let search_msg = GarlemliaMessage::new_search("file_name");
    ///
    /// send_search(socket, local_node, message_handler, nodes, search_msg).await;
    ///
    /// # Note
    ///
    /// This function does not return any result, and errors during the sending process are only logged.
    /// It is the caller's responsibility to handle such cases if further action is needed.
    pub async fn send_search(socket: Arc<UdpSocket>, local_node: Node, message_handler: Arc<Box<dyn GMessage>>, nodes: Vec<Node>, search_msg: GarlemliaMessage) {
        for node in nodes {
            {
                if let Err(e) = message_handler.send_no_recv(&Arc::clone(&socket), local_node.clone(), &node.address, &search_msg).await {
                    eprintln!("Failed to send SearchFile to {}: {:?}", node.address, e);
                }
            }
        }
    }
}