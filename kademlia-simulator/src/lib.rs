use std::cmp::PartialEq;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::net::{SocketAddr};
use std::sync::{Arc};
use std::sync::atomic::{AtomicBool, Ordering};
use rand::Rng;
use serde::{Serialize, Deserialize};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex, MutexGuard};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::task;
use tokio::time::{timeout, Duration};

/// Helper struct to use a max-heap for closest node selection
#[derive(Eq)]
struct HeapNode {
    distance: u128,
    node: Node,
}

impl Ord for HeapNode {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.distance.cmp(&self.distance) // Reverse order for min-heap behavior
    }
}

impl PartialOrd for HeapNode {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for HeapNode {
    fn eq(&self, other: &Self) -> bool {
        self.distance == other.distance
    }
}

// Default bucket size
const DEFAULT_K: usize = 20;
// Maximum bucket size for high-traffic buckets
const MAX_K: usize = 40;

// Node Struct
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Node {
    pub id: u128,
    pub address: SocketAddr,
}

impl Node {
    fn set(&mut self, new: &mut Node) {
        self.id = new.id;
        self.address = new.address;
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[derive(Default)]
#[derive(PartialEq)]
struct KBucket {
    nodes: VecDeque<Node>,
    max_size: usize,
}

impl KBucket {
    fn new() -> Self {
        Self {
            nodes: VecDeque::with_capacity(DEFAULT_K),
            max_size: DEFAULT_K,
        }
    }

    fn insert(&mut self, node: Node) {
        self.nodes.push_back(node);
    }

    fn remove(&mut self, node: Node) {
        if let Some(pos) = self.nodes.iter().position(|n| n.id == node.id) {
            self.nodes.remove(pos).unwrap();
        }
    }

    fn update_node(&mut self, node: Node) {
        self.remove(node.clone());
        self.insert(node);
    }

    fn contains(&self, node_id: u128) -> bool {
        self.nodes.iter().any(|n| n.id == node_id)
    }

    fn is_full(&self) -> bool {
        self.nodes.len() >= self.max_size
    }

    fn increase_capacity(&mut self) {
        if self.max_size < MAX_K {
            // Incrementally increase size
            self.max_size += 5;
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct RoutingTable {
    local_node: Node,
    buckets: Vec<KBucket>,
}

impl RoutingTable {
    fn new(local_node: Node) -> Self {
        let num_buckets = 128;
        Self {
            local_node,
            buckets: vec![KBucket::new(); num_buckets],
        }
    }

    fn set(&mut self, new: &mut RoutingTable) {
        self.local_node = new.local_node.clone();
        self.buckets = new.buckets.clone();
    }

    fn bucket_index(&self, node_id: u128) -> usize {
        let xor_distance = self.local_node.id ^ node_id;

        128 - xor_distance.leading_zeros() as usize
    }

    fn check_buckets(&mut self, node: Node, index: usize) -> bool {
        // If node already exists, move it to the back (most recently seen)
        if self.buckets[index].contains(node.id) {
            self.buckets[index].update_node(node);
            return true;
        }

        // If bucket is not full, simply add the node
        if !self.buckets[index].is_full() {
            self.buckets[index].insert(node);
            return true;
        }

        false
    }

    // Add a node to the routing table from Kademlia Responder
    async fn add_node_from_responder(&mut self, node: Node, socket: &UdpSocket) {
        let index = self.bucket_index(node.id);

        if self.check_buckets(node.clone(), index) {
            return;
        }

        // Query the LRU node before evicting it
        if let Some(lru_node) = self.buckets[index].nodes.clone().front() {
            let lru_address = lru_node.address;

            // Send a ping message to check if LRU node is alive
            let ping_message = KademliaMessage::FindNode {
                id: lru_node.id,
                sender_id: self.local_node.id,
            };

            ping_message.send(socket, &lru_address).await;

            // Buffer to store the response
            let mut buf = [0; 1024];

            // Wait up to 300ms for a response asynchronously
            let response = timeout(Duration::from_millis(300), async {
                // Try to receive a response
                match socket.recv_from(&mut buf).await {
                    Ok((_size, src)) => {
                        if src == lru_address {
                            // The LRU node responded, so keep it in the bucket and push to the front
                            self.buckets[index].update_node(lru_node.clone());
                            return true;
                        } else {
                            false
                        }
                    }
                    _ => {
                        false
                    }
                }
            }).await.unwrap_or(false);

            if !response {
                // No response, replace it with the new node
                // No valid response from the LRU node → Remove it
                self.buckets[index].remove(lru_node.clone());
                // Add the new node after LRU eviction
                self.buckets[index].insert(node);
            }
        }
    }

    // Add a node to the routing table
    async fn add_node(&mut self,
                      response_queue: Arc<Mutex<HashMap<u128, Vec<KademliaMessage>>>>,
                      rx: Arc<Mutex<UnboundedReceiver<MessageChannel>>>,
                      node: Node, socket: &UdpSocket) {
        let index = self.bucket_index(node.id);
        if self.check_buckets(node.clone(), index) {
            return;
        }

        // Query the LRU node before evicting it
        if let Some(lru_node) = self.buckets[index].nodes.clone().front() {
            let lru_address = lru_node.address;

            // Send a ping message to check if LRU node is alive
            let ping_message = KademliaMessage::FindNode {
                id: lru_node.id,
                sender_id: self.local_node.id,
            };

            ping_message.send(socket, &lru_address).await;

            // Wait up to 300ms for a response asynchronously
            let response = KademliaMessage::recv(response_queue, rx, 300).await;

            match response {
                Some(msg) => {
                    match msg {
                        KademliaMessage::Response { sender_id, .. } => {
                            if sender_id == lru_node.id {
                                self.buckets[index].update_node(lru_node.clone());
                            }
                        }
                        _ => {}
                    }
                }
                None => {
                    // No response, replace it with the new node
                    // No valid response from the LRU node → Remove it
                    self.buckets[index].remove(lru_node.clone());
                    // Add the new node after LRU eviction
                    self.buckets[index].insert(node);
                }
            }
        }
    }

    // Find the closest nodes based on XOR distance
    fn find_closest_nodes(&self, target_id: u128, count: usize) -> Vec<Node> {
        let mut heap = BinaryHeap::new();
        heap.push(HeapNode { distance: target_id ^ self.local_node.id, node: self.local_node.clone() });
        let mut searched_buckets = 0;

        let start_index = self.bucket_index(target_id);

        // Search from the closest bucket outward
        for offset in 0..self.buckets.len() {
            let index = if offset % 2 == 0 {
                // Search left
                start_index.saturating_sub(offset / 2)
            } else {
                // Search right
                start_index + (offset / 2)
            };

            if index >= self.buckets.len() {
                continue;
            }

            for node in &self.buckets[index].nodes {
                let distance = target_id ^ node.id;
                heap.push(HeapNode { distance, node: node.clone() });

                // Keep only the closest 'count' nodes
                if heap.len() > count {
                    heap.pop();
                }
            }

            searched_buckets += 1;

            // Stop early if we have enough nodes
            if heap.len() >= count && searched_buckets > 3 {
                break;
            }
        }

        // Extract and return the closest nodes
        heap.into_sorted_vec()
            .into_iter()
            .map(|heap_node| heap_node.node)
            .collect()
    }
}

#[derive(Debug)]
struct MessageChannel {
    node_id: u128,
    msg_id: u128,
}

// Kademlia Messages
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum KademliaMessage {
    FindNode { id: u128, sender_id: u128 },
    Store { key: u128, value: String, sender_id: u128 },
    FindValue { key: u128, sender_id: u128 },
    Response { msg_id: Option<u128>, nodes: Vec<Node>, value: Option<String>, sender_id: u128 },
}

impl KademliaMessage {
    // Extract sender ID from the message
    pub fn get_sender_id(&self) -> u128 {
        match self {
            KademliaMessage::FindNode { sender_id, .. } => *sender_id,
            KademliaMessage::Store { sender_id, .. } => *sender_id,
            KademliaMessage::FindValue { sender_id, .. } => *sender_id,
            KademliaMessage::Response {sender_id, .. } => *sender_id,
        }
    }

    // Send a message to another node
    pub async fn send(&self, socket: &UdpSocket, target: &SocketAddr) {
        let message_bytes = serde_json::to_vec(self).unwrap();
        socket.send_to(&message_bytes, target).await.unwrap();
    }

    async fn recv(response_queue: Arc<Mutex<HashMap<u128, Vec<KademliaMessage>>>>,
                  rx: Arc<Mutex<UnboundedReceiver<MessageChannel>>>, time: u64) -> Option<KademliaMessage> {
        // Lock before entering timeout
        let mut rx_locked = rx.lock().await;
        let response = match timeout(Duration::from_millis(time), async {
            if !rx_locked.is_closed() {
                rx_locked.recv().await
            } else {
                println!("tx is closed");
                None
            }
        }).await {
            Ok(Some(node_id)) => Some(node_id),
            Ok(None) => {
                println!("Received None from channel.");
                None
            },
            Err(_) => {
                println!("Timeout occurred while waiting for response.");
                None
            }
        };

        let mut position = -1;
        let message_info;
        let mut kad_msg = KademliaMessage::Response {
            msg_id: None,
            nodes: vec![],
            value: None,
            sender_id: 0,
        };

        let mut res_queue = response_queue.lock().await;
        match response {
            Some(mc) => {
                if let Some(pos) = res_queue.get(&mc.node_id).unwrap().iter().position(|n|
                    match n {
                        &KademliaMessage::Response { msg_id, .. } => { msg_id == Option::from(mc.msg_id) }
                        _ => { false }
                    }) {
                    position = pos as i32;
                }
                message_info = Some(mc);
            },
            None => {
                return None;
            }
        };

        let km = match message_info {
            Some(mc) => {
                let response_msg = res_queue.get(&mc.node_id).unwrap().get(position as usize).unwrap();
                match response_msg {
                    KademliaMessage::Response { msg_id, nodes, value, sender_id } => {
                        kad_msg = KademliaMessage::Response {
                            msg_id: *msg_id,
                            nodes: nodes.clone(),
                            value: value.clone(),
                            sender_id: *sender_id,
                        }
                    },
                    _ => {}
                }
                res_queue.get_mut(&mc.node_id).unwrap().remove(position as usize);
                Some(kad_msg)
            }
            None => None
        };

        km
    }
}

// Kademlia Struct
pub struct Kademlia {
    pub node: Arc<Mutex<Node>>,
    pub socket: Arc<UdpSocket>,
    routing_table: Arc<Mutex<RoutingTable>>,
    pub data_store: Arc<Mutex<HashMap<u128, String>>>,
    pub response_queue: Arc<Mutex<HashMap<u128, Vec<KademliaMessage>>>>,
    rx: Option<Arc<Mutex<UnboundedReceiver<MessageChannel>>>>,
    stop_signal: Arc<AtomicBool>,
    join_handle: Arc<Option<task::JoinHandle<()>>>,
}

impl Kademlia {
    pub async fn new(id: u128, address: &str, port: u32) -> Self {
        let node = Node { id, address: format!("{address}:{port}").parse().unwrap() };
        let rt = RoutingTable::new(node.clone());

        Self {
            node: Arc::new(Mutex::new(node)),
            socket: Arc::new(UdpSocket::bind(format!("{}:{}", address, port)).await.unwrap()),
            routing_table: Arc::new(Mutex::new(rt)),
            data_store: Arc::new(Mutex::new(HashMap::new())),
            response_queue: Arc::new(Mutex::new(HashMap::new())),
            rx: None,
            stop_signal: Arc::new(AtomicBool::new(false)),
            join_handle: Arc::new(None),
        }
    }

    async fn set_node(&self, node: &mut Node) {
        self.node.lock().await.set(node)
    }

    async fn set_routing_table(&self, rt: &mut RoutingTable) {
        self.routing_table.lock().await.set(rt);
    }

    async fn set_data_store(&self, data_store: &mut HashMap<u128, String>) {
        let mut ds = self.data_store.lock().await;
        ds.clear();

        for i in data_store.iter() {
            ds.insert(*i.0, i.1.clone());
        }
    }

    async fn set_response_queue(&self, response_queue: &mut HashMap<u128, Vec<KademliaMessage>>) {
        let mut rq = self.response_queue.lock().await;
        rq.clear();

        for i in response_queue.iter() {
            rq.insert(*i.0, i.1.clone());
        }
    }

    async fn get_node(&self) -> Node {
        let node;
        {
            node = self.node.lock().await;
        }
        node.clone()
    }

    // Start listening for messages
    pub async fn start(&mut self, orig_socket: Arc<UdpSocket>) {
        let self_node = Arc::clone(&self.node);
        let socket = Arc::clone(&orig_socket);
        let routing_table = Arc::clone(&self.routing_table);
        let response_queue = Arc::clone(&self.response_queue);
        let data_store = Arc::clone(&self.data_store);
        let stop_clone = Arc::clone(&self.stop_signal);
        let (tx, rx) = mpsc::unbounded_channel::<MessageChannel>();

        let handle = tokio::spawn(async move {
            let mut buf = [0; 1024];
            while !stop_clone.load(Ordering::Relaxed) {
                if let Ok((size, src)) = socket.recv_from(&mut buf).await {
                    let self_ref;
                    {
                        self_ref = self_node.lock().await;
                    }
                    let msg: KademliaMessage = serde_json::from_slice(&buf[..size]).unwrap();

                    // Extract sender Node info
                    let sender_node = Node {
                        id: msg.get_sender_id(),
                        address: src,
                    };

                    if cfg!(debug_assertions) {
                        println!("Received msg {:?} from {:?} to {:?}", msg, sender_node, self_ref);
                    }

                    match msg {
                        KademliaMessage::FindNode { id, .. } => {
                            let mut rt = routing_table.lock().await;
                            // Add the sender to the routing table
                            rt.add_node_from_responder(sender_node.clone(), &socket).await;
                            let response = if id == self_ref.id {
                                // If the search target is this node itself, return only this node
                                KademliaMessage::Response {
                                    msg_id: None,
                                    nodes: vec![self_ref.clone()],
                                    value: None,
                                    sender_id: self_ref.id,
                                }
                            } else {
                                // Return the closest known nodes
                                let closest_nodes = rt.find_closest_nodes(id, DEFAULT_K);
                                KademliaMessage::Response {
                                    msg_id: None,
                                    nodes: closest_nodes,
                                    value: None,
                                    sender_id: self_ref.id,
                                }
                            };

                            if cfg!(debug_assertions) {
                                println!("Responding to message with {:?}", response);
                            }

                            response.send(&socket, &src).await;
                        }

                        // Store a key-value pair
                        KademliaMessage::Store { key, value, .. } => {
                            routing_table.lock().await.add_node_from_responder(sender_node.clone(), &socket).await;
                            data_store.lock().await.insert(key, value);
                        }

                        // Use find_closest_nodes() if value is not found
                        KademliaMessage::FindValue { key, .. } => {
                            let mut rt = routing_table.lock().await;
                            rt.add_node_from_responder(sender_node.clone(), &socket).await;
                            let value = data_store.lock().await.get(&key).cloned();

                            let response = if let Some(val) = value {
                                KademliaMessage::Response {
                                    msg_id: None,
                                    nodes: vec![],
                                    value: Some(val),
                                    sender_id: self_ref.id,
                                }
                            } else {
                                let closest_nodes = rt.find_closest_nodes(key, DEFAULT_K);

                                KademliaMessage::Response {
                                    msg_id: None,
                                    nodes: closest_nodes,
                                    value: None,
                                    sender_id: self_ref.id,
                                }
                            };

                            response.send(&socket, &src).await;
                        }

                        KademliaMessage::Response { nodes, value, sender_id, .. } => {
                            let msg_id = rand::rng().random::<u128>();
                            let constructed = KademliaMessage::Response {
                                msg_id: Some(msg_id),
                                nodes,
                                value,
                                sender_id,
                            };

                            if cfg!(debug_assertions) {
                                println!("Responded with {:?}", constructed);
                            }

                            {
                                let mut locked_queue = response_queue.lock().await;
                                match locked_queue.get_mut(&sender_node.id) {
                                    Some(queue) => queue.push(constructed),
                                    None => {
                                        locked_queue.insert(sender_node.id, vec![constructed]);
                                    }
                                }
                            } // Mutex unlocked here before send()

                            if cfg!(debug_assertions) {
                                println!("Sending message: {:?}", MessageChannel { node_id: sender_node.id, msg_id });
                            }
                            tx.send(MessageChannel { node_id: sender_node.id, msg_id }).expect("TODO: panic message");
                            if cfg!(debug_assertions) {
                                println!("Message sent successfully");
                            }
                        }
                    }
                }
            }
            println!("Finished");
        });
        *Arc::get_mut(&mut self.join_handle).unwrap() = Some(handle);
        self.rx = Some(Arc::new(Mutex::new(rx)));
    }

    pub async fn stop(&self) {
        self.stop_signal.store(true, Ordering::Relaxed);

        if let Some(handle) = Arc::get_mut(&mut self.join_handle.clone()).and_then(|h| h.take()) {
            let _ = handle.await;
        }
    }

    pub async fn iterative_find_node(&self, socket: Arc<UdpSocket>, target_id: u128) -> Vec<Node> {
        let self_node = self.get_node().await;
        let mut queried_nodes = HashSet::new();
        let mut closest_nodes = self.routing_table.lock().await.find_closest_nodes(target_id, DEFAULT_K);
        closest_nodes.retain(|x| *x != self_node);
        let mut all_nodes = closest_nodes.clone();
        let mut best_known_distance = u128::MAX;
        let mut new_nodes_found = true;

        while new_nodes_found {
            new_nodes_found = false;
            let mut new_closest_nodes = Vec::new();
            let mut tasks = Vec::new();

            for node in closest_nodes.iter() {
                if queried_nodes.contains(&node.address) {
                    continue;
                }

                queried_nodes.insert(node.address);
                let socket_clone = Arc::clone(&socket);
                let node_clone = node.clone();
                let response_queue = Arc::clone(&self.response_queue);
                let self_id = self_node.id;

                self.add_node(&socket_clone, node_clone.clone()).await;

                if let Some(rx) = &self.rx {
                    let rx = Arc::clone(rx);
                    // Spawn async task for each lookup request
                    let task = task::spawn(async move {
                        let message = KademliaMessage::FindNode {
                            id: target_id,
                            sender_id: self_id,
                        };

                        message.send(&*socket_clone, &node_clone.address).await;

                        let response = KademliaMessage::recv(response_queue, rx, 200).await;

                        return match response {
                            Some(msg) => {
                                match msg {
                                    KademliaMessage::Response { nodes, .. } => {
                                        Some(nodes)
                                    }
                                    _ => {
                                        None
                                    }
                                }
                            },
                            _ => {
                                None
                            }
                        }
                    });

                    tasks.push(task);
                }
            }

            // Collect results from tasks
            let prev_best_known_distance = best_known_distance;
            for task in tasks {
                if let Ok(Some(nodes)) = task.await {
                    for n in nodes {
                        let distance = n.id ^ target_id;
                        if distance < prev_best_known_distance {
                            new_closest_nodes.push(n);
                            new_nodes_found = true;
                            if distance < best_known_distance {
                                best_known_distance = distance;
                            }
                        }
                    }
                }
            }

            if new_nodes_found {
                new_closest_nodes.retain(|x| *x != self_node);
                closest_nodes.clear();
                closest_nodes.extend(new_closest_nodes.clone());
                all_nodes.extend(new_closest_nodes);
                closest_nodes.sort_by_key(|n| n.id ^ target_id);
                closest_nodes.truncate(DEFAULT_K);
                closest_nodes.dedup();
            }
        }

        all_nodes.push(self_node.clone());
        all_nodes.sort_by_key(|n| n.id ^ target_id);
        all_nodes.dedup();
        all_nodes.truncate(5);
        all_nodes
    }

    // Perform an iterative lookup for a value in the DHT
    pub async fn iterative_find_value(&self, socket: Arc<UdpSocket>, key: u128) -> Option<String> {
        let self_node = self.get_node().await;
        // Check if this node has the value first
        let local = self.data_store.lock().await.get(&key).cloned();
        match local {
            Some(val) => {
                return Some(val);
            }
            _ => {}
        }

        let mut queried_nodes = HashSet::new();
        queried_nodes.insert(self_node.address);
        let mut closest_nodes = self.routing_table.lock().await.find_closest_nodes(key, DEFAULT_K);
        closest_nodes.retain(|x| *x != self_node);
        let mut best_known_distance = u128::MAX;
        let mut new_nodes_found = true;

        while new_nodes_found {
            new_nodes_found = false;
            let mut new_closest_nodes: Vec<Node> = Vec::new();
            let mut tasks = Vec::new();

            for node in closest_nodes.iter() {
                if queried_nodes.contains(&node.address) {
                    continue;
                }

                queried_nodes.insert(node.address);
                let socket_clone = Arc::clone(&socket);
                let node_clone = node.clone();
                let response_queue = Arc::clone(&self.response_queue);
                let self_id = self_node.id;

                self.add_node(&socket_clone, node_clone.clone()).await;

                if let Some(rx) = &self.rx {
                    let rx = Arc::clone(rx);
                    // Spawn async task for each lookup request
                    let task = task::spawn(async move {
                        let message = KademliaMessage::FindValue {
                            key,
                            sender_id: self_id,
                        };

                        message.send(&*socket_clone, &node_clone.address).await;

                        let response = KademliaMessage::recv(response_queue, rx, 200).await;

                        return match response {
                            Some(msg) => {
                                match msg {
                                    KademliaMessage::Response { nodes, value, .. } => {
                                        if let Some(value) = value {
                                            return Some(Ok(value))
                                        }
                                        Some(Err(nodes))
                                    }
                                    _ => {
                                        Some(Err(vec![]))
                                    }
                                }
                            },
                            _ => {
                                Some(Err(vec![]))
                            }
                        }
                    });

                    tasks.push(task);
                }
            }

            // Collect results from tasks
            let prev_best_known_distance = best_known_distance;
            for task in tasks {
                if let Ok(Some(result)) = task.await {
                    match result {
                        Ok(value) => return Some(value), // Return immediately if value is found
                        Err(received_nodes) => {
                            for n in received_nodes {
                                let distance = n.id ^ key;
                                if distance < prev_best_known_distance {
                                    new_closest_nodes.push(n);
                                    new_nodes_found = true;
                                    if distance < best_known_distance {
                                        best_known_distance = distance;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if new_nodes_found {
                closest_nodes.clear();
                closest_nodes.extend(new_closest_nodes);
                closest_nodes.sort_by_key(|n| n.id ^ key);
                closest_nodes.truncate(DEFAULT_K);
            }
        }

        None
    }

    pub async fn store_value(&self, socket: Arc<UdpSocket>, key: u128, value: String) -> Vec<Node> {
        let self_node = self.get_node().await;
        // Find the closest nodes to store the value
        let mut closest_nodes = self.iterative_find_node(Arc::clone(&socket), key).await;
        closest_nodes.truncate(2);


        for node in closest_nodes.iter() {
            if node.id == self_node.id {
                // Store the value locally if this node is among the closest
                let mut data_store = self.data_store.lock().await;
                data_store.insert(key, value.clone());
                continue;
            }

            // Create STORE message
            let store_message = KademliaMessage::Store {
                key,
                value: value.clone(),
                sender_id: self_node.id,
            };

            // Send STORE message
            store_message.send(&socket, &node.address).await;
        }

        closest_nodes
    }

    // Add a node to the routing table
    pub async fn add_node(&self, socket: &UdpSocket, node: Node) {
        if let Some(rx) = &self.rx {
            let rx = Arc::clone(rx);
            let response_queue = Arc::clone(&self.response_queue);
            self.routing_table.lock().await.add_node(response_queue, rx, node, socket).await;
        }
    }

    pub async fn join_network(&self, socket: Arc<UdpSocket>, target: &SocketAddr) {
        let self_node = self.get_node().await;
        if let Some(rx) = &self.rx {
            let rx = Arc::clone(rx);
            let socket_clone = Arc::clone(&socket);
            let response_queue = Arc::clone(&self.response_queue);
            let message = KademliaMessage::FindNode {
                id: self_node.id,
                sender_id: self_node.id,
            };

            message.send(&*socket, target).await;

            let response = KademliaMessage::recv(response_queue, rx, 300).await;

            match response {
                Some(msg) => {
                    match msg {
                        KademliaMessage::Response { nodes, .. } => {
                            for node in nodes {
                                if node.id != self_node.id {
                                    self.add_node(&*socket, node.clone()).await;
                                }
                            }
                        }
                        _ => {}
                    }
                },
                _ => {}
            }

            self.iterative_find_node(socket_clone, self_node.id).await;
        }
    }
}

static SIM: Mutex<Option<Simulator>> = Mutex::const_new(None);

#[derive(Clone)]
pub struct SimulatedNode {
    pub node: Node,
    routing_table: RoutingTable,
    pub data_store: HashMap<u128, String>,
    pub response_queue: HashMap<u128, Vec<KademliaMessage>>,
}

// Simulator Struct
pub struct Simulator {
    pub available: Arc<Mutex<Vec<Kademlia>>>,
    pub unavailable: Arc<Mutex<HashMap<SocketAddr, Kademlia>>>,
    pub sims: Arc<Mutex<Vec<SimulatedNode>>>,
    pub map: Arc<Mutex<HashMap<u16, u16>>>,
    /*pub node: Node,
    pub socket: Arc<UdpSocket>,
    routing_table: Arc<Mutex<RoutingTable>>,
    pub data_store: Arc<Mutex<HashMap<u128, String>>>,
    pub response_queue: Arc<Mutex<HashMap<u128, Vec<KademliaMessage>>>>,
    rx: Option<Arc<Mutex<UnboundedReceiver<MessageChannel>>>>,
    stop_signal: Arc<AtomicBool>,
    join_handle: Arc<Option<task::JoinHandle<()>>>,*/
}

impl Simulator {

    async fn create_sim_node(id: u128, port: u16) -> Kademlia {
        let mut node = Kademlia::new(id, "127.0.0.1", port as u32).await;

        // Spawn a task to keep the node running and listening
        node.start(Arc::clone(&node.socket)).await;

        node
    }
    pub async fn new(start_port: u16, available_total: u8, current_simulators: Vec<SimulatedNode>) -> Simulator {
        let mut created_sims = vec![];

        for i in 0..available_total {
            created_sims.push(Simulator::create_sim_node(0, start_port + i as u16).await);
        }

        Simulator {
            available: Arc::new(Mutex::new(created_sims)),
            unavailable: Arc::new(Mutex::new(HashMap::new())),
            sims: Arc::new(Mutex::new(current_simulators)),
            map: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn save_state(&self, kademlia: &Kademlia) {
        let id = kademlia.get_node().await.id;

        for sim in self.sims.lock().await.iter_mut() {
            if sim.node.id == id {
                sim.data_store = kademlia.data_store.lock().await.clone();
                sim.routing_table = kademlia.routing_table.lock().await.clone();
                break;
            }
        }
    }

    pub async fn add_node(&self, address: SocketAddr) {
        let started;
        {
            started = self.unavailable.lock().await.contains_key(&address);
        }

        if !started {
            let mut sim_data = None;
            {
                for sim in self.sims.lock().await.iter_mut() {
                    if sim.node.address == address {
                        sim_data = Some(sim.clone());
                        break;
                    }
                }
            }

            match sim_data {
                Some(mut val) => {
                    let mut kad;
                    {
                        kad = self.available.lock().await.pop().unwrap();
                    }

                    kad.set_node(&mut val.node).await;
                    kad.set_routing_table(&mut val.routing_table.clone()).await;
                    kad.set_data_store(&mut val.data_store).await;
                    kad.set_response_queue(&mut val.response_queue).await;

                    {
                        self.unavailable.lock().await.insert(address, kad);
                    }
                }
                None => {}
            }
        }
    }

    pub async fn remove_node(&self, address: SocketAddr) {
        let mut kad = None;
        {
            let mut una = self.unavailable.lock().await;
            let started = una.contains_key(&address);

            if started {
                kad = una.remove(&address);
            }
        }

        match kad {
            Some(val) => {
                self.save_state(&val).await;
                self.available.lock().await.push(val);
            }
            None => {}
        }
    }

    pub async fn stop(&self) {
        for kad in self.available.lock().await.iter() {
            self.save_state(kad).await;
            kad.stop().await;
        }

        for kad in self.unavailable.lock().await.iter() {
            self.save_state(kad.1).await;
            kad.1.stop().await;
        }
    }
}

/// TESTS
#[cfg(test)]
mod sim_tests {
}
#[cfg(test)]
mod kad_tests {
    use super::*;
    use tokio::time::sleep;

    async fn create_test_node(id: u128, port: u16) -> Kademlia {
        let mut node = Kademlia::new(id, "127.0.0.1", port as u32).await;

        // Spawn a task to keep the node running and listening
        node.start(Arc::clone(&node.socket)).await;

        node
    }

    #[tokio::test]
    async fn test_iterative_find_node() {
        // Create multiple nodes and bind them to real sockets
        let node1 = create_test_node(1, 8005).await;
        let node2 = create_test_node(2, 8006).await;
        let node3 = create_test_node(3, 8007).await;

        let node3_addr = node3.node.lock().await.address;
        let node2_info = node2.node.lock().await.clone();

        node1.join_network(Arc::clone(&node1.socket), &node3_addr).await;
        node2.join_network(Arc::clone(&node2.socket), &node3_addr).await;

        // Perform lookup
        let found_nodes = node1.iterative_find_node(Arc::clone(&node1.socket), 2).await;

        sleep(Duration::from_secs(2)).await; // Allow time for replication

        node1.stop().await;
        node2.stop().await;
        node3.stop().await;

        println!("found_nodes: {:?}\nrouting_table: {:?}", found_nodes, node1.routing_table);

        assert!(!found_nodes.is_empty() && found_nodes[0] == node2_info, "Should find node 2 and it should be first in the list");
    }

    #[tokio::test]
    async fn test_add_node_to_routing_table() {
        let kad = create_test_node(1, 8080).await;
        let node = Node {
            id: 42,
            address: "127.0.0.1:8001".parse().unwrap(),
        };

        kad.add_node(&kad.socket, node.clone()).await;

        let rt = kad.routing_table.lock().await;

        let index = rt.bucket_index(node.id);

        kad.stop().await;

        println!("rt: {:?}", rt);

        assert!(rt.buckets[index].contains(node.id), "Node should be in the routing table");
    }

    #[tokio::test]
    async fn test_add_node_ping() {
        let kad = create_test_node(1, 8081).await;
        let test = create_test_node(128, 8082).await;

        let base_id: u128 = 128;
        let bucket_index;

        {
            let rt = kad.routing_table.lock().await;
            bucket_index = rt.bucket_index(base_id);
        }

        // Generate nodes that belong in the same bucket
        let mut nodes = Vec::new();
        for i in 1..DEFAULT_K {
            let id = base_id + i as u128;
            nodes.push(Node {
                id,
                address: format!("127.0.0.1:{}", 8000 + base_id + i as u128).parse().unwrap(),
            });
        }

        let test_info = test.node.lock().await.clone();

        // Insert all nodes into the routing table
        kad.add_node(&kad.socket, test_info.clone()).await;
        for node in &nodes {
            kad.add_node(&kad.socket, node.clone()).await;
        }

        let orig;
        {
            let rt = kad.routing_table.lock().await;
            orig = rt.buckets[bucket_index].clone();
        }

        // One extra node to force a ping
        let overflow_node = Node {
            id: base_id + (DEFAULT_K as u128),
            address: "127.0.0.1:9000".parse().unwrap(),
        };
        kad.add_node(&kad.socket, overflow_node.clone()).await;

        let mut new;
        {
            let rt = kad.routing_table.lock().await;
            new = rt.buckets[bucket_index].clone();
        }

        // Ensure that the original bucket is the same
        println!("Routing Table Before Overflow: {:?}", orig);
        println!("Routing Table After Overflow: {:?}", new);
        assert_eq!(new.nodes[DEFAULT_K - 1], test_info.clone(), "Bucket should have same nodes");

        test.stop().await;

        kad.add_node(&kad.socket, overflow_node.clone()).await;

        {
            let rt = kad.routing_table.lock().await;
            new = rt.buckets[bucket_index].clone();
            println!("Routing Table After Guaranteed LRU Removal: {:?}", rt.buckets[bucket_index]);
        }

        // Ensure that the original bucket has new node
        assert_eq!(new.nodes[DEFAULT_K - 1], overflow_node, "Bucket should have new LRU");
        {
            let rt = kad.routing_table.lock().await;
            assert!(
                rt.buckets[bucket_index].contains(overflow_node.id),
                "Overflow node should be in the bucket"
            );
        }

        kad.stop().await;
    }

    #[tokio::test]
    async fn test_iterative_find_value() {
        // Create multiple nodes and bind them to real sockets
        let node1 = create_test_node(1, 8001).await;
        let node2 = create_test_node(2, 8002).await;
        let node3 = create_test_node(3, 8003).await;
        let node4 = create_test_node(4, 8004).await;

        let node3_info = node3.node.lock().await.clone();
        let node2_info = node2.node.lock().await.clone();
        let node1_info = node1.node.lock().await.clone();

        // Let nodes join the network
        node4.join_network(Arc::clone(&node4.socket), &node1_info.address).await;
        node1.join_network(Arc::clone(&node1.socket), &node3_info.address).await;
        node2.join_network(Arc::clone(&node2.socket), &node1_info.address).await;

        sleep(Duration::from_secs(1)).await;

        // Store a value in node1
        node1.store_value(Arc::clone(&node1.socket), 2, "Hello, world!".to_string()).await;
        sleep(Duration::from_secs(1)).await;

        // Attempt to retrieve the stored value from node4
        let value = node4.iterative_find_value(Arc::clone(&node4.socket), 2).await;

        node1.stop().await;
        node2.stop().await;
        node3.stop().await;
        node4.stop().await;

        assert_eq!(value, Some("Hello, world!".to_string()), "Value should be found");
    }
}