use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr};
use std::sync::{Arc};
use std::sync::atomic::{AtomicBool, Ordering};
use rand::Rng;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::task;
use kademlia_structs::{Node, KademliaRoutingTable, MessageChannel, RoutingTable, DEFAULT_K, KMessage, KademliaMessage};

// Kademlia Struct
pub struct Kademlia {
    pub node: Arc<Mutex<Node>>,
    pub socket: Arc<UdpSocket>,
    pub receive_addr: SocketAddr,
    pub message_handler: Box<dyn KMessage>,
    pub routing_table: Arc<Mutex<Box<dyn KademliaRoutingTable>>>,
    pub data_store: Arc<Mutex<HashMap<u128, String>>>,
    pub response_queue: Arc<Mutex<HashMap<u128, Vec<KademliaMessage>>>>,
    rx: Option<Arc<Mutex<UnboundedReceiver<MessageChannel>>>>,
    stop_signal: Arc<AtomicBool>,
    join_handle: Arc<Option<task::JoinHandle<()>>>,
}

impl Kademlia {
    pub async fn new(id: u128, address: &str, port: u16, msg_handler: Box<dyn KMessage>) -> Self {
        let node = Node { id, address: format!("{address}:{port}").parse().unwrap() };
        let rt = RoutingTable::new(node.clone());

        Self {
            node: Arc::new(Mutex::new(node)),
            socket: Arc::new(UdpSocket::bind(format!("{}:{}", address, port)).await.unwrap()),
            receive_addr: format!("{address}:{port}").parse().unwrap(),
            message_handler: msg_handler,
            routing_table: Arc::new(Mutex::new(Box::new(rt))),
            data_store: Arc::new(Mutex::new(HashMap::new())),
            response_queue: Arc::new(Mutex::new(HashMap::new())),
            rx: None,
            stop_signal: Arc::new(AtomicBool::new(false)),
            join_handle: Arc::new(None),
        }
    }

    pub async fn set_node(&self, node: &mut Node) {
        self.node.lock().await.set(node)
    }

    pub async fn set_routing_table(&self, rt: &dyn KademliaRoutingTable) {
        self.routing_table.lock().await.set(rt);
    }

    pub async fn set_data_store(&self, data_store: &mut HashMap<u128, String>) {
        let mut ds = self.data_store.lock().await;
        ds.clear();

        for i in data_store.iter() {
            ds.insert(*i.0, i.1.clone());
        }
    }

    pub async fn set_response_queue(&self, response_queue: &mut HashMap<u128, Vec<KademliaMessage>>) {
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
        let message_handler = self.message_handler.clone();
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

                            message_handler.send(&socket, &src, &response).await;
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

                            message_handler.send(&socket, &src, &response).await;
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
                let message_handler = self.message_handler.clone();
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

                        message_handler.send(&socket_clone, &node_clone.address, &message).await;

                        let response = message_handler.recv(response_queue, rx, 200, &node_clone.address).await;

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
                let message_handler = self.message_handler.clone();
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

                        message_handler.send(&socket_clone, &node_clone.address, &message).await;

                        let response = message_handler.recv(response_queue, rx, 200, &node_clone.address).await;

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
            {
                self.message_handler.send(&socket, &node.address, &store_message).await;
            }
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

            self.message_handler.send(&socket, &target, &message).await;

            let response = self.message_handler.recv(response_queue, rx, 200, &target).await;

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

/// TESTS
#[cfg(test)]
mod kad_tests {
    use std::time::Duration;
    use super::*;
    use tokio::time::sleep;
    use kademlia_structs::{MessageHandler, Node, DEFAULT_K};

    async fn create_test_node(id: u128, port: u16) -> Kademlia {
        let mut node = Kademlia::new(id, "127.0.0.1", port, MessageHandler::create()).await;

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

        assert!(rt.get_buckets().get(&index).unwrap().contains(node.id), "Node should be in the routing table");
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
            orig = rt.get_buckets().get(&bucket_index).unwrap().clone();
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
            new = rt.get_buckets().get(&bucket_index).unwrap().clone();
        }

        // Ensure that the original bucket is the same
        println!("Routing Table Before Overflow: {:?}", orig);
        println!("Routing Table After Overflow: {:?}", new);
        assert_eq!(new.nodes[DEFAULT_K - 1], test_info.clone(), "Bucket should have same nodes");

        test.stop().await;

        kad.add_node(&kad.socket, overflow_node.clone()).await;

        {
            let rt = kad.routing_table.lock().await;
            new = rt.get_buckets().get(&bucket_index).unwrap().clone();
            println!("Routing Table After Guaranteed LRU Removal: {:?}", rt.get_buckets().get(&bucket_index).unwrap());
        }

        // Ensure that the original bucket has new node
        assert_eq!(new.nodes[DEFAULT_K - 1], overflow_node, "Bucket should have new LRU");
        {
            let rt = kad.routing_table.lock().await;
            assert!(
                rt.get_buckets().get(&bucket_index).unwrap().contains(overflow_node.id),
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