use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr};
use std::sync::{Arc};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::{mpsc, Mutex};
use tokio::task;
use kademlia_structs::{Node, MessageChannel, DEFAULT_K, KMessage, KademliaMessage, RoutingTable, MAX_K, LOOKUP_ALPHA};

// Kademlia Struct
#[derive(Clone)]
pub struct Kademlia {
    pub node: Arc<Mutex<Node>>,
    pub socket: Arc<UdpSocket>,
    pub receive_addr: SocketAddr,
    pub message_handler: Arc<Box<dyn KMessage>>,
    pub routing_table: Arc<Mutex<RoutingTable>>,
    pub data_store: Arc<Mutex<HashMap<u128, String>>>,
    stop_signal: Arc<AtomicBool>,
    join_handle: Arc<Option<task::JoinHandle<()>>>,
}

// TODO: Implement new event thread for watching last_seen information and pinging nodes
// TODO: which have not been seen in an hour + evicting those which fail
// TODO: Add RPC ID's to messages
// TODO:
impl Kademlia {
    pub async fn new(id: u128, address: &str, port: u16, rt: RoutingTable, msg_handler: Box<dyn KMessage>) -> Self {
        let node = Node { id, address: format!("{address}:{port}").parse().unwrap() };

        Self {
            node: Arc::new(Mutex::new(node)),
            socket: Arc::new(UdpSocket::bind(format!("{}:{}", address, port)).await.unwrap()),
            receive_addr: format!("{address}:{port}").parse().unwrap(),
            message_handler: Arc::new(msg_handler),
            routing_table: Arc::new(Mutex::new(rt)),
            data_store: Arc::new(Mutex::new(HashMap::new())),
            stop_signal: Arc::new(AtomicBool::new(false)),
            join_handle: Arc::new(None),
        }
    }

    pub fn new_with_sock(id: u128, address: &str, port: u16, rt: RoutingTable, msg_handler: Box<dyn KMessage>, socket: Arc<UdpSocket>) -> Self {
        let node = Node { id, address: format!("{address}:{port}").parse().unwrap() };

        Self {
            node: Arc::new(Mutex::new(node)),
            socket: Arc::clone(&socket),
            receive_addr: format!("{address}:{port}").parse().unwrap(),
            message_handler: Arc::new(msg_handler),
            routing_table: Arc::new(Mutex::new(rt)),
            data_store: Arc::new(Mutex::new(HashMap::new())),
            stop_signal: Arc::new(AtomicBool::new(false)),
            join_handle: Arc::new(None),
        }
    }

    pub async fn set_node(&self, node: &mut Node) {
        self.node.lock().await.update(node);
    }

    pub async fn set_routing_table(&self, rt: RoutingTable) {
        self.routing_table.lock().await.update_from(rt).await;
    }

    pub async fn set_data_store(&self, data_store: &mut HashMap<u128, String>) {
        let mut ds = self.data_store.lock().await;
        ds.clear();

        for i in data_store.iter() {
            ds.insert(*i.0, i.1.clone());
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
        let message_handler = Arc::clone(&self.message_handler);
        let routing_table = Arc::clone(&self.routing_table);
        let data_store = Arc::clone(&self.data_store);
        let stop_clone = Arc::clone(&self.stop_signal);
        println!("STARTING {}", socket.local_addr().unwrap());

        let handle = tokio::spawn(async move {
            let mut buf = [0; 4096];
            while !stop_clone.load(Ordering::Relaxed) {
                if let Ok((size, src)) = socket.recv_from(&mut buf).await {
                    let self_ref;
                    {
                        self_ref = self_node.lock().await;
                    }
                    let msg: KademliaMessage = serde_json::from_slice(&buf[..size]).unwrap();

                    //println!("{} received {:?}", socket.local_addr().unwrap(), msg);

                    // Extract sender Node info
                    let sender_node = Node {
                        id: msg.sender_id(),
                        address: src,
                    };

                    if cfg!(debug_assertions) {
                        println!("Received msg {:?} from {:?} to {:?}", msg, sender_node, self_ref);
                    }

                    match msg {
                        KademliaMessage::FindNode { id, .. } => {
                            let mut rt = routing_table.lock().await;
                            // Add the sender to the routing table
                            rt.add_node_from_responder(Arc::clone(&message_handler), sender_node.clone(), Arc::clone(&socket)).await;
                            let response = if id == self_ref.id {
                                // If the search target is this node itself, return only this node
                                KademliaMessage::Response {
                                    nodes: vec![self_ref.clone()],
                                    value: None,
                                    sender: self_ref.clone(),
                                }
                            } else {
                                // Return the closest known nodes
                                let closest_nodes = rt.find_closest_nodes(id, DEFAULT_K).await;
                                KademliaMessage::Response {
                                    nodes: closest_nodes,
                                    value: None,
                                    sender: self_ref.clone(),
                                }
                            };

                            if cfg!(debug_assertions) {
                                //println!("Responding to message with {:?}", response);
                            }

                            if let Err(e) = message_handler.send_no_recv(&socket, self_ref.clone(), &src, &response).await {
                                eprintln!("Failed to send response to {}: {:?}", src, e);
                            }
                        }

                        // Store a key-value pair
                        KademliaMessage::Store { key, value, .. } => {
                            routing_table.lock().await.add_node_from_responder(Arc::clone(&message_handler), sender_node.clone(), Arc::clone(&socket)).await;
                            data_store.lock().await.insert(key, value);
                        }

                        // Use find_closest_nodes() if value is not found
                        KademliaMessage::FindValue { key, .. } => {
                            let mut rt = routing_table.lock().await;

                            rt.add_node_from_responder(Arc::clone(&message_handler), sender_node.clone(), Arc::clone(&socket)).await;
                            let value = data_store.lock().await.get(&key).cloned();

                            let response = if let Some(val) = value {
                                KademliaMessage::Response {
                                    nodes: vec![],
                                    value: Some(val),
                                    sender: self_ref.clone(),
                                }
                            } else {
                                let closest_nodes = rt.find_closest_nodes(key, DEFAULT_K).await;

                                KademliaMessage::Response {
                                    nodes: closest_nodes,
                                    value: None,
                                    sender: self_ref.clone(),
                                }
                            };

                            if let Err(e) = message_handler.send_no_recv(&socket, self_ref.clone(), &src, &response).await {
                                eprintln!("Failed to send response to {}: {:?}", src, e);
                            }
                        }

                        KademliaMessage::Response { nodes, value, sender, .. } => {
                            let mut rt = routing_table.lock().await;
                            rt.add_node_from_responder(Arc::clone(&message_handler), sender_node.clone(), Arc::clone(&socket)).await;

                            let constructed = KademliaMessage::Response {
                                nodes,
                                value,
                                sender,
                            };

                            let tx_info = message_handler.send_tx(sender_node.address, MessageChannel { node_id: sender_node.id, msg: constructed }).await;

                            match tx_info {
                                Ok(_) => {}
                                Err(e) => {
                                    eprintln!("Failed to send TX for message from {}: {:?}", src, e);
                                }
                            }
                        }

                        KademliaMessage::Ping { .. } => {
                            if let Err(e) = message_handler.send_no_recv(&socket, self_ref.clone(), &src, &KademliaMessage::Pong { sender: self_ref.clone() }).await {
                                eprintln!("Failed to send response to {}: {:?}", src, e);
                            }
                        }

                        KademliaMessage::Pong { sender, .. } => {
                            let tx_info = message_handler.send_tx(sender_node.address, MessageChannel { node_id: sender_node.id, msg: KademliaMessage::Pong { sender } }).await;

                            match tx_info {
                                Ok(_) => {}
                                Err(e) => {
                                    eprintln!("Failed to send TX for message from {}: {:?}", src, e);
                                }
                            }
                        }

                        KademliaMessage::Stop {} => {
                            if sender_node.address == self_ref.address {
                                break;
                            }
                        }
                    }
                }
            }
            println!("FINISHED {}", socket.local_addr().unwrap());
            drop(socket);
        });
        *Arc::get_mut(&mut self.join_handle).unwrap() = Some(handle);
    }

    pub async fn stop(&self) {
        self.stop_signal.store(true, Ordering::Relaxed);

        if let Some(handle) = Arc::get_mut(&mut self.join_handle.clone()).and_then(|h| h.take()) {
            handle.abort();
            let _ = handle.await;
        }

        self.socket.send_to(&*serde_json::to_vec(&KademliaMessage::Stop {}).unwrap(), &self.receive_addr).await.unwrap();
    }

    pub async fn iterative_find_node(&self, socket: Arc<UdpSocket>, target_id: u128) -> Vec<Node> {
        let self_node = self.get_node().await;

        let mut queried_nodes = HashSet::new();

        let mut closest_nodes = self.routing_table.lock().await.find_closest_nodes(target_id, LOOKUP_ALPHA).await;
        if closest_nodes.contains(&self_node) {
            closest_nodes = self.routing_table.lock().await.find_closest_nodes(target_id, LOOKUP_ALPHA + 1).await;
            closest_nodes.retain(|x| *x != self_node);
        }
        let mut all_nodes = closest_nodes.clone();

        let mut best_known_distance = u128::MAX;

        let mut run_k_search = false;
        let mut end_search = false;

        //println!("{:?}", all_nodes);

        while !end_search {
            let mut tasks = Vec::new();

            for node in closest_nodes.iter() {
                if queried_nodes.contains(&node.address) {
                    continue;
                }

                queried_nodes.insert(node.address);
                let socket_clone = Arc::clone(&socket);
                let node_clone = node.clone();
                let message_handler = Arc::clone(&self.message_handler);
                let self_thread_node = self_node.clone();

                // Spawn async task for each lookup request
                let task = task::spawn(async move {
                    let message = KademliaMessage::FindNode {
                        id: target_id,
                        sender: self_thread_node.clone(),
                    };

                    {
                        if let Err(e) = message_handler.send(&socket_clone, self_thread_node.clone(), &node_clone.address, &message).await {
                            eprintln!("Failed to send FindNode to {}: {:?}", node_clone.address, e);
                        }
                    }

                    let response;
                    {
                        response = message_handler.recv(200, &node_clone.address).await;
                    }

                    if response.is_ok() {
                        let msg = response.unwrap();
                        match msg {
                            KademliaMessage::Response { nodes, .. } => {
                                Some(nodes)
                            }
                            _ => {
                                None
                            }
                        }
                    } else {
                        None
                    }
                });

                tasks.push(task);
            }

            for task in tasks {
                if let Ok(Some(nodes)) = task.await {
                    for node in nodes {
                        all_nodes.push(node.clone());
                    }
                }
            }

            all_nodes.dedup();
            all_nodes.retain(|x| *x != self_node);

            if run_k_search {
                end_search = true;
                break;
            }

            let mut found_closer = false;
            for node in all_nodes.clone() {
                let distance = node.id ^ target_id;
                if distance < best_known_distance {
                    best_known_distance = distance;
                    found_closer = true;
                }
            }

            closest_nodes = all_nodes.clone();
            closest_nodes.retain(|x| !queried_nodes.contains(&x.address));
            closest_nodes.sort_by_key(|n| n.id ^ target_id);

            if found_closer {
                closest_nodes.truncate(LOOKUP_ALPHA);
            } else {
                run_k_search = true;
                closest_nodes.truncate(DEFAULT_K);
            }
        }

        all_nodes.push(self_node.clone());
        all_nodes.sort_by_key(|n| n.id ^ target_id);
        all_nodes.truncate(DEFAULT_K);
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
        let mut closest_nodes = self.routing_table.lock().await.find_closest_nodes(key, LOOKUP_ALPHA).await;
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
                let message_handler = Arc::clone(&self.message_handler);
                let self_thread_node = self_node.clone();

                // Spawn async task for each lookup request
                let task = task::spawn(async move {
                    let message = KademliaMessage::FindValue {
                        key,
                        sender: self_thread_node.clone(),
                    };

                    {
                        if let Err(e) = message_handler.send(&socket_clone, self_thread_node.clone(), &node_clone.address, &message).await {
                            eprintln!("Failed to send FindValue to {}: {:?}", node_clone.address, e);
                        }
                    }

                    let response;
                    {
                        response = message_handler.recv(200, &node_clone.address).await;
                    }

                    if response.is_ok() {
                        let msg = response.unwrap();
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
                    } else {
                        Some(Err(vec![]))
                    }
                });

                tasks.push(task);
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
                closest_nodes.dedup();
                closest_nodes.truncate(LOOKUP_ALPHA);
            }
        }

        None
    }

    pub async fn store_value(&mut self, socket: Arc<UdpSocket>, key: u128, value: String) -> Vec<Node> {
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
                sender: self_node.clone(),
            };

            // Send STORE message
            {
                if let Err(e) = self.message_handler.send_no_recv(&socket, self_node.clone(), &node.address, &store_message).await {
                    eprintln!("Failed to send Store to {}: {:?}", node.address, e);
                }
            }
        }

        closest_nodes
    }

    // Add a node to the routing table
    pub async fn add_node(&self, socket: &UdpSocket, node: Node) {
        let self_node = self.get_node().await;
        if node.id != self_node.id {
            let message_handler = Arc::clone(&self.message_handler);
            self.routing_table.lock().await.add_node(message_handler, node, socket).await;
        }
    }

    pub async fn join_network(&mut self, socket: Arc<UdpSocket>, target: &SocketAddr) {
        let self_node = self.get_node().await;
        let socket_clone = Arc::clone(&socket);
        let message = KademliaMessage::FindNode {
            id: self_node.id,
            sender: self_node.clone(),
        };

        {
            if let Err(e) = self.message_handler.send(&socket, self_node.clone(), &target, &message).await {
                eprintln!("Failed to send FindNode to {}: {:?}", target, e);
            }
        }

        let response;
        {
            response = self.message_handler.recv(200, &target).await;
        }

        if response.is_ok() {
            self.iterative_find_node(socket_clone, self_node.id).await;
        } else {
            println!("FAILED TO JOIN NETWORK");
        }
    }
}

/// TESTS
#[cfg(test)]
mod kad_tests {
    use std::time::Duration;
    use super::*;
    use tokio::time::sleep;
    use kademlia_structs::{MessageHandler, Node, RoutingTable, DEFAULT_K};

    async fn create_test_node(id: u128, port: u16) -> Kademlia {
        let mut node = Kademlia::new(id, "127.0.0.1", port, RoutingTable::new(Node {id, address: SocketAddr::new("127.0.0.1".parse().unwrap(), port)}), MessageHandler::create(1)).await;

        // Spawn a task to keep the node running and listening
        node.start(Arc::clone(&node.socket)).await;

        node
    }

    #[tokio::test]
    async fn test_iterative_find_node() {
        // Create multiple nodes and bind them to real sockets
        let mut node1 = create_test_node(1, 8005).await;
        let mut node2 = create_test_node(2, 8006).await;
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

        assert!(rt.buckets().await.get(&index).unwrap().contains(node.id), "Node should be in the routing table");
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
            orig = rt.buckets().await.get(&bucket_index).unwrap().clone();
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
            new = rt.buckets().await.get(&bucket_index).unwrap().clone();
        }

        // Ensure that the original bucket is the same
        println!("Routing Table Before Overflow: {:?}", orig);
        println!("Routing Table After Overflow: {:?}", new);
        assert_eq!(new.nodes[DEFAULT_K - 1], test_info.clone(), "Bucket should have same nodes");

        test.stop().await;

        kad.add_node(&kad.socket, overflow_node.clone()).await;

        {
            let rt = kad.routing_table.lock().await;
            new = rt.buckets().await.get(&bucket_index).unwrap().clone();
            println!("Routing Table After Guaranteed LRU Removal: {:?}", rt.buckets().await.get(&bucket_index).unwrap());
        }

        // Ensure that the original bucket has new node
        assert_eq!(new.nodes[DEFAULT_K - 1], overflow_node, "Bucket should have new LRU");
        {
            let rt = kad.routing_table.lock().await;
            assert!(
                rt.buckets().await.get(&bucket_index).unwrap().contains(overflow_node.id),
                "Overflow node should be in the bucket"
            );
        }

        kad.stop().await;
    }

    #[tokio::test]
    async fn test_iterative_find_value() {
        // Create multiple nodes and bind them to real sockets
        let mut node1 = create_test_node(1, 8001).await;
        let mut node2 = create_test_node(2, 8002).await;
        let mut node3 = create_test_node(3, 8003).await;
        let mut node4 = create_test_node(4, 8004).await;

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