use std::cmp::PartialEq;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{Read, Write};
use std::net::{SocketAddr};
use std::ops::Deref;
use std::sync::{Arc};
use std::sync::atomic::{AtomicBool, Ordering};
use lazy_static::lazy_static;
use rand::Rng;
use serde::{Serialize, Deserialize};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::task;
use tokio::time::{timeout, Duration};

// Kademlia Struct
pub struct Kademlia {
    pub node: Arc<Mutex<Node>>,
    pub socket: Arc<UdpSocket>,
    pub receive_addr: SocketAddr,
    routing_table: Arc<Mutex<RoutingTable>>,
    pub data_store: Arc<Mutex<HashMap<u128, String>>>,
    pub response_queue: Arc<Mutex<HashMap<u128, Vec<KademliaMessage>>>>,
    rx: Option<Arc<Mutex<UnboundedReceiver<MessageChannel>>>>,
    stop_signal: Arc<AtomicBool>,
    join_handle: Arc<Option<task::JoinHandle<()>>>,
}

impl Kademlia {
    pub async fn new(id: u128, address: &str, port: u16) -> Self {
        let node = Node { id, address: format!("{address}:{port}").parse().unwrap() };
        let rt = RoutingTable::new(node.clone());

        Self {
            node: Arc::new(Mutex::new(node)),
            socket: Arc::new(UdpSocket::bind(format!("{}:{}", address, port)).await.unwrap()),
            receive_addr: format!("{address}:{port}").parse().unwrap(),
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

                            // **SIMULATOR CODE**
                            let mut sim_running = false;
                            {
                                let sim = SIM.lock().await;
                                {
                                    if !sim.sims.lock().await.is_empty() {
                                        sim_running = true;
                                    }
                                }
                            }

                            if sim_running {
                                response.send_sim(&socket, &src).await;
                            } else {
                                response.send(&socket, &src).await;
                            }
                            // **END SIMULATOR CODE**

                            //response.send(&socket, &src).await;
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

                            // **SIMULATOR CODE**
                            let mut sim_running = false;
                            {
                                let sim = SIM.lock().await;
                                {
                                    if !sim.sims.lock().await.is_empty() {
                                        sim_running = true;
                                    }
                                }
                            }

                            if sim_running {
                                response.send_sim(&socket, &src).await;
                            } else {
                                response.send(&socket, &src).await;
                            }
                            // **END SIMULATOR CODE**

                            //response.send(&socket, &src).await;
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

                        // **SIMULATOR CODE**
                        let mut sim_running = false;
                        {
                            let sim = SIM.lock().await;
                            {
                                if !sim.sims.lock().await.is_empty() {
                                    sim_running = true;
                                }
                            }
                        }

                        let response;
                        if sim_running {
                            message.send_sim(&socket_clone, &node_clone.address).await;

                            // Wait up to 300ms for a response asynchronously
                            response = KademliaMessage::recv_sim(response_queue, rx, 300, &node_clone.address).await;
                        } else {
                            message.send(&socket_clone, &node_clone.address).await;

                            // Wait up to 300ms for a response asynchronously
                            response = KademliaMessage::recv(response_queue, rx, 300).await;
                        }
                        // **END SIMULATOR CODE**

                        //message.send(&*socket_clone, &node_clone.address).await;

                        //let response = KademliaMessage::recv(response_queue, rx, 200).await;

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

                        // **SIMULATOR CODE**
                        let mut sim_running = false;
                        {
                            let sim = SIM.lock().await;
                            {
                                if !sim.sims.lock().await.is_empty() {
                                    sim_running = true;
                                }
                            }
                        }

                        let response;
                        if sim_running {
                            message.send_sim(&socket_clone, &node_clone.address).await;

                            // Wait up to 300ms for a response asynchronously
                            response = KademliaMessage::recv_sim(response_queue, rx, 300, &node_clone.address).await;
                        } else {
                            message.send(&socket_clone, &node_clone.address).await;

                            // Wait up to 300ms for a response asynchronously
                            response = KademliaMessage::recv(response_queue, rx, 300).await;
                        }
                        // **END SIMULATOR CODE**

                        //message.send(&*socket_clone, &node_clone.address).await;

                        //let response = KademliaMessage::recv(response_queue, rx, 200).await;

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

            // **SIMULATOR CODE**
            let mut sim_running = false;
            {
                let sim = SIM.lock().await;
                {
                    if !sim.sims.lock().await.is_empty() {
                        sim_running = true;
                    }
                }
            }

            if sim_running {
                store_message.send_sim(&socket, &node.address).await;
            } else {
                store_message.send(&socket, &node.address).await;
            }
            // **END SIMULATOR CODE**

            // Send STORE message
            //store_message.send(&socket, &node.address).await;
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

            // **SIMULATOR CODE**
            let mut sim_running = false;
            {
                let sim = SIM.lock().await;
                {
                    if !sim.sims.lock().await.is_empty() {
                        sim_running = true;
                    }
                }
            }

            let response;
            if sim_running {
                message.send_sim(&socket_clone, target).await;

                // Wait up to 300ms for a response asynchronously
                response = KademliaMessage::recv_sim(response_queue, rx, 300, target).await;
            } else {
                message.send(&socket_clone, target).await;

                // Wait up to 300ms for a response asynchronously
                response = KademliaMessage::recv(response_queue, rx, 300).await;
            }
            // **END SIMULATOR CODE**

            //message.send(&*socket, target).await;

            //let response = KademliaMessage::recv(response_queue, rx, 300).await;

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

lazy_static! {
    static ref SIM: Arc<Mutex<Simulator>> = Arc::new(Mutex::new(Simulator::new_empty()));
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileNode {
    pub id: u128,
    pub address: String,
    pub routing_table: Vec<Node>,
    pub data_store: HashMap<u128, String>,
    pub response_queue: HashMap<u128, Vec<KademliaMessage>>,
    pub locked: bool,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulatedNode {
    pub node: Node,
    pub routing_table: RoutingTable,
    pub data_store: HashMap<u128, String>,
    pub response_queue: HashMap<u128, Vec<KademliaMessage>>,
    pub locked: bool,
}

impl SimulatedNode {
    pub fn new(node: Node, rt: RoutingTable, ds: HashMap<u128, String>, rq: HashMap<u128, Vec<KademliaMessage>>) -> SimulatedNode {
        SimulatedNode {
            node,
            routing_table: rt,
            data_store: ds,
            response_queue: rq,
            locked: false,
        }
    }

    fn set_routing_table(&mut self, rt: &mut RoutingTable) {
        self.routing_table.set(rt);
    }

    fn set_data_store(&mut self, data_store: &mut HashMap<u128, String>) {
        self.data_store.clear();

        for i in data_store.iter() {
            self.data_store.insert(*i.0, i.1.clone());
        }
    }

    fn set_response_queue(&mut self, response_queue: &mut HashMap<u128, Vec<KademliaMessage>>) {
        self.response_queue.clear();

        for i in response_queue.iter() {
            self.response_queue.insert(*i.0, i.1.clone());
        }
    }
}

// Simulator Struct
#[derive(Clone)]
pub struct Simulator {
    pub available: Arc<Mutex<Vec<Kademlia>>>,
    pub unavailable: Arc<Mutex<HashMap<SocketAddr, Kademlia>>>,
    pub availability_queue: Arc<Mutex<VecDeque<SocketAddr>>>,
    pub sims: Arc<Mutex<HashMap<SocketAddr, SimulatedNode>>>,
    pub sim_to_real_map: Arc<Mutex<HashMap<SocketAddr, SocketAddr>>>,
    pub real_to_sim_map: Arc<Mutex<HashMap<SocketAddr, SocketAddr>>>,
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

    // Generate the nodes which the simulator will use
    async fn create_sim_node(id: u128, port: u16) -> Kademlia {
        let mut node = Kademlia::new(id, "127.0.0.1", port).await;

        // Spawn a task to keep the node running and listening
        node.start(Arc::clone(&node.socket)).await;

        node
    }

    // Setup the simulator
    pub async fn new(start_port: u16, available_total: u8, current_simulators: Vec<SimulatedNode>) -> Simulator {
        let mut created_sims = vec![];
        let mut sims_hash = HashMap::new();

        for i in 0..available_total {
            created_sims.push(Simulator::create_sim_node(0, start_port + i as u16).await);
        }

        for i in 0..current_simulators.len() {
            sims_hash.insert(current_simulators[i].node.address, current_simulators[i].clone());
        }

        Simulator {
            available: Arc::new(Mutex::new(created_sims)),
            unavailable: Arc::new(Mutex::new(HashMap::new())),
            availability_queue: Arc::new(Mutex::new(VecDeque::new())),
            sims: Arc::new(Mutex::new(sims_hash)),
            sim_to_real_map: Arc::new(Mutex::new(HashMap::new())),
            real_to_sim_map: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn new_empty() -> Simulator {
        Simulator {
            available: Arc::new(Mutex::new(vec![])),
            unavailable: Arc::new(Mutex::new(HashMap::new())),
            availability_queue: Arc::new(Mutex::new(VecDeque::new())),
            sims: Arc::new(Mutex::new(HashMap::new())),
            sim_to_real_map: Arc::new(Mutex::new(HashMap::new())),
            real_to_sim_map: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // Save the state of a Kademlia node to the simulator storage
    pub async fn save_state(&self, kademlia: &Kademlia) {
        let mut sims = self.sims.lock().await;
        let sim = sims.get_mut(&kademlia.node.lock().await.address);
        match sim {
            Some(sim) => {
                sim.set_data_store(&mut kademlia.data_store.lock().await.clone());
                sim.set_routing_table(&mut kademlia.routing_table.lock().await.clone());
                sim.set_response_queue(&mut kademlia.response_queue.lock().await.clone());
            }
            _ => {}
        }
    }

    pub async fn lock_node_from_sim(&self, address: SocketAddr) {
        let mut sims = self.sims.lock().await;
        let sim = sims.get_mut(&address);

        {
            self.update_lru(address).await;
        }

        match sim {
            Some(sim) => {
                sim.locked = true;
            }
            _ => {}
        }
    }

    pub async fn lock_node_from_real(&self, address: SocketAddr) {
        let mut sims = self.sims.lock().await;
        let mut sim = None;
        if let Some(sim_addr) = self.real_to_sim_map.lock().await.get(&address) {
            {
                self.update_lru(*sim_addr).await;
            }

            sim = sims.get_mut(sim_addr);
        }

        match sim {
            Some(sim) => {
                sim.locked = true;
            }
            _ => {}
        }
    }

    pub async fn unlock_node_from_sim(&self, address: SocketAddr) {
        let mut sims = self.sims.lock().await;
        let sim = sims.get_mut(&address);

        match sim {
            Some(sim) => {
                sim.locked = false;
            }
            _ => {}
        }
    }

    pub async fn unlock_node_from_real(&self, address: SocketAddr) {
        let mut sims = self.sims.lock().await;
        let mut sim = None;
        if let Some(sim_port) = self.real_to_sim_map.lock().await.get(&address) {
            sim = sims.get_mut(sim_port);
        }

        match sim {
            Some(sim) => {
                sim.locked = false;
            }
            _ => {}
        }
    }

    pub async fn is_locked(&self, address: SocketAddr) -> bool {
        let mut sims = self.sims.lock().await;
        let sim = sims.get_mut(&address);
        match sim {
            Some(sim) => {
                sim.locked
            }
            _ => {
                false
            }
        }
    }

    pub async fn node_running_from_sim(&self, address: SocketAddr) -> bool {
        if self.unavailable.lock().await.contains_key(&address) {
            return true;
        }

        false
    }

    pub async fn node_running_from_real(&self, address: SocketAddr) -> bool {
        let sim_addr;
        if let Some(sim_address) = self.real_to_sim_map.lock().await.get(&address) {
            sim_addr = sim_address.clone();
        } else {
            return false;
        }

        if self.unavailable.lock().await.contains_key(&sim_addr) {
            return true;
        }

        false
    }

    pub async fn get_socket_address(&self, address: SocketAddr) -> Option<SocketAddr> {
        self.sim_to_real_map.lock().await.get(&address).cloned()
    }

    pub async fn update_lru(&self, address: SocketAddr) {
        let mut aq = self.availability_queue.lock().await;

        if aq.contains(&address) {
            aq.retain(|n| n != &address);
            aq.push_back(address);
        }
    }

    // Remove a node from the unavailable list then saves its state and makes
    // it available
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
                let temp_node = &mut Node { id: 0, address: "127.0.0.1:7999".parse().unwrap() };
                val.set_node(temp_node).await;
                val.set_routing_table(&mut RoutingTable::new(temp_node.clone())).await;
                val.set_data_store(&mut HashMap::new()).await;
                val.set_response_queue(&mut HashMap::new()).await;

                {
                    self.available.lock().await.push(val);
                    let mut strm = self.sim_to_real_map.lock().await;
                    if let Some(real) = strm.remove(&address) {
                        self.real_to_sim_map.lock().await.remove(&real);
                    }
                    let mut aq = self.availability_queue.lock().await;

                    if aq.contains(&address) {
                        aq.retain(|n| n != &address);
                    }
                }
            }
            None => {}
        }
    }

    async fn make_available(&self) {
        let old;
        {
            let mut aq = self.availability_queue.lock().await;
            old = aq.pop_front();
        }

        match old {
            Some(val) => {
                let mut exit = false;
                while !exit {
                    {
                        if let Some(sim) = self.sims.lock().await.get(&val) {
                            if !sim.locked {
                                exit = true;
                            }
                        }
                    }
                }
                self.remove_node(val).await;
            }
            None => {}
        }
    }

    // Run a simulated node; gets an available slot from the available list and
    // sets its data accordingly then maps the port
    pub async fn add_node(&self, address: SocketAddr) -> Option<SocketAddr> {
        let started;
        {
            started = self.unavailable.lock().await.contains_key(&address);
        }

        if !started {
            let has_available;
            {
                has_available = self.available.lock().await.len() > 0;
            }

            if !has_available {
                self.make_available().await;
            }

            let mut sim_data = None;
            {
                let sims = self.sims.lock().await;
                let sim = sims.get(&address);
                match sim {
                    Some(sim) => {
                        sim_data = Some(sim.clone());
                    }
                    _ => {}
                }
            }

            return match sim_data {
                Some(mut val) => {
                    let kad;
                    {
                        kad = self.available.lock().await.pop().unwrap();
                    }

                    kad.set_node(&mut val.node).await;
                    kad.set_routing_table(&mut val.routing_table.clone()).await;
                    kad.set_data_store(&mut val.data_store).await;
                    kad.set_response_queue(&mut val.response_queue).await;

                    let kad_socket = kad.receive_addr;

                    {
                        self.unavailable.lock().await.insert(address, kad);
                        self.sim_to_real_map.lock().await.insert(address, kad_socket);
                        self.real_to_sim_map.lock().await.insert(kad_socket, address);
                        self.availability_queue.lock().await.push_back(address);
                    }

                    Some(kad_socket)
                }
                None => {
                    None
                }
            }
        }
        None
    }

    pub async fn create_node(&self, new_node: SimulatedNode) {
        self.sims.lock().await.insert(new_node.node.address, new_node);
    }

    pub async fn get_node(&self, address: SocketAddr) -> Option<SimulatedNode> {
        {
            if let Some(kad) = self.unavailable.lock().await.get(&address) {
                self.save_state(kad).await;
            }
        }
        self.sims.lock().await.get(&address).cloned()
    }

    pub async fn get_all_nodes(&self) -> Vec<SimulatedNode> {
        let mut finished = vec![];
        let sims;
        {
            sims = self.sims.lock().await.clone();
        }

        for i in sims {
            if let Some(node) = self.get_node(i.0).await {
                finished.push(node);
            }
        }

        finished
    }

    // Stops all running nodes and saves their states
    pub async fn stop(&self) {
        {
            let available = self.available.lock().await;
            for kad in available.iter() {
                kad.stop().await;
            }
        }

        {
            let unavailable = self.unavailable.lock().await;
            for kad in unavailable.iter() {
                self.save_state(kad.1).await;
                kad.1.stop().await;
            }
        }
    }
}

fn file_node_to_simulated(file_node: FileNode) -> SimulatedNode {
    let mut rt = RoutingTable::new(Node { id: file_node.id, address: file_node.address.parse().unwrap() });

    for node in file_node.routing_table {
        rt.insert_direct(node);
    }

    SimulatedNode::new(Node { id: file_node.id, address: file_node.address.parse().unwrap() }, rt, file_node.data_store, file_node.response_queue)
}

fn simulated_node_to_file(sim_node: SimulatedNode) -> FileNode {
    FileNode {
        id: sim_node.node.id,
        address: sim_node.node.address.to_string(),
        routing_table: sim_node.routing_table.flat(),
        data_store: sim_node.data_store,
        response_queue: sim_node.response_queue,
        locked: sim_node.locked,
    }
}

/// Loads SimulatedNodes from a JSON file
pub fn load_simulated_nodes(file_path: &str) -> Result<Vec<SimulatedNode>, Box<dyn std::error::Error>> {
    let mut file = File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let file_nodes: Vec<FileNode> = serde_json::from_str(&contents)?;
    let mut simulated_nodes = vec![];
    for node in file_nodes {
        simulated_nodes.push(file_node_to_simulated(node));
    }
    Ok(simulated_nodes)
}

/// Saves SimulatedNodes to a JSON file
pub fn save_simulated_nodes(file_path: &str, nodes: &Vec<SimulatedNode>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file_nodes = vec![];
    for node in nodes {
        file_nodes.push(simulated_node_to_file(node.clone()));
    }

    let json_string = serde_json::to_string_pretty(&file_nodes)?;
    let mut file = File::create(file_path)?;
    file.write_all(json_string.as_bytes())?;
    Ok(())
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
        let mut node = Kademlia::new(id, "127.0.0.1", port).await;

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

        assert!(rt.buckets.get(&index).unwrap().contains(node.id), "Node should be in the routing table");
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
            orig = rt.buckets.get(&bucket_index).unwrap().clone();
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
            new = rt.buckets.get(&bucket_index).unwrap().clone();
        }

        // Ensure that the original bucket is the same
        println!("Routing Table Before Overflow: {:?}", orig);
        println!("Routing Table After Overflow: {:?}", new);
        assert_eq!(new.nodes[DEFAULT_K - 1], test_info.clone(), "Bucket should have same nodes");

        test.stop().await;

        kad.add_node(&kad.socket, overflow_node.clone()).await;

        {
            let rt = kad.routing_table.lock().await;
            new = rt.buckets.get(&bucket_index).unwrap().clone();
            println!("Routing Table After Guaranteed LRU Removal: {:?}", rt.buckets.get(&bucket_index).unwrap());
        }

        // Ensure that the original bucket has new node
        assert_eq!(new.nodes[DEFAULT_K - 1], overflow_node, "Bucket should have new LRU");
        {
            let rt = kad.routing_table.lock().await;
            assert!(
                rt.buckets.get(&bucket_index).unwrap().contains(overflow_node.id),
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