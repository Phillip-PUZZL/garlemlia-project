use async_trait::async_trait;
use kademlia::Kademlia;
use kademlia_structs::{HeapNode, KBucket, KMessage, KademliaMessage, KademliaRoutingTable, MessageChannel, MessageHandler, Node, RoutingTable};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SimulatedRoutingTable {
    local_node: Node,
    buckets: HashMap<u8, KBucket>,
}

#[async_trait]
impl KademliaRoutingTable for SimulatedRoutingTable {
    fn new(local_node: Node) -> Self {
        Self {
            local_node,
            buckets: HashMap::new(),
        }
    }

    fn set(&mut self, new: &dyn KademliaRoutingTable) {
        self.local_node = new.get_local_node().clone();
        self.buckets = new.get_buckets().clone();
    }

    fn get_local_node(&self) -> &Node {
        &self.local_node
    }

    fn get_buckets(&self) -> &HashMap<u8, KBucket> {
        &self.buckets
    }

    fn bucket_index(&self, node_id: u128) -> u8 {
        let xor_distance = self.local_node.id ^ node_id;

        (128 - xor_distance.leading_zeros()) as u8
    }

    fn flat(&self) -> Vec<Node> {
        self.buckets
            .iter()
            .flat_map(|bucket| bucket.1.nodes.iter().cloned())
            .collect()
    }

    fn insert_direct(&mut self, node: Node) {
        let index = self.bucket_index(node.id);
        if let Some(bucket) = self.buckets.get_mut(&index) {
            bucket.insert(node);
        } else {
            self.buckets.insert(index, KBucket::new());
            if let Some(bucket_new) = self.buckets.get_mut(&index) {
                bucket_new.insert(node);
            }
        }
    }

    fn check_buckets(&mut self, node: Node, index: u8) -> bool {
        // If node already exists, move it to the back (most recently seen)
        let bucket = self.buckets.get_mut(&index);

        match bucket {
            Some(bucket) => {
                if !bucket.is_full() {
                    bucket.update_node(node.clone());
                    return true
                }
                false
            }
            None => {
                self.buckets.insert(index, KBucket::new());
                if let Some(bucket_new) = self.buckets.get_mut(&index) {
                    bucket_new.insert(node);
                }
                true
            }
        }
    }

    // Add a node to the routing table from Kademlia Responder
    async fn add_node_from_responder(&mut self, node: Node, socket: &UdpSocket) {
        let index = self.bucket_index(node.id);

        if self.check_buckets(node.clone(), index) {
            return;
        }

        let bucket = self.buckets.get_mut(&index).unwrap();

        // Query the LRU node before evicting it
        if let Some(lru_node) = bucket.nodes.clone().front() {
            let lru_address = lru_node.address;

            // Send a ping message to check if LRU node is alive
            let ping_message = KademliaMessage::FindNode {
                id: lru_node.id,
                sender_id: self.local_node.id,
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

            let mut buf = [0; 1024];
            let response;
            if sim_running {
                SimulatedMessageHandler::create().send(socket, &lru_address, &ping_message).await;

                response = timeout(Duration::from_millis(300), async {
                    // Try to receive a response
                    match socket.recv_from(&mut buf).await {
                        Ok((_size, src)) => {
                            let sim_src;
                            {
                                let sim = SIM.lock().await;
                                let map = sim.real_to_sim_map.lock().await;
                                if let Some(new_src) = map.get(&src) {
                                    sim_src = new_src.clone();
                                } else {
                                    sim_src = src.clone();
                                }
                            }
                            if sim_src == lru_address {
                                // The LRU node responded, so keep it in the bucket and push to the front
                                bucket.update_node(lru_node.clone());
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
            } else {
                SimulatedMessageHandler::create().send(socket, &lru_address, &ping_message).await;

                response = timeout(Duration::from_millis(300), async {
                    // Try to receive a response
                    match socket.recv_from(&mut buf).await {
                        Ok((_size, src)) => {
                            if src == lru_address {
                                // The LRU node responded, so keep it in the bucket and push to the front
                                bucket.update_node(lru_node.clone());
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
            }
            // **END SIMULATOR CODE**

            if !response {
                // No response, replace it with the new node
                // No valid response from the LRU node → Remove it
                bucket.remove(lru_node.clone());
                // Add the new node after LRU eviction
                bucket.insert(node);
            }
        }
    }

    // Add a node to the routing table
    async fn add_node(&mut self,
                      response_queue: Arc<Mutex<HashMap<u128, Vec<KademliaMessage>>>>,
                      rx: Arc<Mutex<UnboundedReceiver<MessageChannel>>>,
                      node: Node, socket: &UdpSocket) {
        if self.local_node.id == node.id {
            return;
        }

        let index = self.bucket_index(node.id);

        if self.check_buckets(node.clone(), index) {
            return;
        }

        let bucket = self.buckets.get_mut(&index).unwrap();

        // Query the LRU node before evicting it
        if let Some(lru_node) = bucket.nodes.clone().front() {
            let lru_address = lru_node.address;

            // Send a ping message to check if LRU node is alive
            let ping_message = KademliaMessage::FindNode {
                id: lru_node.id,
                sender_id: self.local_node.id,
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
                SimulatedMessageHandler::create().send(socket, &lru_address, &ping_message).await;

                // Wait up to 300ms for a response asynchronously
                response = SimulatedMessageHandler::create().recv(response_queue, rx, 300, &lru_address).await;
            } else {
                SimulatedMessageHandler::create().send(socket, &lru_address, &ping_message).await;

                // Wait up to 300ms for a response asynchronously
                response = SimulatedMessageHandler::create().recv(response_queue, rx, 300, &lru_address).await;
            }
            // **END SIMULATOR CODE**

            match response {
                Some(msg) => {
                    match msg {
                        KademliaMessage::Response { sender_id, .. } => {
                            if sender_id == lru_node.id {
                                bucket.update_node(lru_node.clone());
                            }
                        }
                        _ => {}
                    }
                }
                None => {
                    // No response, replace it with the new node
                    // No valid response from the LRU node → Remove it
                    bucket.remove(lru_node.clone());
                    // Add the new node after LRU eviction
                    bucket.insert(node);
                }
            }
        }
    }

    // Find the closest nodes based on XOR distance
    fn find_closest_nodes(&mut self, target_id: u128, count: usize) -> Vec<Node> {
        let mut heap = BinaryHeap::new();
        heap.push(HeapNode { distance: target_id ^ self.local_node.id, node: self.local_node.clone() });

        let mut searched_buckets = 0;
        let start_index = self.bucket_index(target_id);

        // Get all existing bucket indices in sorted order
        let mut bucket_indices: Vec<u8> = self.buckets.keys().cloned().collect();
        bucket_indices.sort();

        // Find the closest bucket index to start searching from
        let closest_index_pos = bucket_indices
            .binary_search(&start_index)
            .unwrap_or_else(|pos| pos.min(bucket_indices.len().saturating_sub(1))); // If not found, returns where it should be inserted

        let mut left = closest_index_pos as isize;
        let mut right = closest_index_pos as isize + 1;

        // Expand search outward from the closest bucket index
        while searched_buckets < bucket_indices.len() {
            if left >= 0 && (left as usize) < bucket_indices.len() {
                if let Some(bucket) = self.buckets.get(&bucket_indices[left as usize]) {
                    for node in &bucket.nodes {
                        let distance = target_id ^ node.id;
                        heap.push(HeapNode { distance, node: node.clone() });

                        if heap.len() > count {
                            heap.pop();
                        }
                    }
                    searched_buckets += 1;
                }
                left -= 1;
            }

            if right < bucket_indices.len() as isize {
                if let Some(bucket) = self.buckets.get(&bucket_indices[right as usize]) {
                    for node in &bucket.nodes {
                        let distance = target_id ^ node.id;
                        heap.push(HeapNode { distance, node: node.clone() });

                        if heap.len() > count {
                            heap.pop();
                        }
                    }
                    searched_buckets += 1;
                }
                right += 1;
            }

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

    fn clone_box(&self) -> Box<dyn KademliaRoutingTable> {
        Box::new(self.clone())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SimulatedMessageHandler {}

#[async_trait]
impl KMessage for SimulatedMessageHandler {
    fn create() -> Box<dyn KMessage> {
        Box::new(SimulatedMessageHandler {})
    }

    // Send a message to another node
    async fn send(&self, socket: &UdpSocket, target: &SocketAddr, msg: &KademliaMessage) {
        println!("send - sim to {} from {}", target, socket.local_addr().unwrap());
        let mut target_real = target.clone();
        let mut needs_to_fuck_off = false;
        {
            let mut sim_running = false;
            let mut has_available = false;
            let mut node_running = false;
            {
                let sim = SIM.lock().await;
                let sims;
                {
                    sims = sim.sims.lock().await.clone();
                }
                if !sims.is_empty() {
                    sim_running = true;
                    has_available = sim.has_unlocked().await;
                    node_running = sim.node_running_from_sim(*target).await;
                }

                if sim_running {
                    if node_running {
                        target_real = sim.get_socket_address(*target).await.expect("REASON");
                        sim.lock_node_from_sim(*target).await;
                        println!("NODE RUNNING AT {}", target_real);
                    } else if has_available {
                        if let Some(addr) = sim.add_node(*target).await {
                            target_real = addr;
                            println!("NODE STARTED AT {}", target_real);
                        } else {
                            println!("NODE FAILED TO START OR RUN AT {}", target_real);
                        }
                        sim.lock_node_from_sim(*target).await;
                    } else {
                        needs_to_fuck_off = true;
                        println!("MUST WAIT FOR NODE TO UNLOCK");
                    }
                }
            }
        }

        if needs_to_fuck_off {
            while needs_to_fuck_off {
                println!("WAITING FOR NODE TO UNLOCK");
                tokio::time::sleep(Duration::from_millis(10)).await;
                {
                    let sim = SIM.lock().await;
                    needs_to_fuck_off = !sim.has_unlocked().await;

                    if !needs_to_fuck_off {
                        if let Some(addr) = sim.add_node(*target).await {
                            target_real = addr;
                            sim.lock_node_from_sim(*target).await;
                            println!("NODE STARTED AT {}", target_real);
                        } else {
                            println!("NODE FAILED TO START OR RUN AT {}", target_real);
                        }
                    }
                }
            }
        }

        let message_bytes = serde_json::to_vec(msg).unwrap();
        socket.send_to(&message_bytes, target_real).await.unwrap();
    }

    async fn recv(&self, response_queue: Arc<Mutex<HashMap<u128, Vec<KademliaMessage>>>>,
                  rx: Arc<Mutex<UnboundedReceiver<MessageChannel>>>, time: u64, src: &SocketAddr) -> Option<KademliaMessage> {
        println!("recv - sim from: {}", src);
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
                println!("Timeout occurred while waiting for response from {}.", src);
                None
            }
        };

        {
            let sim = SIM.lock().await;
            let mut sim_running = false;

            {
                if !sim.sims.lock().await.is_empty() {
                    sim_running = true;
                }
            }

            if sim_running {
                sim.unlock_node_from_sim(*src).await;
            }
        }

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

    fn clone_box(&self) -> Box<dyn KMessage> {
        Box::new(self.clone())
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
    pub routing_table: SimulatedRoutingTable,
    pub data_store: HashMap<u128, String>,
    pub response_queue: HashMap<u128, Vec<KademliaMessage>>,
    pub locked: bool,
}

impl SimulatedNode {
    pub fn new(node: Node, rt: SimulatedRoutingTable, ds: HashMap<u128, String>, rq: HashMap<u128, Vec<KademliaMessage>>) -> SimulatedNode {
        SimulatedNode {
            node,
            routing_table: rt,
            data_store: ds,
            response_queue: rq,
            locked: false,
        }
    }

    fn set_routing_table(&mut self, rt: Box<dyn KademliaRoutingTable>) {
        self.routing_table.set(&*rt);
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
}

impl Simulator {

    // Generate the nodes which the simulator will use
    async fn create_sim_node(id: u128, port: u16) -> Kademlia {
        let mut node = Kademlia::new(id, "127.0.0.1", port, Box::new(RoutingTable::new(Node {id, address: SocketAddr::new("127.0.0.1".parse().unwrap(), port)})), MessageHandler::create()).await;

        // Spawn a task to keep the node running and listening
        node.start(Arc::clone(&node.socket)).await;

        node
    }

    // Set up the simulator
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

    pub fn set(&mut self, new_sim: Simulator) {
        self.available = new_sim.available.clone();
        self.unavailable = new_sim.unavailable.clone();
        self.availability_queue = new_sim.availability_queue.clone();
        self.sims = new_sim.sims.clone();
        self.sim_to_real_map = new_sim.sim_to_real_map.clone();
        self.real_to_sim_map = new_sim.real_to_sim_map.clone();
    }

    // Save the state of a Kademlia node to the simulator storage
    pub async fn save_state(&self, kademlia: &Kademlia) {
        let mut sims = self.sims.lock().await;
        let sim = sims.get_mut(&kademlia.node.lock().await.address);
        match sim {
            Some(sim) => {
                sim.set_data_store(&mut kademlia.data_store.lock().await.clone());
                sim.set_routing_table(kademlia.routing_table.lock().await.clone());
                sim.set_response_queue(&mut kademlia.response_queue.lock().await.clone());
            }
            _ => {}
        }
    }

    pub async fn lock_node_from_sim(&self, address: SocketAddr) {
        let sim;
        {
            sim = self.sims.lock().await.get(&address).cloned();
            println!("SIMULATED PORT {} MAPPED TO {}", address, self.sim_to_real_map.lock().await.get(&address).unwrap());
        }

        match sim {
            Some(_sim) => {
                {
                    self.update_lru(address).await;
                }
                {
                    let mut test = self.sims.lock().await;
                    test.get_mut(&address).unwrap().locked = true;
                }
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
        let sim;
        {
            sim = self.sims.lock().await.get(&address).cloned();
        }

        match sim {
            Some(_sim) => {
                {
                    let mut test = self.sims.lock().await;
                    test.get_mut(&address).unwrap().locked = false;
                }
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
        let sim;
        {
            sim = self.sims.lock().await.get(&address).cloned();
        }

        match sim {
            Some(sim) => {
                sim.locked
            }
            _ => {
                false
            }
        }
    }

    pub async fn has_unlocked(&self) -> bool {
        let has_available;
        {
            has_available = self.available.lock().await.len() > 0;
        }

        if !has_available {
            {
                let mut aq = self.availability_queue.lock().await;
                for i in aq.iter_mut() {
                    let locked;
                    {
                        locked = self.is_locked(*i).await;
                    }
                    if !locked {
                        return true;
                    }
                }
                false
            }
        } else {
            true
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
                val.set_routing_table(&mut SimulatedRoutingTable::new(temp_node.clone())).await;
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
        let mut old = None;
        {
            let mut aq = self.availability_queue.lock().await;
            let mut index = 0;
            for i in aq.iter_mut() {
                let locked;
                {
                    locked = self.sims.lock().await.get(&i).cloned().unwrap().locked;
                }
                if !locked {
                    old = aq.remove(index);
                    break;
                }
                index += 1;
            }
        }

        match old {
            Some(val) => {
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
        self.sims.lock().await.insert(new_node.node.address.clone(), new_node.clone());
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
                kad.stop(kad.receive_addr, SocketAddr::new("127.0.0.1".parse().unwrap(), 12000)).await;
            }
        }

        {
            let unavailable = self.unavailable.lock().await;
            for kad in unavailable.iter() {
                self.save_state(kad.1).await;
                kad.1.stop(kad.1.receive_addr, SocketAddr::new("127.0.0.1".parse().unwrap(), 12000)).await;
            }
        }
    }
}

pub async fn get_all_nodes() -> Vec<SimulatedNode> {
    let sim = SIM.lock().await;
    sim.stop().await;
    sim.get_all_nodes().await
}

fn file_node_to_simulated(file_node: FileNode) -> SimulatedNode {
    let mut rt = SimulatedRoutingTable::new(Node { id: file_node.id, address: file_node.address.parse().unwrap() });

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
pub async fn load_simulated_nodes(file_path: &str) -> Result<Vec<SimulatedNode>, Box<dyn std::error::Error>> {
    let mut file = File::open(file_path).await?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).await?;
    let file_nodes: Vec<FileNode> = serde_json::from_str(&contents)?;
    let mut simulated_nodes = vec![];
    for node in file_nodes {
        simulated_nodes.push(file_node_to_simulated(node));
    }
    Ok(simulated_nodes)
}

/// Saves SimulatedNodes to a JSON file
pub async fn save_simulated_nodes(file_path: &str, nodes: &Vec<SimulatedNode>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file_nodes = vec![];
    for node in nodes {
        file_nodes.push(simulated_node_to_file(node.clone()));
    }

    let json_string = serde_json::to_string_pretty(&file_nodes)?;
    let mut file = File::create(file_path).await?;
    file.write_all(json_string.as_bytes()).await?;
    Ok(())
}

pub async fn create_network(mut nodes: Vec<SimulatedNode>) {
    let mut sockets = vec![];
    for node in nodes.clone() {
        sockets.push(node.node.address.clone());
    }

    {
        SIM.lock().await.set(Simulator::new(9000, 10, vec![nodes[0].clone()]).await);
    }

    nodes.remove(0);
    let mut index = 0;
    for node in nodes {
        let mut run_node = Kademlia::new(node.node.id, "127.0.0.1", node.node.address.port(), Box::new(SimulatedRoutingTable::new(Node {id: node.node.id, address: SocketAddr::new("127.0.0.1".parse().unwrap(), node.node.address.port())})), SimulatedMessageHandler::create()).await;

        // Spawn a task to keep the node running and listening
        run_node.start(Arc::clone(&run_node.socket)).await;

        let ind;
        if index >= 5 {
            ind = rand::random_range(0..5);
        } else {
            ind = index;
        }
        //8000 <- 8001 <- 8002
        {
            println!("{}: {}", run_node.node.lock().await.address, sockets[ind].clone());
        }

        {
            run_node.join_network(run_node.socket.clone(), &sockets[ind].clone()).await;

            run_node.iterative_find_node(run_node.socket.clone(), rand::random::<u128>(), 2).await;
        }

        {
            let node_actual = run_node.node.lock().await.clone();
            let mut rt = SimulatedRoutingTable::new(node_actual.clone());
            rt.set(&*run_node.routing_table.lock().await.clone());
            SIM.lock().await.create_node(SimulatedNode {
                node: node_actual.clone(),
                routing_table: rt.clone(),
                data_store: run_node.data_store.lock().await.clone(),
                response_queue: run_node.response_queue.lock().await.clone(),
                locked: false,
            }).await;
        }

        run_node.stop(run_node.receive_addr, SocketAddr::new("127.0.0.1".parse().unwrap(), 12000)).await;
        index = index + 1;
    }
}

/// TESTS
#[cfg(test)]
mod sim_tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use kademlia::Kademlia;
    use kademlia_structs::{KMessage, KademliaRoutingTable, Node};
    use crate::{create_network, load_simulated_nodes, save_simulated_nodes, SimulatedMessageHandler, SimulatedRoutingTable, Simulator, SIM};

    async fn create_test_node(id: u128, port: u16) -> Kademlia {
        let mut node = Kademlia::new(id, "127.0.0.1", port,Box::new(SimulatedRoutingTable::new(Node {id, address: SocketAddr::new("127.0.0.1".parse().unwrap(), port)})), SimulatedMessageHandler::create()).await;

        // Spawn a task to keep the node running and listening
        node.start(Arc::clone(&node.socket)).await;

        node
    }

    /*#[tokio::test]
    async fn simulated_node_file_test() {
        let file_path = "nodes.json";

        // Load nodes from JSON
        match load_simulated_nodes(file_path) {
            Ok(mut nodes) => {
                println!("Loaded nodes: {:?}", nodes);

                // Modify the nodes as needed
                if let Some(first_node) = nodes.get_mut(0) {
                    first_node.locked = true;
                }

                // Save the modified nodes back to a new file
                let new_file_path = "updated_nodes.json";
                if let Err(e) = save_simulated_nodes(new_file_path, &nodes) {
                    eprintln!("Error saving nodes: {}", e);
                } else {
                    println!("Saved updated nodes to {}", new_file_path);
                }
            }
            Err(e) => eprintln!("Error loading nodes: {}", e),
        }
    }*/

    #[tokio::test]
    async fn simulated_node_thread_test() {
        let file_path = "../kademlia_nodes_empty.json";

        // Load nodes from JSON
        match load_simulated_nodes(file_path).await {
            Ok(mut nodes) => {
                //println!("Loaded nodes: {:?}", nodes);

                create_network(nodes.clone()).await;

                /*{
                    SIM.lock().await.set(Simulator::new(8000, 10, nodes.clone()).await);
                }

                let node1 = create_test_node(rand::random::<u128>(), 9000).await;

                let _node1_info = node1.node.lock().await.clone();
                let test_node_sock = SocketAddr::new("127.0.0.1".parse().unwrap(), 6000 + (rand::random::<u16>() % 100));

                node1.join_network(Arc::clone(&node1.socket), &test_node_sock).await;

                println!("Joined network");

                // Perform lookup
                let found_nodes = node1.iterative_find_node(Arc::clone(&node1.socket), 164706100918213460259449010270964917190, 2).await;

                println!("Send Find node");

                node1.stop(node1.receive_addr, SocketAddr::new("127.0.0.1".parse().unwrap(), 12000)).await;

                println!("found_nodes: {:?}\nrouting_table: {:?}", found_nodes, node1.routing_table);*/

                let mut updated_nodes = nodes.clone();
                let test_node;
                {
                    let sim = SIM.lock().await;
                    sim.stop().await;
                    updated_nodes = sim.get_all_nodes().await;
                    test_node = sim.sims.lock().await.get(&SocketAddr::new("127.0.0.1".parse().unwrap(), 6075)).cloned();
                }

                // Save the modified nodes back to a new file
                let new_file_path = "../updated_nodes.json";
                if let Err(e) = save_simulated_nodes(new_file_path, &updated_nodes).await {
                    eprintln!("Error saving nodes: {}", e);
                } else {
                    println!("Saved updated nodes to {}", new_file_path);
                }

                /*if let Some(check) = test_node {
                    assert_eq!(found_nodes[0], check.node, "Should find node 98765, and it should be first in the list");
                } else {
                    assert!(false, "Should find node 98765");
                }*/

            }
            Err(e) => {
                eprintln!("Error loading nodes: {}", e);
                assert!(false, "Could not load nodes");
            },
        }
    }

}