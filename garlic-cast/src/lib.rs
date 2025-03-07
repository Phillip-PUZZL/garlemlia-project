use chrono::{DateTime, Utc};
use garlemlia_structs::{Clove, CloveData, CloveNode, GMessage, GarlicMessage, Node};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CloveCache {
    cloves: HashMap<u128, CloveData>,
    next_hop: HashMap<CloveNode, Option<CloveNode>>,
    alt_nodes: HashMap<CloveNode, CloveNode>,
    associations: HashMap<u128, Vec<CloveNode>>,
    #[serde(with = "chrono::serde::ts_seconds")]
    seen_last: HashMap<u128, DateTime<Utc>>,
    my_alt_nodes: HashMap<u128, CloveNode>
}

impl CloveCache {
    pub fn new() -> CloveCache {
        CloveCache {
            cloves: HashMap::new(),
            next_hop: HashMap::new(),
            alt_nodes: HashMap::new(),
            associations: HashMap::new(),
            seen_last: HashMap::new(),
            my_alt_nodes: HashMap::new()
        }
    }

    pub fn remove_sequence(&mut self, sequence_number: u128) {
        let associated = self.associations.remove(&sequence_number);

        match associated {
            Some(associated_nodes) => {
                self.cloves.remove(&sequence_number);
                self.seen_last.remove(&sequence_number);
                self.my_alt_nodes.remove(&sequence_number);

                for node in associated_nodes {
                    self.next_hop.remove(&node);
                    self.alt_nodes.remove(&node);
                }
            }
            None => {
                // If the clove exists in the cache, there should be nodes associated with it
                // So this should never happen in theory.
                println!("This should not happen: CloveCache::remove_sequence():1");
            }
        }
    }

    pub fn insert_clove(&mut self, clove: Clove, from: Node) {
        self.cloves.insert(clove.sequence_number, CloveData { clove, from });
    }

    pub fn remove_clove(&mut self, clove: Clove) {
        self.cloves.remove(&clove.sequence_number);
    }

    pub fn insert_association(&mut self, sequence_number: u128, node: CloveNode) {
        if self.associations.contains_key(&sequence_number) {
            self.associations.get_mut(&sequence_number).unwrap().push(node);
        } else {
            self.associations.insert(sequence_number, vec![node]);
        }
    }

    pub fn insert_updated_association(&mut self, sequence_number: u128, new_sequence_number: u128) {
        if self.associations.contains_key(&sequence_number) {
            let associations = self.associations.remove(&sequence_number).unwrap();
            self.associations.insert(new_sequence_number, associations.clone());
        } else {
            self.associations.insert(sequence_number, vec![]);
        }
    }

    pub fn remove_association(&mut self, sequence_number: u128) {
        self.associations.remove(&sequence_number);
    }

    pub fn insert_next_hop(&mut self, node: CloveNode, next_hop: CloveNode) {
        self.next_hop.insert(node.clone(), Some(next_hop.clone()));

        self.insert_association(node.sequence_number, next_hop);
    }

    pub fn remove_next_hop(&mut self, node: CloveNode) {
        self.next_hop.remove(&node);
    }

    pub fn insert_alt_node(&mut self, node: CloveNode, alt_node: CloveNode) {
        self.alt_nodes.insert(node.clone(), alt_node.clone());

        self.insert_association(node.sequence_number, alt_node);
    }

    pub fn remove_alt_node(&mut self, node: CloveNode) {
        self.alt_nodes.remove(&node);
    }

    pub fn insert_my_alt_node(&mut self, sequence_number: u128, my_alt_node: CloveNode) {
        self.my_alt_nodes.insert(sequence_number, my_alt_node.clone());

        self.insert_association(sequence_number, my_alt_node);
    }

    pub fn remove_my_alt_node(&mut self, sequence_number: u128) {
        self.my_alt_nodes.remove(&sequence_number);
    }
    
    pub fn get_forward_node(&self, clove_node: CloveNode) -> Result<Option<CloveNode>, None> {
        let info = self.next_hop.get(&clove_node);

        match info {
            Some(info) => {
                Ok(info.clone())
            }
            _ => {
                Err(())
            }
        }
    }

    pub fn update_sequence_number(&mut self, new_sequence_number: u128, clove_node: CloveNode) {
        let node = clove_node.node.clone();
        let new_clove_node = CloveNode { sequence_number: new_sequence_number, node };

        let next = self.get_forward_node(clove_node.clone());

        match next {
            Ok(next_hop) => {
                match next_hop {
                    Some(next_node) => {
                        let new_next_hop_clove_node = CloveNode { sequence_number: new_sequence_number, node: next_node.clone().node };
                        self.add_next_hop(new_clove_node.clone(), new_next_hop_clove_node.clone());
                        self.add_next_hop(new_next_hop_clove_node.clone(), new_clove_node.clone());

                        let mut has_alt = self.alt_nodes.contains_key(&clove_node);

                        if has_alt {
                            // In theory this should never happen since alt nodes are assigned
                            // after the path has already been solidified
                            println!("This should not happen: CloveCache::update_sequence_number():1");
                            let alt = self.alt_nodes.get(&clove_node).unwrap().clone();
                            self.add_alt_node(new_clove_node, alt);
                        }

                        has_alt = self.alt_nodes.contains_key(&next_node);

                        if has_alt {
                            // In theory this should never happen since alt nodes are assigned
                            // after the path has already been solidified
                            println!("This should not happen: CloveCache::update_sequence_number():2");
                            let alt = self.alt_nodes.get(&next_node).unwrap().clone();
                            self.add_alt_node(new_next_hop_clove_node, alt);
                        }

                        self.insert_updated_association(clove_node.sequence_number, new_sequence_number);
                    }
                    None => {
                        // This is the end of the line, either at the initiator or proxy
                        self.next_hop.insert(new_clove_node.clone(), None);

                        let has_alt = self.alt_nodes.contains_key(&clove_node);

                        if has_alt {
                            // In theory this should never happen since alt nodes are assigned
                            // after the path has already been solidified
                            println!("This should not happen: CloveCache::update_sequence_number():3");
                            let alt = self.alt_nodes.get(&clove_node).unwrap().clone();
                            self.add_alt_node(new_clove_node, alt);
                        }

                        self.insert_updated_association(clove_node.sequence_number, new_sequence_number);
                    }
                }
            }
            Err(_) => {
                // This shouldn't happen and is a failure
                // This method should only be called upon a proxy agree, meaning that this
                // Should exist
                println!("This should not happen: CloveCache::update_sequence_number():4");
            }
        }
    }

    pub fn replace_with_alt_node(&mut self, sequence_number: u128, node: Node) -> Option<CloveNode> {
        let old_clove_node = CloveNode { sequence_number, node };
        let new_clove_node = self.alt_nodes.remove(&old_clove_node);

        match new_clove_node {
            Some(new_clove_node) => {
                let forward_clove_node = self.next_hop.remove(&old_clove_node).unwrap();

                self.next_hop.insert(new_clove_node.clone(), forward_clove_node.clone());

                match forward_clove_node {
                    Some(forward_clove_node) => {
                        self.next_hop.insert(forward_clove_node, Some(new_clove_node.clone()));
                    }
                    _ => {}
                }
                Some(new_clove_node)
            }
            _ => {
                None
            }
        }
    }

    pub fn seen(&mut self, sequence_number: u128) {
        self.seen_last.insert(sequence_number, Utc::now());
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proxy {
    sequence_number: u128,
    neighbor_1: Node,
    neighbor_2: Node,
    neighbor_1_hops: u16,
    neighbor_2_hops: u16,
    public_key: String,
    #[serde(with = "chrono::serde::ts_seconds")]
    used_last: DateTime<Utc>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GarlicCast {
    socket: Arc<UdpSocket>,
    local_node: Node,
    message_handler: Arc<Box<dyn GMessage>>,
    known_nodes: Arc<Mutex<Vec<Node>>>,
    proxies: Arc<Mutex<VecDeque<Proxy>>>,
    cache: Arc<Mutex<CloveCache>>,
}

impl GarlicCast {
    pub fn new(socket: Arc<UdpSocket>, local_node: Node, message_handler: Arc<Box<dyn GMessage>>, known_nodes: Vec<Node>) -> GarlicCast {
        GarlicCast {
            socket,
            local_node,
            message_handler,
            known_nodes: Arc::new(Mutex::new(known_nodes)),
            proxies: Arc::new(Mutex::new(VecDeque::new())),
            cache: Arc::new(Mutex::new(CloveCache::new())),
        }
    }

    pub async fn update_known(&self, nodes: Vec<Node>) {
        self.known_nodes.lock().await.extend(nodes);
    }

    async fn add_proxy(&self, node: Node) {
        // todo()
    }

    async fn remove_proxy(&self, node: Node) {
        // todo()
    }

    async fn is_proxy(&self, node: Node) -> bool {
        // todo()
        false
    }

    async fn in_cache(&self, sequence_number: u128) -> bool {
        let cache = self.cache.lock().await;
        let cache_info = cache.cloves.get(&sequence_number);

        if let Some(_) = cache_info {
            return true;
        }

        false
    }

    pub async fn discover_proxies(&self, nodes: Vec<Node>, count: u8) {
        let mut known_nodes;
        {
            let mut known = self.known_nodes.lock().await;
            known.extend(nodes);
            known_nodes = known.clone();
        }

        let mut try_nodes = vec![];
        for _ in 0..count {
            try_nodes.push(known_nodes.remove(rand::rng().random_range(0..known_nodes.len())));
        }

        // todo()
    }

    pub async fn send(&self, msg: Clove, count: u8) {
        // todo()
    }

    async fn forward(&self, last_node: Node, next_node: CloveNode, msg: Clove) {
        let mut new_clove = msg.clone();

        if msg.sequence_number != next_node.sequence_number {
            new_clove.sequence_number = next_node.sequence_number;
        }

        let new_msg = GarlicMessage::Forward {
            sequence_number: next_node.sequence_number,
            clove: new_clove.clone()
        };

        {
            if let Err(e) = self.message_handler.send(&self.socket, self.local_node.clone(), &last_node.address, &GarlicMessage::build_send(self.local_node.clone(), new_msg)).await {
                eprintln!("Failed to send IsAlive to {}: {:?}", last_node.address, e);
            }
        }

        let response;
        {
            response = self.message_handler.recv(200, &last_node.address).await;
        }

        match response {
            Ok(_) => {
                return;
            }
            _ => {
                let mut try_update: Option<CloveNode> = None;
                {
                    let mut cache = self.cache.lock().await;
                    try_update = cache.replace_with_alt_node(next_node.sequence_number, next_node.node).await;
                }

                match try_update {
                    Some(updated) => {
                        new_clove.sequence_number = updated.sequence_number;

                        let new_alt_msg = GarlicMessage::Forward {
                            sequence_number: updated.sequence_number,
                            clove: new_clove
                        };

                        {
                            if let Err(e) = self.message_handler.send(&self.socket, self.local_node.clone(), &last_node.address, &GarlicMessage::build_send(self.local_node.clone(), new_alt_msg)).await {
                                eprintln!("Failed to send IsAlive to {}: {:?}", last_node.address, e);
                            }
                        }

                        let response2;
                        {
                            response2 = self.message_handler.recv(200, &last_node.address).await;
                        }

                        match response2 {
                            Ok(_) => {
                                return;
                            }
                            _ => {
                                // Big failure
                                // TODO: Manage removing old sequence number and CloveNode info
                                self.cache.lock().await.remove_sequence(updated.sequence_number);
                                println!("This should not happen: GarlicCast::forward():1");
                            }
                        }
                    }
                    None => {
                        // Big failure
                        // TODO: Manage removing old sequence number and CloveNode info
                        self.cache.lock().await.remove_sequence(next_node.sequence_number);
                        println!("This should not happen: GarlicCast::forward():2");
                    }
                }
            }
        }
    }

    pub async fn recv(&self, node: Node, garlic_msg: GarlicMessage) {
        match garlic_msg {
            GarlicMessage::Forward { sequence_number, clove } => {

                {
                    if let Err(e) = self.message_handler.send(&self.socket, self.local_node.clone(), &node.address, &GarlicMessage::build_send_is_alive(self.local_node.clone())).await {
                        eprintln!("Failed to send IsAlive to {}: {:?}", node.address, e);
                    }
                }

                let msg = clove.clone();

                let next;
                {
                    let mut cache = self.cache.lock().await;
                    next = cache.get_forward_node(CloveNode { sequence_number, node: node.clone() }).await;
                    cache.seen(sequence_number);
                }

                match next {
                    Ok(info) => {
                        match info {
                            Some(next_node) => {
                                self.forward(node, next_node, msg).await;
                            }
                            None => {
                                // TODO: PROCESS DATA, NO FORWARD NODE SO END OF LINE
                            }
                        }
                    }
                    Err(_) => {
                        // TODO: Need to do something here to check if this is a new set of messages
                        if !self.in_cache(sequence_number).await {

                        } else {
                            // TODO: This might mean that this node can be a proxy, need to do more research
                        }
                    }
                }
            }
            GarlicMessage::IsAlive { sender } => {

            }
            GarlicMessage::ProxyAgree { sequence_number, updated_sequence_number, hops, clove } => {

            }
            GarlicMessage::RequestAlt { .. } => {}
            GarlicMessage::RefreshAlt { .. } => {}
            GarlicMessage::UpdateAlt { .. } => {}
            _ => {}
        }
    }
}