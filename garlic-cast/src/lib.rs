use chrono::{DateTime, Utc};
use kademlia_structs::{KMessage, KademliaMessage, MessageHandler, Node};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Clove {
    sequence_number: u128,
    msg_fragment: String,
    key_fragment: String,
    sent: DateTime<Utc>
}

#[derive(Clone, Debug, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub struct CloveNode {
    // The sequence number used when sending to this node
    // Most of the time it will be the chain sequence number, but if it is an alt node
    // then it will be the randomly generated sequence number
    sequence_number: u128,
    node: Node
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CloveCache {
    cloves: HashMap<u128, Vec<Clove>>,
    next_hop: HashMap<CloveNode, Option<CloveNode>>,
    alt_nodes: HashMap<CloveNode, CloveNode>,
    seen_last: HashMap<u128, DateTime<Utc>>,
    this_node_alt_nodes: HashMap<u128, CloveNode>
}

impl CloveCache {
    pub fn new() -> CloveCache {
        CloveCache {
            cloves: HashMap::new(),
            next_hop: HashMap::new(),
            alt_nodes: HashMap::new(),
            seen_last: HashMap::new(),
            this_node_alt_nodes: HashMap::new()
        }
    }

    pub async fn insert_clove(&mut self, clove: Clove) {
        let clove_info = self.cloves.contains_key(&clove.sequence_number);

        if !clove_info {
            self.cloves.insert(clove.sequence_number, Vec::new());
        }

        self.cloves.get_mut(&clove.sequence_number).unwrap().push(clove);
    }

    pub async fn add_alt_node(&mut self, node: CloveNode, alt_node: CloveNode) {
        self.alt_nodes.insert(node, alt_node);
    }
    
    pub async fn get_forward_node(&self, sequence_number: u128, node: Node) -> Result<Option<CloveNode>, None> {
        let info = self.next_hop.get(&CloveNode { sequence_number, node });

        match info {
            Some(info) => {
                Ok(info.clone())
            }
            _ => {
                Err(())
            }
        }
    }

    pub async fn replace_with_alt_node(&mut self, sequence_number: u128, node: Node) -> Option<CloveNode> {
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proxy {
    sequence_number: u128,
    hops: u16,
    neighbor_1: Node,
    neighbor_2: Node,
    public_key: String,
    used_last: DateTime<Utc>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GarlicCast {
    socket: Arc<UdpSocket>,
    msg_handler: Arc<Box<dyn KMessage>>,
    known_nodes: Arc<Mutex<Vec<Node>>>,
    proxies: Arc<Mutex<VecDeque<Proxy>>>,
    cache: Arc<Mutex<CloveCache>>,
}

impl GarlicCast {
    pub fn new(socket: Arc<UdpSocket>, msg_handler: Arc<Box<dyn KMessage>>, known_nodes: Vec<Node>) -> GarlicCast {
        GarlicCast {
            socket,
            msg_handler,
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

    pub async fn in_cache(&self, sequence_number: u128) -> bool {
        let cache = self.cache.lock().await;
        let cache_info = cache.cloves.get(&sequence_number);

        if let Some(_) = cache_info {
            return true;
        }

        false
    }

    pub async fn discover_proxies(&self, nodes: Vec<Node>) {
        // todo()
    }

    pub async fn send(&self, msg: Clove, count: u8) {
        // todo()
    }

    async fn forward(&self, next_node: CloveNode, msg: Clove) {
        let mut new_clove = msg.clone();

        if msg.sequence_number != next_node.sequence_number {
            new_clove.sequence_number = next_node.sequence_number;
        }

        let new_msg = GarlicMessage::Forward {
            sequence_number: next_node.sequence_number,
            clove: new_clove.clone()
        };

        //*SEND FORWARD VIA MESSAGE HANDLER*
        let response = None;//*ATTEMPT TO RECEIVE ISALIVE*;

        match response {
            Some(msg) => {
                return;
            }
            _ => {
                let try_update;
                {
                    let mut cache = self.cache.lock().await;
                    try_update = cache.replace_with_alt_node(next_node.sequence_number, next_node.node).await;
                }

                match try_update {
                    Some(updated) => {
                        new_clove.sequence_number = updated.sequence_number;

                        let new_msg = GarlicMessage::Forward {
                            sequence_number: next_node.sequence_number,
                            clove: new_clove
                        };

                        //*SEND FORWARD VIA MESSAGE HANDLER*
                        let response2 = None;//*ATTEMPT TO RECEIVE ISALIVE*;

                        match response2 {
                            Some(msg) => {
                                return;
                            }
                            _ => {
                                // Big failure
                                // TODO: Manage removing old sequence number and CloveNode info
                                // TODO: CATASTROPHIC FAILURE, NO COMING BACK
                            }
                        }
                    }
                    None => {
                        // Big failure
                        // TODO: Manage removing old sequence number and CloveNode info
                        // TODO: CATASTROPHIC FAILURE, NO COMING BACK
                    }
                }
            }
        }
    }

    pub async fn recv(&self, node: Node, garlic_msg: GarlicMessage) {
        match garlic_msg {
            GarlicMessage::Forward { sequence_number, clove } => {
                //*SEND VIA MESSAGE HANDLER ISALIVE*
                let msg = clove.clone();

                let next;
                {
                    let cache = self.cache.lock().await;
                    next = cache.get_forward_node(sequence_number, node.clone()).await;
                }

                match next {
                    Ok(info) => {
                        match info {
                            Some(next_node) => {
                                self.forward(next_node, msg).await;
                            }
                            None => {
                                //*PROCESS RESULT, NO FORWARD NODE*
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
            GarlicMessage::IsAlive { .. } => {}
            GarlicMessage::RequestAlt { .. } => {}
            GarlicMessage::RefreshAlt { .. } => {}
            GarlicMessage::UpdateAlt { .. } => {}
            _ => {}
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GarlicMessage {
    Forward {
        sequence_number: u128,
        clove: Clove
    },
    IsAlive { },
    SearchOverlay { },
    SearchKademlia { },
    ResponseDirect { },
    ResponseWithValidator { },
    RequestAlt { },
    RefreshAlt { },
    UpdateAlt { }
}

impl GarlicMessage {
    pub fn sequence_number(&self) -> u128 {
        match self {
            GarlicMessage::Forward { sequence_number, .. } => {sequence_number.clone()}
            GarlicMessage::IsAlive { .. } => {0}
            GarlicMessage::SearchOverlay { .. } => {0}
            GarlicMessage::SearchKademlia { .. } => {0}
            GarlicMessage::ResponseDirect { .. } => {0}
            GarlicMessage::ResponseWithValidator { .. } => {0}
            GarlicMessage::RequestAlt { .. } => {0}
            GarlicMessage::RefreshAlt { .. } => {0}
            GarlicMessage::UpdateAlt { .. } => {0}
        }
    }

    pub fn clove(&self) -> Option<Clove> {
        match self {
            GarlicMessage::Forward { clove, .. } => {Some(clove.clone().clone())}
            GarlicMessage::IsAlive { .. } => {None}
            GarlicMessage::SearchOverlay { .. } => {None}
            GarlicMessage::SearchKademlia { .. } => {None}
            GarlicMessage::ResponseDirect { .. } => {None}
            GarlicMessage::ResponseWithValidator { .. } => {None}
            GarlicMessage::RequestAlt { .. } => {None}
            GarlicMessage::RefreshAlt { .. } => {None}
            GarlicMessage::UpdateAlt { .. } => {None}
        }
    }
}
