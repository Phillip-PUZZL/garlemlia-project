use crate::core::u256_random;
use crate::data::garlemlia_protocol::GarlemliaMessage;
use crate::net::message_handler::GMessage;
use crate::net::node::Node;
use crate::routing::table::bucket::KBucket;
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// Routing table struct whose information is serializable and can be stored in a file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableRoutingTable {
    pub local_node: Node,
    pub buckets: HashMap<u8, KBucket>,
}

impl SerializableRoutingTable {
    pub async fn from(routing_table: RoutingTable) -> SerializableRoutingTable {
        SerializableRoutingTable {
            local_node: routing_table.local_node,
            buckets: routing_table.buckets.lock().await.clone(),
        }
    }

    pub fn to_routing_table(self) -> RoutingTable {
        RoutingTable {
            local_node: self.local_node,
            buckets: Arc::new(Mutex::new(self.buckets)),
        }
    }
}

/// Routing table object
// TODO: Implement last_seen information for nodes in routing table
#[derive(Debug, Clone)]
pub struct RoutingTable {
    local_node: Node,
    buckets: Arc<Mutex<HashMap<u8, KBucket>>>,
}

impl RoutingTable {
    pub fn new(local_node: Node) -> Self {
        Self {
            local_node,
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Set the routing table
    pub async fn update_from(&mut self, other: RoutingTable) {
        self.local_node = other.local_node().clone();
        let mut self_buckets = self.buckets.lock().await;
        self_buckets.clear();

        let other_buckets = other.buckets.lock().await;
        for bucket in other_buckets.iter() {
            self_buckets.insert(*bucket.0, bucket.1.clone());
        }
    }

    fn local_node(&self) -> &Node {
        &self.local_node
    }

    pub async fn buckets(&self) -> HashMap<u8, KBucket> {
        self.buckets.lock().await.clone()
    }

    /// Get bucket index for a specified node ID
    pub fn bucket_index(&self, node_id: U256) -> u8 {
        let xor_distance = self.local_node.id ^ node_id;

        if xor_distance == U256::from(0) {
            return 0;
        }

        (255 - xor_distance.leading_zeros()) as u8
    }

    /// Get the flat vector of all nodes in my routing table
    pub async fn flat_nodes(&self) -> Vec<Node> {
        self.buckets
            .lock()
            .await
            .values()
            .flat_map(|bucket| bucket.nodes.iter().cloned())
            .collect()
    }

    /// Add a node into the routing table at its specified bucket index
    pub async fn insert_direct(&mut self, node: Node) {
        let index = self.bucket_index(node.id);
        self.buckets
            .lock()
            .await
            .entry(index)
            .or_insert_with(KBucket::new)
            .insert(node);
    }

    /// Check if KBucket is full, and if it is not, then add a node
    pub async fn check_and_update_bucket(&mut self, node: Node, index: u8) -> bool {
        let mut self_buckets = self.buckets.lock().await;
        if let Some(bucket) = self_buckets.get_mut(&index) {
            if bucket.contains(node.clone().id) {
                bucket.update_node(node);
                return true;
            } else {
                if !bucket.is_full() {
                    bucket.insert(node);
                    return true;
                }
            }
            false
        } else {
            self_buckets.insert(index, KBucket::new());
            self_buckets.get_mut(&index).unwrap().insert(node);
            true
        }
    }

    /// Adding a node from the main event loop, this involves pinging the LRU node
    pub async fn add_node_from_responder(
        &mut self,
        message_handler: Arc<Box<dyn GMessage>>,
        node: Node,
        socket: Arc<UdpSocket>,
    ) {
        if self.local_node.id == node.id {
            return;
        }

        let index = self.bucket_index(node.id);
        if self.check_and_update_bucket(node.clone(), index).await {
            return;
        }

        let self_buckets = Arc::clone(&self.buckets);
        let mh = Arc::clone(&message_handler);
        let local_node = self.local_node.clone();
        let node_clone = node.clone();
        let socket_clone = Arc::clone(&socket);
        // Spawn a new thread for this since we want to continue on working on other stuff after
        // TODO: have a thread pool for this maybe?
        tokio::spawn(async move {
            let bucket_clone;
            {
                bucket_clone = self_buckets.lock().await.get_mut(&index).unwrap().clone();
            }

            if let Some(lru_node) = bucket_clone.nodes.front().cloned() {
                let ping_msg = GarlemliaMessage::Ping {
                    sender: local_node.clone(),
                };

                {
                    // Send the message to LRU node
                    // If sending fails, log the error and continue.
                    if let Err(e) = mh
                        .send(
                            &socket_clone,
                            local_node.clone(),
                            &lru_node.address,
                            &ping_msg,
                        )
                        .await
                    {
                        eprintln!("Failed to send ping to {}: {:?}", lru_node.address, e);
                        let mut locked_buckets = self_buckets.lock().await;
                        let bucket = locked_buckets.get_mut(&index).unwrap();
                        bucket.remove(&lru_node);
                        bucket.insert(node_clone);
                        return;
                    }
                }

                {
                    // Receive response back from LRU node, if no response then remove
                    // LRU node and add the specified node
                    match mh.recv(300, &lru_node.address).await {
                        Ok(GarlemliaMessage::Pong { sender, .. }) if sender.id == lru_node.id => {
                            let mut locked_buckets = self_buckets.lock().await;
                            let bucket = locked_buckets.get_mut(&index).unwrap();
                            bucket.update_node(lru_node);
                        }
                        Ok(_) | Err(_) => {
                            let mut locked_buckets = self_buckets.lock().await;
                            let bucket = locked_buckets.get_mut(&index).unwrap();
                            bucket.remove(&lru_node);
                            bucket.insert(node_clone);
                        }
                    }
                }
            }
        });
    }

    /// Add node to routing table
    pub async fn add_node(
        &mut self,
        message_handler: &Arc<Box<dyn GMessage>>,
        node: Node,
        socket: &UdpSocket,
    ) {
        if self.local_node.id == node.id {
            return;
        }

        let index = self.bucket_index(node.id);
        if self.check_and_update_bucket(node.clone(), index).await {
            return;
        }

        let mut locked_buckets = self.buckets.lock().await;
        let bucket = locked_buckets.get_mut(&index).unwrap();
        // Same process as adding from responder, but no new thread needed since this is already
        // running in its own thread
        if let Some(lru_node) = bucket.nodes.front().cloned() {
            let ping_msg = GarlemliaMessage::Ping {
                sender: self.local_node.clone(),
            };

            if let Err(e) = message_handler
                .send(
                    socket,
                    self.local_node.clone(),
                    &lru_node.address,
                    &ping_msg,
                )
                .await
            {
                eprintln!("Failed to send ping to {}: {:?}", lru_node.address, e);
                bucket.remove(&lru_node);
                bucket.insert(node);
                return;
            }

            match message_handler.recv(300, &lru_node.address).await {
                Ok(GarlemliaMessage::Pong { sender, .. }) if sender.id == lru_node.id => {
                    bucket.update_node(lru_node);
                }
                Ok(_) | Err(_) => {
                    bucket.remove(&lru_node);
                    bucket.insert(node);
                }
            }
        }
    }

    /// Find the closest known node to a specified ID
    pub async fn find_closest_nodes(&self, target_id: U256, count: usize) -> Vec<Node> {
        // Always include self
        let mut candidates = vec![self.local_node.clone()];

        // Lock the buckets and extract a sorted list of bucket indices.
        let buckets = self.buckets.lock().await;
        let mut bucket_indices: Vec<u8> = buckets.keys().cloned().collect();
        bucket_indices.sort();

        // Determine the bucket index for the target.
        let target_bucket = self.bucket_index(target_id);

        // Find the position in the sorted bucket list.
        // If no bucket has an index >= target_bucket, start with the last one.
        let pos = bucket_indices
            .iter()
            .position(|&i| i >= target_bucket)
            .unwrap_or(bucket_indices.len().saturating_sub(1));

        if bucket_indices.len() < 1 {
            return candidates;
        }

        // Add nodes from the bucket that contains the target (if it exists)
        if let Some(bucket) = buckets.get(&bucket_indices[pos]) {
            candidates.extend(bucket.nodes.iter().cloned());
        }

        // Expand outwards from the target bucket.
        let mut left: isize = pos as isize - 1;
        let mut right: isize = pos as isize + 1;

        while candidates.len() < count && (left >= 0 || (right as usize) < bucket_indices.len()) {
            if right < bucket_indices.len() as isize {
                if let Some(bucket) = buckets.get(&bucket_indices[right as usize]) {
                    candidates.extend(bucket.nodes.iter().cloned());
                }
                right += 1;
            }
            if candidates.len() >= count {
                break;
            }
            if left >= 0 {
                if let Some(bucket) = buckets.get(&bucket_indices[left as usize]) {
                    candidates.extend(bucket.nodes.iter().cloned());
                }
                left -= 1;
            }
        }

        // Sort the gathered nodes by XOR distance to target_id.
        candidates.sort_by_key(|node| node.id ^ target_id);
        candidates.truncate(count);
        candidates
    }

    /// Convert routing table to string for displaying debug info
    pub async fn to_string(&self) -> String {
        let mut last: String = "ROUTING TABLE {\n".to_string();

        let mut bucket_strings = HashMap::new();
        let mut bucket_ids = vec![];
        for bucket in self.buckets.lock().await.iter() {
            let mut temp: String = "".to_string();
            temp.push_str("\t{\n");
            temp.push_str(
                format!(
                    "\t\tID: {},\n\t\tCOUNT: {},\n",
                    bucket.0,
                    bucket.1.nodes.len()
                )
                .as_str(),
            );
            temp.push_str("\t\t{\n");
            temp.push_str("\t\t\t");

            for node in bucket.1.nodes.clone() {
                temp.push_str("{ ");
                temp.push_str(format!("id: {}, address: {}", node.id, node.address).as_str());
                temp.push_str(" }, ");
            }

            temp.push_str("\n\t\t},\n");
            temp.push_str("\t},\n");

            bucket_strings.insert(bucket.0.clone(), temp.clone());
            bucket_ids.push(bucket.0.clone());
        }
        bucket_ids.sort();

        for bucket_id in bucket_ids {
            last.push_str(bucket_strings.get(&bucket_id).unwrap().as_str());
        }

        last.push_str("}");

        last
    }

    /// Generate random ID for each bucket - used when refreshing buckets
    pub fn random_id_for_bucket(self_id: U256, bucket_index: u8) -> U256 {
        // The bit we want to differ from (counting from the left,
        // where 0 = top bit, 255 = bottom bit):
        let bit_pos = 255 - bucket_index;

        // 1. Flip that bit from self_id.
        //    We'll construct a mask that has only that bit set:
        let flip_mask = U256::from(1) << bit_pos;
        let mut candidate = self_id ^ flip_mask;

        // 2. Now randomize all the bits below `bit_pos`.
        //    That means the `bit_pos` least significant bits can be anything.
        //    We can generate a random 256-bit number but then zero out
        //    all bits except the lower `bit_pos`.
        //
        //    If bit_pos is 0, that means we only flipped the top bit
        //    and there are no "lower bits" to randomize, so handle that case:
        if bit_pos > 0 {
            // e.g., for bit_pos=5, we want to keep only bits [0..4].
            let mask_below = (U256::from(1) << bit_pos) - 1; // e.g. (1 << 5) - 1 = 0b11111

            // A random U256 from the standard RNG:
            let random_lower: U256 = u256_random();

            // Keep only the lower bit_pos bits:
            let random_bits = random_lower & mask_below;

            // Combine these random bits into the candidate:
            // First, zero out the bits below bit_pos (they might already be zero, but let's be explicit)
            candidate &= !mask_below; // not strictly needed since we already matched the above bit
                                      // Then OR in the random bits
            candidate |= random_bits;
        }

        candidate
    }
}
