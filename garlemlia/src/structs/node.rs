use std::cmp::Ordering;
use std::net::SocketAddr;
use primitive_types::U256;
use serde::{Deserialize, Serialize};

/// Node struct
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Node {
    pub id: U256,
    pub address: SocketAddr,
}

impl Node {
    pub fn update(&mut self, other: &Node) {
        self.id = other.id;
        self.address = other.address;
    }
}

/// Helper struct for a min-heap (using reverse ordering)
#[derive(Eq)]
pub struct HeapNode {
    pub distance: U256,
    pub node: Node,
}

impl Ord for HeapNode {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering to simulate a min-heap.
        other.distance.cmp(&self.distance)
    }
}

impl PartialOrd for HeapNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for HeapNode {
    fn eq(&self, other: &Self) -> bool {
        self.distance == other.distance
    }
}