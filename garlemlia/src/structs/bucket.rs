use std::collections::VecDeque;
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use crate::structs::constants::{DEFAULT_K, MAX_K};
use crate::structs::node::Node;

#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq)]
pub struct KBucket {
    pub nodes: VecDeque<Node>,
    max_size: usize,
}

impl KBucket {
    pub fn new() -> Self {
        Self {
            nodes: VecDeque::with_capacity(DEFAULT_K),
            max_size: DEFAULT_K,
        }
    }

    pub fn new_with_node(node: Node) -> Self {
        let mut bucket = Self::new();
        bucket.nodes.push_back(node);
        bucket
    }

    pub fn insert(&mut self, node: Node) {
        self.nodes.push_back(node);
    }

    pub fn remove(&mut self, node: &Node) {
        if let Some(pos) = self.nodes.iter().position(|n| n.id == node.id) {
            self.nodes.remove(pos);
        }
    }

    pub fn update_node(&mut self, node: Node) {
        self.remove(&node);
        self.insert(node);
    }

    pub fn contains(&self, node_id: U256) -> bool {
        self.nodes.iter().any(|n| n.id == node_id)
    }

    pub fn is_full(&self) -> bool {
        self.nodes.len() >= self.max_size
    }

    pub fn try_increase_capacity(&mut self) {
        if self.max_size < MAX_K {
            self.max_size += 5;
        }
    }
}