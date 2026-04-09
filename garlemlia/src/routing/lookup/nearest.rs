use crate::net::node::Node;
use primitive_types::U256;
use std::collections::HashSet;

pub struct Nearest;
impl Nearest {
    pub fn sort_by_distance(nodes: &mut Vec<Node>, target: U256) {
        nodes.sort_by_key(|n| n.id ^ target);
    }

    pub fn dedup_and_trim(nodes: &mut Vec<Node>, target: U256, self_node: &Node, limit: usize) {
        nodes.retain(|n| n != self_node);
        Self::sort_by_distance(nodes, target);

        let mut seen = HashSet::new();
        nodes.retain(|n| seen.insert(n.id));

        nodes.truncate(limit);
    }
}
