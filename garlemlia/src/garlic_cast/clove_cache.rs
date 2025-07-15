use std::collections::{HashMap, HashSet};
use chrono::{DateTime, Utc};
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use crate::structs::garlic_message::{Clove, CloveData, CloveNode};
use crate::structs::node::Node;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableCloveCache {
    cloves: HashMap<U256, CloveData>,
    next_hop_key: HashMap<u32, CloveNode>,
    next_hop_val: HashMap<u32, Option<CloveNode>>,
    alt_nodes_key: HashMap<u32, CloveNode>,
    alt_nodes_val: HashMap<u32, CloveNode>,
    alt_to_sequence_key: HashMap<u32, CloveNode>,
    alt_to_sequence_val: HashMap<u32, U256>,
    associations: HashMap<U256, Vec<CloveNode>>,
    seen_last: HashMap<U256, DateTime<Utc>>,
    my_alt_nodes: HashMap<U256, CloveNode>,
    am_alt_for: HashSet<U256>
}

impl SerializableCloveCache {
    pub fn from(cache: CloveCache) -> SerializableCloveCache {
        let mut next_hop_key = HashMap::new();
        let mut next_hop_val = HashMap::new();
        let mut alt_nodes_key = HashMap::new();
        let mut alt_nodes_val = HashMap::new();
        let mut alt_to_sequence_key = HashMap::new();
        let mut alt_to_sequence_val = HashMap::new();

        let mut index = 0;
        for info in cache.next_hop.iter() {
            next_hop_key.insert(index, info.0.clone());
            next_hop_val.insert(index, info.1.clone());

            index += 1;
        }

        index = 0;
        for info in cache.alt_nodes.iter() {
            alt_nodes_key.insert(index, info.0.clone());
            alt_nodes_val.insert(index, info.1.clone());

            index += 1;
        }

        index = 0;
        for info in cache.alt_to_sequence.iter() {
            alt_to_sequence_key.insert(index, info.0.clone());
            alt_to_sequence_val.insert(index, info.1.clone());

            index += 1;
        }

        SerializableCloveCache {
            cloves: HashMap::new(),
            next_hop_key,
            next_hop_val,
            alt_nodes_key,
            alt_nodes_val,
            alt_to_sequence_key,
            alt_to_sequence_val,
            associations: cache.associations,
            seen_last: cache.seen_last,
            my_alt_nodes: cache.my_alt_nodes,
            am_alt_for: cache.am_alt_for
        }
    }

    pub fn to_clove_cache(self) -> CloveCache {
        let mut next_hop = HashMap::new();
        let mut alt_nodes = HashMap::new();
        let mut alt_to_sequence = HashMap::new();

        for entry in self.next_hop_key.iter() {
            let val = self.next_hop_val.get(entry.0).unwrap().clone();
            next_hop.insert(entry.1.clone(), val);
        }

        for entry in self.alt_nodes_key.iter() {
            let val = self.alt_nodes_val.get(entry.0).unwrap().clone();
            alt_nodes.insert(entry.1.clone(), val);
        }

        for entry in self.alt_to_sequence_key.iter() {
            let val = self.alt_to_sequence_val.get(entry.0).unwrap().clone();
            alt_to_sequence.insert(entry.1.clone(), val);
        }

        CloveCache {
            cloves: self.cloves,
            next_hop,
            alt_nodes,
            alt_to_sequence,
            associations: self.associations,
            seen_last: self.seen_last,
            my_alt_nodes: self.my_alt_nodes,
            am_alt_for: self.am_alt_for,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CloveCache {
    pub(crate) cloves: HashMap<U256, CloveData>,
    next_hop: HashMap<CloveNode, Option<CloveNode>>,
    alt_nodes: HashMap<CloveNode, CloveNode>,
    pub(crate) alt_to_sequence: HashMap<CloveNode, U256>,
    associations: HashMap<U256, Vec<CloveNode>>,
    seen_last: HashMap<U256, DateTime<Utc>>,
    pub(crate) my_alt_nodes: HashMap<U256, CloveNode>,
    pub(crate) am_alt_for: HashSet<U256>
}

impl CloveCache {
    pub fn new() -> CloveCache {
        CloveCache {
            cloves: HashMap::new(),
            next_hop: HashMap::new(),
            alt_nodes: HashMap::new(),
            alt_to_sequence: HashMap::new(),
            associations: HashMap::new(),
            seen_last: HashMap::new(),
            my_alt_nodes: HashMap::new(),
            am_alt_for: HashSet::new(),
        }
    }

    pub fn remove_sequence(&mut self, sequence_number: U256) {
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

    pub fn remove_clove(&mut self, sequence_number: U256) {
        self.cloves.remove(&sequence_number);
    }

    pub fn insert_association(&mut self, sequence_number: U256, node: CloveNode) {
        if self.associations.contains_key(&sequence_number) {
            self.associations.get_mut(&sequence_number).unwrap().push(node);
            self.associations.get_mut(&sequence_number).unwrap().dedup();
        } else {
            self.associations.insert(sequence_number, vec![node]);
        }
    }

    pub fn insert_updated_association(&mut self, sequence_number: U256, new_sequence_number: U256) {
        if self.associations.contains_key(&sequence_number) {
            let associations = self.associations.get(&sequence_number).unwrap().clone();

            self.associations.insert(new_sequence_number, vec![]);
            for mut node in associations.iter().cloned() {
                node.sequence_number = new_sequence_number;
                self.associations.get_mut(&new_sequence_number).unwrap().push(node);
            }
        } else {
            self.associations.insert(new_sequence_number, vec![]);
        }
    }

    pub fn remove_association(&mut self, sequence_number: U256) {
        self.associations.remove(&sequence_number);
    }

    pub fn insert_next_hop(&mut self, node: CloveNode, next_hop: Option<CloveNode>) {
        self.next_hop.insert(node.clone(), next_hop.clone());

        if let Some(next_hop) = next_hop {
            self.insert_association(node.sequence_number, next_hop);
        }
    }

    pub fn update_next_hop(&mut self, node: CloveNode, next_hop: Option<CloveNode>) {
        let prev_next = self.next_hop.remove(&node.clone());
        self.next_hop.insert(node.clone(), next_hop.clone());

        if let Some(previous_wrapped) = prev_next {
            if let Some(previous) = previous_wrapped {
                let associations = self.associations.get_mut(&node.sequence_number).unwrap();
                associations.retain(|x| *x != previous);
                if let Some(next_hop) = next_hop {
                    self.insert_association(node.sequence_number, next_hop);
                }
            }
        }
    }

    pub fn remove_next_hop(&mut self, node: CloveNode) {
        self.next_hop.remove(&node);
    }

    pub fn insert_am_alt(&mut self, sequence_number: U256) {
        self.am_alt_for.insert(sequence_number);
    }

    pub fn remove_am_alt(&mut self, sequence_number: U256) {
        self.am_alt_for.remove(&sequence_number);
    }

    pub fn insert_alt_node(&mut self, node: CloveNode, alt_node: CloveNode) {
        self.alt_nodes.insert(node.clone(), alt_node.clone());

        let try_sequence = self.alt_to_sequence.get(&node).cloned();
        if try_sequence.is_some() {
            self.alt_to_sequence.insert(alt_node.clone(), try_sequence.unwrap());
            self.insert_association(try_sequence.clone().unwrap(), alt_node.clone());
        } else {
            self.alt_to_sequence.insert(alt_node.clone(), node.sequence_number);
            self.insert_association(node.sequence_number, alt_node);
        }
    }

    pub fn remove_alt_node(&mut self, node: CloveNode) {
        self.alt_nodes.remove(&node);
        self.alt_to_sequence.remove(&node);
    }

    pub fn get_alt(&self, node: CloveNode) -> Option<CloveNode> {
        self.alt_nodes.get(&node).cloned()
    }

    pub fn get_old_from_alt(&self, node: &CloveNode) -> Option<CloveNode> {
        for info in self.alt_nodes.iter() {
            if info.1.sequence_number == node.sequence_number {
                return Some(info.0.clone());
            }
        }
        None
    }

    pub fn get_sequence_from_alt(&self, node: CloveNode) -> Option<U256> {
        self.alt_to_sequence.get(&node).cloned()
    }

    pub fn insert_my_alt_node(&mut self, sequence_number: U256, my_alt_node: CloveNode) {
        self.my_alt_nodes.insert(sequence_number, my_alt_node.clone());

        self.insert_association(sequence_number, my_alt_node);
    }

    pub fn remove_my_alt_node(&mut self, sequence_number: U256) {
        self.my_alt_nodes.remove(&sequence_number);
    }

    pub fn get_forward_node(&self, clove_node: CloveNode) -> Result<Option<CloveNode>, ()> {
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

    pub fn update_sequence_number(&mut self, new_sequence_number: U256, clove_node: CloveNode) {
        let node = clove_node.node.clone();
        let new_clove_node = CloveNode { sequence_number: new_sequence_number, node };

        let next = self.get_forward_node(clove_node.clone());

        match next {
            Ok(next_hop) => {
                match next_hop {
                    Some(next_node) => {
                        let mut new_next_hop_clove_node = CloveNode { sequence_number: new_sequence_number, node: next_node.clone().node };
                        new_next_hop_clove_node.sequence_number = new_sequence_number;
                        self.insert_next_hop(new_clove_node.clone(), Some(new_next_hop_clove_node.clone()));
                        self.insert_next_hop(new_next_hop_clove_node.clone(), Some(new_clove_node.clone()));

                        let mut has_alt = self.alt_nodes.contains_key(&clove_node);

                        if has_alt {
                            // In theory this should never happen since alt nodes are assigned
                            // after the path has already been solidified
                            println!("This should not happen: CloveCache::update_sequence_number():1");
                            let mut alt = self.alt_nodes.get(&clove_node).unwrap().clone();
                            alt.sequence_number = new_sequence_number;
                            self.insert_alt_node(new_clove_node, alt);
                        }

                        has_alt = self.alt_nodes.contains_key(&next_node);

                        if has_alt {
                            // In theory this should never happen since alt nodes are assigned
                            // after the path has already been solidified
                            println!("This should not happen: CloveCache::update_sequence_number():2");
                            let mut alt = self.alt_nodes.get(&next_node).unwrap().clone();
                            alt.sequence_number = new_sequence_number;
                            self.insert_alt_node(new_next_hop_clove_node, alt);
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
                            self.insert_alt_node(new_clove_node, alt);
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

    pub fn replace_with_alt_node(&mut self, old_clove_node: &CloveNode) -> Option<CloveNode> {
        let new_clove_node = self.alt_nodes.remove(old_clove_node);

        match new_clove_node {
            Some(new_clove_node) => {
                let forward_clove_node_try = self.next_hop.remove(old_clove_node).unwrap();

                match forward_clove_node_try {
                    Some(forward_clove_node) => {
                        self.next_hop.insert(new_clove_node.clone(), Some(forward_clove_node.clone()));
                        self.next_hop.remove(&forward_clove_node);
                        self.next_hop.insert(forward_clove_node, Some(new_clove_node.clone()));
                    }
                    _ => {
                        self.next_hop.insert(new_clove_node.clone(), None);
                    }
                }
                Some(new_clove_node)
            }
            _ => {
                None
            }
        }
    }

    pub fn seen(&mut self, sequence_number: U256) {
        self.seen_last.insert(sequence_number, Utc::now());
    }
}