use crate::core::constants::{DEFAULT_K, LOOKUP_ALPHA};
use crate::data::garlemlia_protocol::{GarlemliaFindRequest, GarlemliaMessage, GarlemliaResponse};
use crate::net::node::Node;
use crate::routing::dispatcher::garlemlia_dispatch::GarlemliaContext;
use crate::routing::lookup::nearest::Nearest;
use primitive_types::U256;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::task;

enum LookupOutcome<T> {
    Continue(Vec<Node>),
    Found(T),
}

pub struct Iterative;
impl Iterative {
    fn next_nodes_to_query(top_k: &[Node], queried_nodes: &HashSet<SocketAddr>) -> Vec<Node> {
        let mut nodes: Vec<Node> = top_k
            .iter()
            .filter(|n| !queried_nodes.contains(&n.address))
            .cloned()
            .collect();

        if nodes.len() > LOOKUP_ALPHA {
            nodes.truncate(LOOKUP_ALPHA);
        }

        nodes
    }

    fn candidate_ids(nodes: &[Node]) -> HashSet<U256> {
        nodes.iter().map(|n| n.id).collect()
    }

    async fn refresh_initial_nodes(
        context: &GarlemliaContext,
        initial_nodes: &mut Vec<Node>,
        key: U256,
    ) {
        if initial_nodes.contains(&context.self_node) {
            *initial_nodes = context
                .routing_table
                .lock()
                .await
                .find_closest_nodes(key, LOOKUP_ALPHA + 1)
                .await;
            initial_nodes.retain(|x| *x != context.self_node);
        }
    }

    async fn query_find_node_round(
        context: &GarlemliaContext,
        target_id: U256,
        nodes_to_query: Vec<Node>,
        queried_nodes: &mut HashSet<SocketAddr>,
    ) -> Vec<Node> {
        let mut tasks = Vec::new();

        for node in nodes_to_query {
            if queried_nodes.contains(&node.address) {
                continue;
            }

            queried_nodes.insert(node.address);

            let socket = Arc::clone(&context.socket);
            let message_handler = Arc::clone(&context.message_handler);
            let self_node = context.self_node.clone();
            let node_clone = node.clone();

            tasks.push(tokio::spawn(async move {
                let message = GarlemliaMessage::FindNode {
                    id: target_id,
                    sender: self_node.clone(),
                };

                if let Err(e) = message_handler
                    .send(&socket, self_node, &node_clone.address, &message)
                    .await
                {
                    eprintln!("Failed to send FindNode to {}: {:?}", node_clone.address, e);
                    return None;
                }

                match message_handler.recv(200, &node_clone.address).await {
                    Ok(GarlemliaMessage::Response { nodes, .. }) => Some(nodes),
                    _ => None,
                }
            }));
        }

        let mut new_nodes = Vec::new();
        for task in tasks {
            if let Ok(Some(nodes)) = task.await {
                new_nodes.extend(nodes);
            }
        }

        new_nodes
    }

    async fn query_find_value_round(
        context: &GarlemliaContext,
        request: GarlemliaFindRequest,
        nodes_to_query: Vec<Node>,
        queried_nodes: &mut HashSet<SocketAddr>,
    ) -> LookupOutcome<GarlemliaResponse> {
        let mut tasks = Vec::new();

        for node in nodes_to_query {
            if queried_nodes.contains(&node.address) {
                continue;
            }

            queried_nodes.insert(node.address);

            let socket = Arc::clone(&context.socket);
            let message_handler = Arc::clone(&context.message_handler);
            let self_node = context.self_node.clone();
            let node_clone = node.clone();
            let request_clone = request.clone();

            tasks.push(task::spawn(async move {
                let message = GarlemliaMessage::FindValue {
                    request: request_clone,
                    sender: self_node.clone(),
                };

                if let Err(e) = message_handler
                    .send(&socket, self_node, &node_clone.address, &message)
                    .await
                {
                    eprintln!(
                        "Failed to send FindValue to {}: {:?}",
                        node_clone.address, e
                    );
                    return None;
                }

                match message_handler.recv(200, &node_clone.address).await {
                    Ok(GarlemliaMessage::Response { nodes, value, .. }) => {
                        if let Some(value) = value {
                            Some(LookupOutcome::Found(value))
                        } else {
                            Some(LookupOutcome::Continue(nodes))
                        }
                    }
                    _ => Some(LookupOutcome::Continue(vec![])),
                }
            }));
        }

        let mut new_nodes = Vec::new();

        for task in tasks {
            if let Ok(Some(result)) = task.await {
                match result {
                    LookupOutcome::Found(value) => return LookupOutcome::Found(value),
                    LookupOutcome::Continue(nodes) => new_nodes.extend(nodes),
                }
            }
        }

        LookupOutcome::Continue(new_nodes)
    }

    /// Basic Kademlia iterative find node implementation
    pub async fn find_node(context: &GarlemliaContext, target_id: U256) -> Vec<Node> {
        let mut queried_nodes = HashSet::new();

        let mut initial_nodes = context
            .routing_table
            .lock()
            .await
            .find_closest_nodes(target_id, LOOKUP_ALPHA)
            .await;

        Self::refresh_initial_nodes(context, &mut initial_nodes, target_id).await;

        let mut top_k = initial_nodes;
        Nearest::dedup_and_trim(&mut top_k, target_id, &context.self_node, DEFAULT_K);

        loop {
            let nodes_to_query = Self::next_nodes_to_query(&top_k, &queried_nodes);
            if nodes_to_query.is_empty() {
                break;
            }

            let new_nodes =
                Self::query_find_node_round(context, target_id, nodes_to_query, &mut queried_nodes)
                    .await;

            context.garlic.lock().await.update_known(new_nodes.clone());

            let old_ids = Self::candidate_ids(&top_k);

            let mut new_candidate_set = top_k.clone();
            new_candidate_set.extend(new_nodes);
            Nearest::dedup_and_trim(
                &mut new_candidate_set,
                target_id,
                &context.self_node,
                DEFAULT_K,
            );

            if old_ids == Self::candidate_ids(&new_candidate_set) {
                break;
            }

            top_k = new_candidate_set;
        }

        top_k.push(context.self_node.clone());
        Nearest::dedup_and_trim(&mut top_k, target_id, &context.self_node, DEFAULT_K);
        top_k
    }

    /// Perform an iterative lookup for a value in the DHT - Kademlia regular implementation
    pub async fn find_value(
        context: &GarlemliaContext,
        request: GarlemliaFindRequest,
    ) -> Option<GarlemliaResponse> {
        let key = request.get_id();

        if let Some(val) = context.data_store.lock().await.get(&key).cloned() {
            return val.get_response(Some(request));
        }

        let mut queried_nodes = HashSet::new();

        let mut initial_nodes = context
            .routing_table
            .lock()
            .await
            .find_closest_nodes(key, LOOKUP_ALPHA)
            .await;

        Self::refresh_initial_nodes(context, &mut initial_nodes, key).await;

        let mut top_k = initial_nodes;
        Nearest::dedup_and_trim(&mut top_k, key, &context.self_node, DEFAULT_K);

        loop {
            let nodes_to_query = Self::next_nodes_to_query(&top_k, &queried_nodes);
            if nodes_to_query.is_empty() {
                break;
            }

            let old_ids = Self::candidate_ids(&top_k);

            match Self::query_find_value_round(
                context,
                request.clone(),
                nodes_to_query,
                &mut queried_nodes,
            )
            .await
            {
                LookupOutcome::Found(value) => return Some(value),
                LookupOutcome::Continue(new_nodes) => {
                    let mut new_candidate_set = top_k.clone();
                    new_candidate_set.extend(new_nodes);
                    Nearest::dedup_and_trim(
                        &mut new_candidate_set,
                        key,
                        &context.self_node,
                        DEFAULT_K,
                    );

                    if old_ids == Self::candidate_ids(&new_candidate_set) {
                        break;
                    }

                    top_k = new_candidate_set;
                }
            }
        }

        None
    }
}
