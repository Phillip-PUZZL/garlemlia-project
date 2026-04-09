use crate::garlic::forwarding::alt_routes::{AltRoutes, TraitAltRoutes};
use crate::garlic::state::garlic_cast::GarlicCast;
use crate::garlic::state::request_state::Proxy;
use crate::garlic::{
    Clove, CloveMessage, CloveNode, CloveProtocol, GarlicMessage, TraitCloveProtocol,
};
use crate::net::node::Node;
use primitive_types::U256;
use rand::prelude::IndexedRandom;
use rsa::pkcs8::EncodePublicKey;
use std::sync::Arc;

pub(crate) trait TraitForwarding {
    async fn forward_proxy_accept(garlic: &mut GarlicCast, proxy: Proxy, old_sequence: U256);
    async fn forward_find_proxy(
        garlic: &mut GarlicCast,
        sequence_number: U256,
        node: Node,
        msg: Clove,
    );
    async fn forward_from_proxy(
        garlic: &mut GarlicCast,
        next_node_hop: &CloveNode,
        msg: &Clove,
        proxy: &Proxy,
    ) -> Result<Option<Proxy>, ()>;
    async fn forward_from_proxy_failed(
        garlic: &mut GarlicCast,
        next_node_hop: &CloveNode,
        msg: &Clove,
        proxy: &Proxy,
    ) -> Result<Option<Proxy>, ()>;
    async fn handle_failed_forward(
        garlic: &mut GarlicCast,
        next_node_hop: &CloveNode,
        msg: GarlicMessage,
    ) -> bool;
    async fn forward(garlic: &mut GarlicCast, next_node_hop: &CloveNode, msg: &Clove) -> bool;
}

pub struct Forwarding;
impl TraitForwarding for Forwarding {
    async fn forward_proxy_accept(garlic: &mut GarlicCast, proxy: Proxy, old_sequence: U256) {
        let hops_start = rand::random::<u16>() & 0b1111;

        let proxy_info = CloveMessage::ProxyInfo {
            public_key: garlic
                .public_key
                .clone()
                .unwrap()
                .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
                .unwrap(),
            starting_hops: hops_start,
        };

        let cloves = CloveProtocol::generate(
            proxy_info,
            2,
            proxy.sequence_number,
            Some(proxy.public_key),
            None,
        )
        .unwrap();

        let agreement_1 = GarlicMessage::ProxyAgree {
            sequence_number: old_sequence,
            updated_sequence_number: proxy.sequence_number,
            hops: hops_start,
            clove: cloves[0].clone(),
        };

        let agreement_2 = GarlicMessage::ProxyAgree {
            sequence_number: old_sequence,
            updated_sequence_number: proxy.sequence_number,
            hops: hops_start,
            clove: cloves[1].clone(),
        };

        let n_1 = proxy.neighbor_1.node;
        let n_2 = proxy.neighbor_2.node;

        let socket = Arc::clone(&garlic.socket);

        {
            if let Err(e) = garlic
                .message_handler
                .send(
                    &Arc::from(socket.clone()),
                    garlic.local_node.clone(),
                    &n_1.address,
                    &GarlicMessage::build_send(garlic.local_node.clone(), agreement_1),
                )
                .await
            {
                eprintln!("Failed to send Forward to {}: {:?}", n_1.address, e);
            }
        }

        let response;
        {
            response = garlic.message_handler.recv(200, &n_1.address).await;
        }

        {
            if let Err(e) = garlic
                .message_handler
                .send(
                    &Arc::from(socket.clone()),
                    garlic.local_node.clone(),
                    &n_2.address,
                    &GarlicMessage::build_send(garlic.local_node.clone(), agreement_2),
                )
                .await
            {
                eprintln!("Failed to send Forward to {}: {:?}", n_2.address, e);
            }
        }

        let response2;
        {
            response2 = garlic.message_handler.recv(200, &n_2.address).await;
        }

        match response {
            Ok(_) => {
                match response2 {
                    Ok(_) => {
                        //println!("{} SENT ProxyAgree TO {} AND {}", garlic.local_node.address, n_2.address, n_1.address);
                    }
                    _ => {
                        println!(
                            "{} FAILED TO SEND ProxyAgree TO {} BUT SENT TO {}",
                            garlic.local_node.address, n_2.address, n_1.address
                        );
                        garlic.cache.remove_sequence(proxy.sequence_number);
                        garlic.cache.remove_sequence(old_sequence);
                    }
                }
            }
            _ => {
                match response2 {
                    Ok(_) => {
                        println!(
                            "{} FAILED TO SEND ProxyAgree TO {} BUT SENT TO {}",
                            garlic.local_node.address, n_1.address, n_2.address
                        );
                    }
                    _ => {
                        println!(
                            "{} FAILED TO SEND ProxyAgree TO {} AND {}",
                            garlic.local_node.address, n_1.address, n_2.address
                        );
                    }
                }

                garlic.cache.remove_sequence(proxy.sequence_number);
                garlic.cache.remove_sequence(old_sequence);
            }
        }
    }

    async fn forward_find_proxy(
        garlic: &mut GarlicCast,
        sequence_number: U256,
        node: Node,
        msg: Clove,
    ) {
        let mut keep_trying = true;
        while keep_trying {
            // Try the fuck out of some nodes until one responds with an IsAlive message
            let mut choose_list = garlic.known_nodes.clone();

            choose_list.retain(|n| *n != node);

            let forward_node = choose_list.choose(&mut rand::rng()).unwrap().clone();

            let new_msg = GarlicMessage::FindProxy {
                sequence_number,
                clove: msg.clone(),
            };

            let socket = Arc::clone(&garlic.socket);

            {
                if let Err(e) = garlic
                    .message_handler
                    .send(
                        &Arc::from(socket.clone()),
                        garlic.local_node.clone(),
                        &forward_node.address,
                        &GarlicMessage::build_send(garlic.local_node.clone(), new_msg),
                    )
                    .await
                {
                    eprintln!(
                        "Failed to send Forward to {}: {:?}",
                        forward_node.address, e
                    );
                }
            }

            let response;
            {
                response = garlic
                    .message_handler
                    .recv(200, &forward_node.address)
                    .await;
            }

            match response {
                Ok(_) => {
                    // Insert two next_hops for original node and new forward node
                    let forward_clove = CloveNode {
                        sequence_number,
                        node: forward_node.clone(),
                    };
                    let original_clove = CloveNode {
                        sequence_number,
                        node: node.clone(),
                    };

                    garlic
                        .cache
                        .insert_next_hop(original_clove.clone(), Some(forward_clove.clone()));
                    garlic
                        .cache
                        .insert_next_hop(forward_clove.clone(), Some(original_clove.clone()));
                    // Insert clove
                    garlic.cache.insert_clove(msg.clone(), node.clone());
                    // Insert associations
                    garlic
                        .cache
                        .insert_association(sequence_number, original_clove.clone());
                    garlic
                        .cache
                        .insert_association(sequence_number, forward_clove.clone());
                    // Insert seen last
                    garlic.cache.seen(sequence_number);

                    keep_trying = false;
                }
                Err(_) => {}
            }
        }
    }

    async fn forward_from_proxy(
        garlic: &mut GarlicCast,
        next_node_hop: &CloveNode,
        msg: &Clove,
        proxy: &Proxy,
    ) -> Result<Option<Proxy>, ()> {
        let next_node = next_node_hop.clone();
        let mut new_clove = msg.clone();

        if msg.sequence_number != next_node.sequence_number {
            new_clove.sequence_number = next_node.sequence_number;
        }

        let new_msg = GarlicMessage::Forward {
            sequence_number: next_node.sequence_number,
            clove: new_clove.clone(),
        };

        let socket = Arc::clone(&garlic.socket);

        {
            if let Err(e) = garlic
                .message_handler
                .send(
                    &Arc::from(socket.clone()),
                    garlic.local_node.clone(),
                    &next_node.node.address,
                    &GarlicMessage::build_send(garlic.local_node.clone(), new_msg.clone()),
                )
                .await
            {
                eprintln!(
                    "Failed to send Forward to {}: {:?}",
                    next_node.node.address, e
                );
            }
        }

        let response;
        {
            response = garlic
                .message_handler
                .recv(200, &next_node.node.address)
                .await;
        }

        match response {
            Ok(_) => Ok(None),
            _ => {
                let replace_info = garlic.replace_with_alt(next_node, new_msg).await;

                match replace_info {
                    Ok(replacement) => {
                        let mut new_proxy = proxy.clone();

                        if proxy.neighbor_1.node.id == next_node_hop.node.id {
                            new_proxy.neighbor_1 = replacement.clone();
                        } else if proxy.neighbor_2.node.id == next_node_hop.node.id {
                            new_proxy.neighbor_2 = replacement.clone();
                        } else {
                            return Err(());
                        }

                        let my_alt_for_seq = garlic
                            .cache
                            .my_alt_nodes
                            .get(&proxy.sequence_number)
                            .cloned();

                        if my_alt_for_seq.is_some() {
                            AltRoutes::send_alt(
                                garlic,
                                Some(replacement.clone()),
                                None,
                                my_alt_for_seq.clone().unwrap(),
                            )
                            .await;
                            AltRoutes::update_my_alt_next_or_last(
                                garlic,
                                my_alt_for_seq.clone().unwrap(),
                                next_node_hop.clone().node,
                                replacement.node,
                            )
                            .await;
                        }

                        Ok(Some(new_proxy))
                    }
                    Err(info) => Err(info),
                }
            }
        }
    }

    async fn forward_from_proxy_failed(
        garlic: &mut GarlicCast,
        next_node_hop: &CloveNode,
        msg: &Clove,
        proxy: &Proxy,
    ) -> Result<Option<Proxy>, ()> {
        let next_node = next_node_hop.clone();
        let mut new_clove = msg.clone();

        if msg.sequence_number != next_node.sequence_number {
            new_clove.sequence_number = next_node.sequence_number;
        }

        let new_msg = GarlicMessage::Forward {
            sequence_number: next_node.sequence_number,
            clove: new_clove.clone(),
        };

        let replace_info = garlic.replace_with_alt(next_node, new_msg).await;

        match replace_info {
            Ok(replacement) => {
                let mut new_proxy = proxy.clone();

                if proxy.neighbor_1.node.id == next_node_hop.node.id {
                    new_proxy.neighbor_1 = replacement.clone();
                } else if proxy.neighbor_2.node.id == next_node_hop.node.id {
                    new_proxy.neighbor_2 = replacement.clone();
                } else {
                    return Err(());
                }

                let my_alt_for_seq = garlic
                    .cache
                    .my_alt_nodes
                    .get(&proxy.sequence_number)
                    .cloned();

                if my_alt_for_seq.is_some() {
                    AltRoutes::send_alt(
                        garlic,
                        Some(replacement.clone()),
                        None,
                        my_alt_for_seq.clone().unwrap(),
                    )
                    .await;
                    AltRoutes::update_my_alt_next_or_last(
                        garlic,
                        my_alt_for_seq.clone().unwrap(),
                        next_node_hop.clone().node,
                        replacement.node,
                    )
                    .await;
                }

                Ok(Some(new_proxy))
            }
            Err(info) => Err(info),
        }
    }

    async fn handle_failed_forward(
        garlic: &mut GarlicCast,
        next_node_hop: &CloveNode,
        msg: GarlicMessage,
    ) -> bool {
        let replace_info = garlic.replace_with_alt(next_node_hop.clone(), msg).await;

        if let Ok(alt_node) = replace_info {
            let real_sequence_number = garlic
                .cache
                .alt_to_sequence
                .get(next_node_hop)
                .cloned()
                .unwrap_or(next_node_hop.sequence_number);

            if let Some(my_alt_node) = garlic
                .cache
                .my_alt_nodes
                .get(&real_sequence_number)
                .cloned()
            {
                AltRoutes::send_alt(garlic, Some(alt_node.clone()), None, my_alt_node.clone())
                    .await;
                AltRoutes::update_my_alt_next_or_last(
                    garlic,
                    my_alt_node,
                    next_node_hop.clone().node,
                    alt_node.node,
                )
                .await;
            }
            true
        } else {
            false
        }
    }

    async fn forward(garlic: &mut GarlicCast, next_node_hop: &CloveNode, msg: &Clove) -> bool {
        const RESPONSE_TIMEOUT_MS: u64 = 200;

        let mut new_clove = msg.clone();
        if msg.sequence_number != next_node_hop.sequence_number {
            new_clove.sequence_number = next_node_hop.sequence_number;
        }

        let new_msg = GarlicMessage::Forward {
            sequence_number: next_node_hop.sequence_number,
            clove: new_clove,
        };

        if garlic
            .send_forward_message(next_node_hop, &new_msg)
            .await
            .is_err()
        {
            return false;
        }

        if let Ok(_) = garlic
            .message_handler
            .recv(RESPONSE_TIMEOUT_MS, &next_node_hop.node.address)
            .await
        {
            return true;
        }

        Self::handle_failed_forward(garlic, next_node_hop, new_msg).await
    }
}
