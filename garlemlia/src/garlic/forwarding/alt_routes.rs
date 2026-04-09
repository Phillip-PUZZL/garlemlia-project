use crate::core::u256_random;
use crate::data::garlemlia_protocol::GarlemliaMessage;
use crate::garlic::forwarding::forwarding::{Forwarding, TraitForwarding};
use crate::garlic::forwarding::proxy_discovery::{ProxyDiscovery, TraitProxyDiscovery};
use crate::garlic::state::garlic_cast::GarlicCast;
use crate::garlic::state::request_state::Proxy;
use crate::garlic::{Clove, CloveNode, GarlicMessage};
use crate::net::node::Node;
use chrono::Utc;
use primitive_types::U256;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

pub(crate) trait TraitAltRoutes {
    fn handle_alt_forward_failure(
        garlic: &mut GarlicCast,
        proxy: &Proxy,
        neighbor: &CloveNode,
    ) -> Option<Proxy>;
    fn process_neighbor_failure<'a>(
        garlic: &'a mut GarlicCast,
        neighbor: &'a CloveNode,
        clove: &'a Clove,
        proxy: &'a Proxy,
    ) -> impl Future<Output = Result<Option<Proxy>, ()>> + 'a;
    async fn update_my_alt_next_or_last(
        garlic: &GarlicCast,
        my_alt: CloveNode,
        node: Node,
        new_alt: Node,
    );
    async fn send_alt(
        garlic: &mut GarlicCast,
        n_1: Option<CloveNode>,
        n_2: Option<CloveNode>,
        alt: CloveNode,
    );
    async fn find_alt(
        garlic: &mut GarlicCast,
        n_1: Option<Node>,
        n_2: Option<Node>,
        sequence_number: U256,
    ) -> CloveNode;
}

pub struct AltRoutes;
impl TraitAltRoutes for AltRoutes {
    fn handle_alt_forward_failure(
        garlic: &mut GarlicCast,
        proxy: &Proxy,
        neighbor: &CloveNode,
    ) -> Option<Proxy> {
        if let Some(updated) = garlic.cache.get_alt(neighbor.clone()) {
            garlic.cache.remove_sequence(updated.sequence_number);
        }
        garlic
            .cache
            .remove_sequence(proxy.neighbor_2.sequence_number);
        ProxyDiscovery::remove_proxy(garlic, proxy);
        None
    }

    fn process_neighbor_failure<'a>(
        garlic: &'a mut GarlicCast,
        neighbor: &'a CloveNode,
        clove: &'a Clove,
        proxy: &'a Proxy,
    ) -> impl Future<Output = Result<Option<Proxy>, ()>> + 'a {
        Forwarding::forward_from_proxy_failed(garlic, neighbor, clove, proxy)
    }

    async fn update_my_alt_next_or_last(
        garlic: &GarlicCast,
        my_alt: CloveNode,
        node: Node,
        new_alt: Node,
    ) {
        let new_msg = GarlicMessage::UpdateAltNextOrLast {
            sequence_number: my_alt.sequence_number,
            old_node: node,
            new_node: new_alt.clone(),
        };

        let socket = Arc::clone(&garlic.socket);
        let time = Utc::now();

        {
            if let Err(e) = garlic
                .message_handler
                .send(
                    &Arc::from(socket.clone()),
                    garlic.local_node.clone(),
                    &my_alt.node.address,
                    &GarlicMessage::build_send(garlic.local_node.clone(), new_msg.clone()),
                )
                .await
            {
                eprintln!("Failed to send Forward to {}: {:?}", my_alt.node.address, e);
            }
        }

        let response;
        {
            response = garlic.message_handler.recv(200, &my_alt.node.address).await;
        }

        match response {
            Ok(_) => {
                //println!("{} :: UPDATEALTNEXTORLAST {} :: {} -> {}", time, my_alt.sequence_number, garlic.local_node.address, my_alt.node.address);
            }
            _ => {
                println!(
                    "{} :: UPDATEALTNEXTORLAST {} :: FAILURE : OFFLINE :: {} -> {}",
                    time, my_alt.sequence_number, garlic.local_node.address, my_alt.node.address
                );
            }
        }
    }

    async fn send_alt(
        garlic: &mut GarlicCast,
        n_1: Option<CloveNode>,
        n_2: Option<CloveNode>,
        alt: CloveNode,
    ) {
        let socket = Arc::clone(&garlic.socket);
        let time = Utc::now();
        let mut n_1_success = false;

        if let Some(n_1) = n_1 {
            let new_msg = GarlicMessage::UpdateAlt {
                sequence_number: n_1.sequence_number,
                alt_node: alt.clone(),
            };

            {
                if let Err(e) = garlic
                    .message_handler
                    .send(
                        &Arc::from(socket.clone()),
                        garlic.local_node.clone(),
                        &n_1.node.address,
                        &GarlicMessage::build_send(garlic.local_node.clone(), new_msg.clone()),
                    )
                    .await
                {
                    eprintln!("Failed to send Forward to {}: {:?}", n_1.node.address, e);
                }
            }

            let response;
            {
                response = garlic.message_handler.recv(200, &n_1.node.address).await;
            }

            match response {
                Ok(_) => {
                    //println!("{} :: UPDATEALT {} :: {} -> {}", time, n_1.sequence_number, garlic.local_node.address, n_1.node.address);
                    n_1_success = true;
                }
                _ => {
                    println!(
                        "{} :: UPDATEALT {} :: FAILURE : OFFLINE :: {} -> {}",
                        time, n_1.sequence_number, garlic.local_node.address, n_1.node.address
                    );
                    n_1_success = garlic.replace_with_alt(n_1, new_msg.clone()).await.is_ok();
                }
            }
        }

        if !n_1_success {
            return;
        }

        if let Some(n_2) = n_2 {
            let new_msg = GarlicMessage::UpdateAlt {
                sequence_number: n_2.sequence_number,
                alt_node: alt.clone(),
            };

            {
                if let Err(e) = garlic
                    .message_handler
                    .send(
                        &Arc::from(socket.clone()),
                        garlic.local_node.clone(),
                        &n_2.node.address,
                        &GarlicMessage::build_send(garlic.local_node.clone(), new_msg.clone()),
                    )
                    .await
                {
                    eprintln!("Failed to send Forward to {}: {:?}", n_2.node.address, e);
                }
            }

            let response;
            {
                response = garlic.message_handler.recv(200, &n_2.node.address).await;
            }

            match response {
                Ok(_) => {
                    //println!("{} :: UPDATEALT {} :: {} -> {}", time, n_2.sequence_number, garlic.local_node.address, n_2.node.address);
                }
                _ => {
                    println!(
                        "{} :: UPDATEALT {} :: FAILURE : OFFLINE :: {} -> {}",
                        time, n_2.sequence_number, garlic.local_node.address, n_2.node.address
                    );
                    let _ = garlic.replace_with_alt(n_2, new_msg).await;
                }
            }
        }
    }

    async fn find_alt(
        garlic: &mut GarlicCast,
        n_1: Option<Node>,
        n_2: Option<Node>,
        sequence_number: U256,
    ) -> CloveNode {
        let alt_sequence_number = u256_random();
        let mut keep_trying = true;
        let mut alt = CloveNode {
            sequence_number: alt_sequence_number,
            node: Node {
                id: U256::from(0),
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            },
        };

        if n_1.is_none() && n_2.is_none() {
            return alt;
        }

        while keep_trying {
            // Try the fuck out of some nodes until one responds with an IsAlive message
            let mut choose_list = garlic.known_nodes.clone();

            if let Some(n_1) = n_1.clone() {
                choose_list.retain(|n| *n != n_1.clone());
            }
            if let Some(n_2) = n_2.clone() {
                choose_list.retain(|n| *n != n_2.clone());
            }

            let forward_node = choose_list.remove(rand::random_range(0..choose_list.len()));

            let n_1_real;
            let n_2_real;
            if let Some(n_1) = n_1.clone() {
                n_1_real = n_1.clone();
            } else {
                n_1_real = choose_list.remove(rand::random_range(0..choose_list.len()));
            }
            if let Some(n_2) = n_2.clone() {
                n_2_real = n_2.clone();
            } else {
                n_2_real = choose_list.remove(rand::random_range(0..choose_list.len()));
            }

            let new_msg = GarlicMessage::RequestAlt {
                alt_sequence_number,
                next_hop: n_1_real.clone(),
                last_hop: n_2_real.clone(),
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
                Ok(gar_msg) => match gar_msg {
                    GarlemliaMessage::AgreeAlt { .. } => {
                        alt = CloveNode {
                            sequence_number: alt_sequence_number,
                            node: forward_node,
                        };

                        garlic
                            .cache
                            .insert_my_alt_node(sequence_number, alt.clone());

                        keep_trying = false;
                    }
                    _ => {}
                },
                Err(_) => {}
            }
        }
        alt
    }
}
