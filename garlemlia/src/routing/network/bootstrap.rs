use crate::data::garlemlia_protocol::GarlemliaMessage;
use crate::routing::dispatcher::garlemlia_dispatch::GarlemliaContext;
use crate::routing::lookup::iterative::Iterative;
use crate::routing::network::refresh::Refresh;
use crate::routing::runtime::Garlemlia;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

pub struct Bootstrap;
impl Bootstrap {
    /// Initial function to join the network and perform a bucket refresh
    pub async fn join(
        garlemlia: &mut Garlemlia,
        socket: Arc<UdpSocket>,
        initial_target: &Option<SocketAddr>,
    ) {
        let self_node = garlemlia.get_node().await;
        let socket_clone = Arc::clone(&socket);
        let message = GarlemliaMessage::FindNode {
            id: self_node.id,
            sender: self_node.clone(),
        };

        let potential_nodes = garlemlia.routing_table.lock().await.flat_nodes().await;

        let mut potential_targets = vec![];
        for node in potential_nodes {
            potential_targets.push(node.address);
        }

        if initial_target.is_some() {
            potential_targets.push(initial_target.unwrap());
        }

        for target in potential_targets {
            {
                if let Err(e) = garlemlia
                    .message_handler
                    .send(&socket, self_node.clone(), &target, &message)
                    .await
                {
                    eprintln!("Failed to send FindNode to {}: {:?}", target, e);
                }
            }

            let response;
            {
                response = garlemlia.message_handler.recv(200, &target).await;
            }

            // Check if the bootstrap node exists
            if response.is_ok() {
                match response.unwrap() {
                    GarlemliaMessage::Response { nodes, .. } => {
                        for node in nodes {
                            if node.id != self_node.id {
                                // Add this node to the routing table
                                garlemlia
                                    .routing_table
                                    .lock()
                                    .await
                                    .add_node(
                                        &Arc::clone(&garlemlia.message_handler),
                                        node,
                                        &*socket_clone.clone(),
                                    )
                                    .await;
                            }
                        }
                    }
                    _ => {}
                }

                // Search for garlemlia to provide initial routing table information
                Iterative::find_node(
                    &GarlemliaContext::from(garlemlia, socket_clone.clone()).await,
                    self_node.id,
                )
                .await;
                // Refresh buckets to provide better filled buckets
                Refresh::refresh_buckets(garlemlia, socket_clone).await;

                {
                    let rt = garlemlia.routing_table.lock().await;
                    let mut settings_locked = garlemlia.settings.lock().await;

                    let mut old_nodes = settings_locked.get_network_settings().get_known_nodes();
                    old_nodes.sort_by_key(|n| n.id);

                    let mut new_nodes = rt.flat_nodes().await;
                    new_nodes.sort_by_key(|n| n.id);

                    if old_nodes != new_nodes {
                        settings_locked
                            .get_network_settings_mut()
                            .set_known_nodes(new_nodes);
                        if let Err(e) = settings_locked.save_settings().await {
                            eprintln!("Failed to save settings: {: }", e);
                        }
                    }
                }

                break;
            } else {
                println!("NODE AT {target} FAILED, TRYING NEXT NODE");
            }
        }
    }

    /// Function for joining the network without performing an initial bucket refresh
    pub async fn join_no_refresh(
        garlemlia: &mut Garlemlia,
        socket: Arc<UdpSocket>,
        target: &SocketAddr,
    ) {
        let self_node = garlemlia.get_node().await;
        let socket_clone = Arc::clone(&socket);
        let message = GarlemliaMessage::FindNode {
            id: self_node.id,
            sender: self_node.clone(),
        };

        {
            if let Err(e) = garlemlia
                .message_handler
                .send(&socket, self_node.clone(), &target, &message)
                .await
            {
                eprintln!("Failed to send FindNode to {}: {:?}", target, e);
            }
        }

        let response;
        {
            response = garlemlia.message_handler.recv(200, &target).await;
        }

        if response.is_ok() {
            match response.unwrap() {
                GarlemliaMessage::Response { nodes, .. } => {
                    for node in nodes {
                        if node.id != self_node.id {
                            garlemlia
                                .routing_table
                                .lock()
                                .await
                                .add_node(
                                    &Arc::clone(&garlemlia.message_handler),
                                    node,
                                    &*socket_clone.clone(),
                                )
                                .await;
                        }
                    }
                }
                _ => {}
            }

            // Search for garlemlia
            Iterative::find_node(
                &GarlemliaContext::from(garlemlia, socket_clone.clone()).await,
                self_node.id,
            )
            .await;
            // No bucket refresh here

            {
                let rt = garlemlia.routing_table.lock().await;
                let mut settings_locked = garlemlia.settings.lock().await;

                let mut old_nodes = settings_locked.get_network_settings().get_known_nodes();
                old_nodes.sort_by_key(|n| n.id);

                let mut new_nodes = rt.flat_nodes().await;
                new_nodes.sort_by_key(|n| n.id);

                if old_nodes != new_nodes {
                    settings_locked
                        .get_network_settings_mut()
                        .set_known_nodes(new_nodes);
                    if let Err(e) = settings_locked.save_settings().await {
                        eprintln!("Failed to save settings: {: }", e);
                    }
                }
            }
        } else {
            println!("FAILED TO JOIN NETWORK");
        }
    }
}
