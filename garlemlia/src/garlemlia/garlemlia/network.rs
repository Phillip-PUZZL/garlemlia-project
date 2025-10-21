use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use crate::structs::garlemlia_message::GarlemliaMessage;
use crate::structs::node::Node;
use crate::structs::routing_table::RoutingTable;
use super::Garlemlia;

impl Garlemlia {
    /// Add a node to the routing table
    pub async fn add_node(&mut self, socket: &UdpSocket, node: Node) {
        let self_node = self.get_node().await;
        if node.id != self_node.id {
            let message_handler = Arc::clone(&self.message_handler);
            self.routing_table.lock().await.add_node(&message_handler, node, socket).await;
        }

        {
            let rt = self.routing_table.lock().await;
            let mut settings_locked = self.settings.lock().await;

            let mut old_nodes = settings_locked.get_network_settings().get_known_nodes();
            old_nodes.sort_by_key(|n| n.id);

            let mut new_nodes = rt.flat_nodes().await;
            new_nodes.sort_by_key(|n| n.id);

            if old_nodes != new_nodes {
                settings_locked.get_network_settings_mut().set_known_nodes(new_nodes);
                if let Err(e) = settings_locked.save_settings().await {
                    eprintln!("Failed to save settings: {: }", e);
                }
            }
        }
    }

    /// Refresh buckets for self
    pub async fn refresh_buckets(&mut self, socket: Arc<UdpSocket>) {
        let self_id;
        {
            self_id = self.node.lock().await.id;
        }

        let total_buckets = 255;
        for b in 0..=total_buckets {
            let refresh_id = RoutingTable::random_id_for_bucket(self_id, b);
            self.iterative_find_node(socket.clone(), refresh_id).await;
        }
    }

    /// Initial function to join the network and perform a bucket refresh
    pub async fn join_network(&mut self, socket: Arc<UdpSocket>, initial_target: &Option<SocketAddr>) {
        let self_node = self.get_node().await;
        let socket_clone = Arc::clone(&socket);
        let message = GarlemliaMessage::FindNode {
            id: self_node.id,
            sender: self_node.clone(),
        };

        let mut potential_nodes = self.routing_table.lock().await.flat_nodes().await;

        let mut potential_targets = vec![];
        for node in potential_nodes {
            potential_targets.push(node.address);
        }

        if initial_target.is_some() {
            potential_targets.push(initial_target.unwrap());
        }

        for target in potential_targets {
            {
                if let Err(e) = self.message_handler.send(&socket, self_node.clone(), &target, &message).await {
                    eprintln!("Failed to send FindNode to {}: {:?}", target, e);
                }
            }

            let response;
            {
                response = self.message_handler.recv(200, &target).await;
            }

            // Check if the bootstrap node exists
            if response.is_ok() {
                match response.unwrap() {
                    GarlemliaMessage::Response { nodes, .. } => {
                        for node in nodes {
                            if node.id != self_node.id {
                                // Add this node to the routing table
                                self.routing_table.lock().await.add_node(&Arc::clone(&self.message_handler), node, &*socket_clone.clone()).await;
                            }
                        }
                    }
                    _ => {}
                }

                // Search for self to provide initial routing table information
                self.iterative_find_node(socket_clone.clone(), self_node.id).await;
                // Refresh buckets to provide better filled buckets
                self.refresh_buckets(socket_clone).await;

                {
                    let rt = self.routing_table.lock().await;
                    let mut settings_locked = self.settings.lock().await;

                    let mut old_nodes = settings_locked.get_network_settings().get_known_nodes();
                    old_nodes.sort_by_key(|n| n.id);

                    let mut new_nodes = rt.flat_nodes().await;
                    new_nodes.sort_by_key(|n| n.id);

                    if old_nodes != new_nodes {
                        settings_locked.get_network_settings_mut().set_known_nodes(new_nodes);
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
    pub async fn join_network_no_refresh(&mut self, socket: Arc<UdpSocket>, target: &SocketAddr) {
        let self_node = self.get_node().await;
        let socket_clone = Arc::clone(&socket);
        let message = GarlemliaMessage::FindNode {
            id: self_node.id,
            sender: self_node.clone(),
        };

        {
            if let Err(e) = self.message_handler.send(&socket, self_node.clone(), &target, &message).await {
                eprintln!("Failed to send FindNode to {}: {:?}", target, e);
            }
        }

        let response;
        {
            response = self.message_handler.recv(200, &target).await;
        }

        if response.is_ok() {
            match response.unwrap() {
                GarlemliaMessage::Response { nodes, .. } => {
                    for node in nodes {
                        if node.id != self_node.id {
                            self.routing_table.lock().await.add_node(&Arc::clone(&self.message_handler), node, &*socket_clone.clone()).await;
                        }
                    }
                }
                _ => {}
            }

            // Search for self
            self.iterative_find_node(socket_clone.clone(), self_node.id).await;
            // No bucket refresh here

            {
                let rt = self.routing_table.lock().await;
                let mut settings_locked = self.settings.lock().await;

                let mut old_nodes = settings_locked.get_network_settings().get_known_nodes();
                old_nodes.sort_by_key(|n| n.id);

                let mut new_nodes = rt.flat_nodes().await;
                new_nodes.sort_by_key(|n| n.id);

                if old_nodes != new_nodes {
                    settings_locked.get_network_settings_mut().set_known_nodes(new_nodes);
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