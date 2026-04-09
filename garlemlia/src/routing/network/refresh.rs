use crate::net::node::Node;
use crate::routing::dispatcher::garlemlia_dispatch::GarlemliaContext;
use crate::routing::lookup::iterative::Iterative;
use crate::routing::runtime::Garlemlia;
use crate::routing::table::routing_table::RoutingTable;
use std::sync::Arc;
use tokio::net::UdpSocket;

pub struct Refresh;
impl Refresh {
    /// Add a node to the routing table
    pub async fn add_node(garlemlia: &mut Garlemlia, socket: &UdpSocket, node: Node) {
        let self_node = garlemlia.get_node().await;
        if node.id != self_node.id {
            let message_handler = Arc::clone(&garlemlia.message_handler);
            garlemlia
                .routing_table
                .lock()
                .await
                .add_node(&message_handler, node, socket)
                .await;
        }

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
    }

    /// Refresh buckets for self
    pub async fn refresh_buckets(garlemlia: &mut Garlemlia, _socket: Arc<UdpSocket>) {
        let self_id;
        {
            self_id = garlemlia.node.lock().await.id;
        }

        let total_buckets = 255;
        for b in 0..=total_buckets {
            let refresh_id = RoutingTable::random_id_for_bucket(self_id, b);
            Iterative::find_node(
                &GarlemliaContext::from(garlemlia, garlemlia.socket.clone()).await,
                refresh_id,
            )
            .await;
        }
    }
}
