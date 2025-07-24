use std::sync::Arc;
use tokio::net::UdpSocket;
use crate::garlemlia::garlemlia::functions::GarlemliaContext;
use crate::structs::garlemlia_message::GarlemliaStoreRequest;
use crate::structs::node::Node;
use super::{Garlemlia, GarlemliaFunctions};

impl Garlemlia {
    /// Store a value from the Garlemlia object itself
    pub async fn store_value(&mut self, socket: Arc<UdpSocket>, request: GarlemliaStoreRequest, store_count: usize) -> Vec<Node> {
        GarlemliaFunctions::store_value(&GarlemliaContext::from(self, socket).await, request, store_count).await
    }
}