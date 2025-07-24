use super::{Garlemlia, GarlemliaFunctions};
use std::sync::Arc;
use primitive_types::U256;
use tokio::net::UdpSocket;
use crate::garlemlia::garlemlia::functions::GarlemliaContext;
use crate::structs::garlemlia_message::{GarlemliaFindRequest, GarlemliaResponse};
use crate::structs::node::Node;

impl Garlemlia {
    /// Iterative find node function for the Garlemlia object itself
    pub async fn iterative_find_node(&self, socket: Arc<UdpSocket>, target_id: U256) -> Vec<Node> {
        GarlemliaFunctions::iterative_find_node(&GarlemliaContext::from(self, socket).await, target_id).await
    }


    /// Perform an iterative lookup for a value in the DHT for the Garlemlia object itself
    pub async fn iterative_find_value(&self, socket: Arc<UdpSocket>, request: GarlemliaFindRequest) -> Option<GarlemliaResponse> {
        GarlemliaFunctions::iterative_find_value(&GarlemliaContext::from(self, socket).await, request).await
    }
}