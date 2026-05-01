use crate::data::garlemlia_protocol::GarlemliaMessage;
use primitive_types::U256;

#[derive(Debug, Clone)]
pub struct MessageChannel {
    pub node_id: U256,
    pub msg: GarlemliaMessage,
}