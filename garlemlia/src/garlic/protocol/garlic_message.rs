use crate::data::garlemlia_protocol::{GarlemliaMessage, GarlemliaResponse};
use crate::garlic::{Clove, CloveNode, CloveRequestID};
use crate::net::node::Node;
use primitive_types::U256;
use serde::{Deserialize, Serialize};

/// Garlic Message types
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum GarlicMessage {
    FindProxy {
        sequence_number: U256,
        clove: Clove,
    },
    Forward {
        sequence_number: U256,
        clove: Clove,
    },
    ProxyAgree {
        sequence_number: U256,
        updated_sequence_number: U256,
        hops: u16,
        clove: Clove,
    },
    RequestAlt {
        alt_sequence_number: U256,
        next_hop: Node,
        last_hop: Node,
    },
    RefreshAlt {
        sequence_number: U256,
    },
    UpdateAlt {
        sequence_number: U256,
        alt_node: CloveNode,
    },
    UpdateAltNextOrLast {
        sequence_number: U256,
        old_node: Node,
        new_node: Node,
    },
    ResponseDirect {
        request_id: CloveRequestID,
        clove_1: Clove,
        clove_2: Clove,
    },
    FileChunkPart {
        request_id: CloveRequestID,
        data: GarlemliaResponse,
    },
}

impl GarlicMessage {
    pub fn sequence_number(&self) -> U256 {
        match self {
            GarlicMessage::FindProxy {
                sequence_number, ..
            } => sequence_number.clone(),
            GarlicMessage::Forward {
                sequence_number, ..
            } => sequence_number.clone(),
            GarlicMessage::ProxyAgree {
                sequence_number, ..
            } => sequence_number.clone(),
            GarlicMessage::RequestAlt { .. } => U256::from(0),
            GarlicMessage::RefreshAlt { .. } => U256::from(0),
            GarlicMessage::UpdateAlt { .. } => U256::from(0),
            GarlicMessage::UpdateAltNextOrLast { .. } => U256::from(0),
            GarlicMessage::ResponseDirect { .. } => U256::from(0),
            GarlicMessage::FileChunkPart { .. } => U256::from(0),
        }
    }

    /// Updating sequence number of message - used when sending to what was once an alt node
    pub fn update_sequence_number(&mut self, new_sequence_number: U256) {
        match self {
            GarlicMessage::Forward { clove, .. } => {
                *self = GarlicMessage::Forward {
                    sequence_number: new_sequence_number,
                    clove: clove.update_sequence(new_sequence_number),
                };
            }
            GarlicMessage::UpdateAlt { alt_node, .. } => {
                *self = GarlicMessage::UpdateAlt {
                    sequence_number: new_sequence_number,
                    alt_node: alt_node.clone(),
                };
            }
            _ => {}
        }
    }

    pub fn clove(&self) -> Option<Clove> {
        match self {
            GarlicMessage::FindProxy { clove, .. } => Some(clove.clone().clone()),
            GarlicMessage::Forward { clove, .. } => Some(clove.clone().clone()),
            GarlicMessage::ProxyAgree { clove, .. } => Some(clove.clone()),
            GarlicMessage::RequestAlt { .. } => None,
            GarlicMessage::RefreshAlt { .. } => None,
            GarlicMessage::UpdateAlt { .. } => None,
            GarlicMessage::UpdateAltNextOrLast { .. } => None,
            GarlicMessage::ResponseDirect { .. } => None,
            GarlicMessage::FileChunkPart { .. } => None,
        }
    }

    pub fn build_send_is_alive(sender: Node) -> GarlemliaMessage {
        GarlemliaMessage::Pong { sender }
    }

    pub fn build_send(sender: Node, msg: GarlicMessage) -> GarlemliaMessage {
        GarlemliaMessage::Garlic { msg, sender }
    }
}
