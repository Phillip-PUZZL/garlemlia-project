use crate::core::error::MessageError;
use crate::data::garlemlia_protocol::GarlemliaMessage;
use crate::net::node::Node;
use async_trait::async_trait;
use std::fmt::Debug;

#[async_trait]
pub trait GarlemliaMessenger: Send + Sync + Debug {
    async fn send_no_recv(
        &self,
        from: Node,
        target: Node,
        msg: GarlemliaMessage,
    ) -> Result<(), MessageError>;

    async fn send(
        &self,
        from: Node,
        target: Node,
        msg: GarlemliaMessage,
        timeout_ms: u64,
    ) -> Result<Option<GarlemliaMessage>, MessageError>;

    async fn recv(&self, node: Node, timeout_ms: u64) -> Result<GarlemliaMessage, MessageError>;

    fn clone_box(&self) -> Box<dyn GarlemliaMessenger>;
}

impl Clone for Box<dyn GarlemliaMessenger> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}
