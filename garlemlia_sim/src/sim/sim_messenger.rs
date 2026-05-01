use async_trait::async_trait;
use garlemlia::core::error::MessageError;
use garlemlia::data::garlemlia_protocol::GarlemliaMessage;
use garlemlia::net::message_channel::MessageChannel;
use garlemlia::net::messenger::GarlemliaMessenger;
use garlemlia::net::node::Node;
use primitive_types::U256;
use std::collections::{HashMap, VecDeque};
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::timeout;

#[derive(Clone)]
pub struct SimMessenger {
    inboxes: Arc<Mutex<HashMap<U256, VecDeque<MessageChannel>>>>,
}

impl Debug for SimMessenger {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "SimMessenger")
    }
}

impl SimMessenger {
    pub fn new() -> Self {
        Self {
            inboxes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn register_node(&self, node: &Node) {
        self.inboxes
            .lock()
            .await
            .entry(node.id)
            .or_insert_with(VecDeque::new);
    }

    async fn deliver(
        &self,
        from: Node,
        target: Node,
        msg: GarlemliaMessage,
    ) -> Result<(), MessageError> {
        let mut inboxes = self.inboxes.lock().await;

        let inbox = inboxes.get_mut(&target.id).ok_or(MessageError::NoRX)?;

        inbox.push_back(MessageChannel {
            node_id: from.id,
            msg,
        });

        Ok(())
    }

    async fn receive_for(&self, node: Node) -> Result<GarlemliaMessage, MessageError> {
        let mut inboxes = self.inboxes.lock().await;

        let inbox = inboxes.get_mut(&node.id).ok_or(MessageError::NoRX)?;

        let channel = inbox.pop_front().ok_or(MessageError::MissingResponse)?;

        Ok(channel.msg)
    }
}

impl Default for SimMessenger {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl GarlemliaMessenger for SimMessenger {
    async fn send_no_recv(
        &self,
        from: Node,
        target: Node,
        msg: GarlemliaMessage,
    ) -> Result<(), MessageError> {
        self.deliver(from, target, msg).await
    }

    async fn send(
        &self,
        from: Node,
        target: Node,
        msg: GarlemliaMessage,
        timeout_ms: u64,
    ) -> Result<Option<GarlemliaMessage>, MessageError> {
        self.deliver(from.clone(), target.clone(), msg).await?;

        match timeout(Duration::from_millis(timeout_ms), self.receive_for(from)).await {
            Ok(Ok(response)) => Ok(Some(response)),
            Ok(Err(MessageError::MissingResponse)) => Ok(None),
            Ok(Err(e)) => Err(e),
            Err(_) => Ok(None),
        }
    }

    async fn recv(&self, node: Node, timeout_ms: u64) -> Result<GarlemliaMessage, MessageError> {
        timeout(Duration::from_millis(timeout_ms), self.receive_for(node))
            .await
            .unwrap_or_else(|_| Err(MessageError::Timeout))
    }

    fn clone_box(&self) -> Box<dyn GarlemliaMessenger> {
        Box::new(self.clone())
    }
}
