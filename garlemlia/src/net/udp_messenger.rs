use crate::core::error::MessageError;
use crate::data::garlemlia_protocol::GarlemliaMessage;
use crate::net::message_channel::MessageChannel;
use crate::net::messenger::GarlemliaMessenger;
use crate::net::node::Node;
use async_trait::async_trait;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::sync::Mutex;
use tokio::time::timeout;

#[derive(Debug, Clone)]
struct ChannelReceiver {
    id: u8,
    rx: Arc<Mutex<UnboundedReceiver<MessageChannel>>>,
}

#[derive(Debug, Clone)]
struct ChannelSender {
    id: u8,
    tx: Arc<Mutex<UnboundedSender<MessageChannel>>>,
}

#[derive(Clone)]
pub struct UdpMessenger {
    socket: Arc<UdpSocket>,

    available_rx: Arc<Mutex<Vec<ChannelReceiver>>>,
    unavailable_rx: Arc<Mutex<HashMap<SocketAddr, ChannelReceiver>>>,

    available_tx: Arc<Mutex<Vec<ChannelSender>>>,
    unavailable_tx: Arc<Mutex<HashMap<SocketAddr, ChannelSender>>>,
}

impl Debug for UdpMessenger {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "UdpMessenger")
    }
}

impl UdpMessenger {
    pub fn new(socket: Arc<UdpSocket>, channel_count: u8) -> Self {
        let mut rx_pool = Vec::with_capacity(channel_count as usize);
        let mut tx_pool = Vec::with_capacity(channel_count as usize);

        for id in 0..channel_count {
            let (tx, rx) = mpsc::unbounded_channel();

            rx_pool.push(ChannelReceiver {
                id,
                rx: Arc::new(Mutex::new(rx)),
            });

            tx_pool.push(ChannelSender {
                id,
                tx: Arc::new(Mutex::new(tx)),
            });
        }

        Self {
            socket,
            available_rx: Arc::new(Mutex::new(rx_pool)),
            unavailable_rx: Arc::new(Mutex::new(HashMap::new())),
            available_tx: Arc::new(Mutex::new(tx_pool)),
            unavailable_tx: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn route_response(
        &self,
        src: SocketAddr,
        msg: MessageChannel,
    ) -> Result<(), MessageError> {
        let tx = {
            let map = self.unavailable_tx.lock().await;
            map.get(&src).cloned()
        };

        let Some(tx_info) = tx else {
            return Err(MessageError::NoTX);
        };

        let tx_guard = tx_info.tx.lock().await;

        if tx_guard.is_closed() {
            return Err(MessageError::TXDropped);
        }

        tx_guard.send(msg).map_err(|_| MessageError::TXSendError)
    }

    async fn reserve_channel_pair(&self, target: SocketAddr) -> Result<(), MessageError> {
        loop {
            let receiver = {
                let mut rx_pool = self.available_rx.lock().await;
                rx_pool.pop()
            };

            if let Some(receiver) = receiver {
                let sender = {
                    let mut tx_pool = self.available_tx.lock().await;

                    let index = tx_pool
                        .iter()
                        .position(|tx| tx.id == receiver.id)
                        .ok_or(MessageError::NoTX)?;

                    tx_pool.remove(index)
                };

                self.unavailable_rx.lock().await.insert(target, receiver);

                self.unavailable_tx.lock().await.insert(target, sender);

                return Ok(());
            }

            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn release_channel_pair(&self, target: SocketAddr) {
        let tx = self.unavailable_tx.lock().await.remove(&target);
        let rx = self.unavailable_rx.lock().await.remove(&target);

        if let Some(tx) = tx {
            self.available_tx.lock().await.push(tx);
        }

        if let Some(rx) = rx {
            self.available_rx.lock().await.push(rx);
        }
    }

    async fn recv_from_reserved_channel(
        &self,
        target: SocketAddr,
        timeout_ms: u64,
    ) -> Result<GarlemliaMessage, MessageError> {
        let rx = {
            let map = self.unavailable_rx.lock().await;
            map.get(&target).cloned()
        };

        let Some(receiver) = rx else {
            return Err(MessageError::NoRX);
        };

        let result = {
            let mut guard = receiver.rx.lock().await;

            match timeout(Duration::from_millis(timeout_ms), guard.recv()).await {
                Ok(Some(channel)) => Ok(channel.msg),
                Ok(None) => Err(MessageError::MissingResponse),
                Err(_) => Err(MessageError::Timeout),
            }
        };

        self.release_channel_pair(target).await;

        result
    }

    async fn send_udp(
        &self,
        target: SocketAddr,
        msg: &GarlemliaMessage,
    ) -> Result<(), MessageError> {
        let bytes =
            serde_json::to_vec(msg).map_err(|e| MessageError::SerializationError(e.to_string()))?;

        self.socket.send_to(&bytes, target).await?;

        Ok(())
    }
}

#[async_trait]
impl GarlemliaMessenger for UdpMessenger {
    async fn send_no_recv(
        &self,
        _from: Node,
        target: Node,
        msg: GarlemliaMessage,
    ) -> Result<(), MessageError> {
        self.send_udp(target.address, &msg).await
    }

    async fn send(
        &self,
        _from: Node,
        target: Node,
        msg: GarlemliaMessage,
        timeout_ms: u64,
    ) -> Result<Option<GarlemliaMessage>, MessageError> {
        self.reserve_channel_pair(target.address).await?;

        if let Err(e) = self.send_udp(target.address, &msg).await {
            self.release_channel_pair(target.address).await;
            return Err(e);
        }

        match self
            .recv_from_reserved_channel(target.address, timeout_ms)
            .await
        {
            Ok(response) => Ok(Some(response)),
            Err(MessageError::Timeout) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn recv(&self, node: Node, timeout_ms: u64) -> Result<GarlemliaMessage, MessageError> {
        self.recv_from_reserved_channel(node.address, timeout_ms)
            .await
    }

    fn clone_box(&self) -> Box<dyn GarlemliaMessenger> {
        Box::new(self.clone())
    }
}
