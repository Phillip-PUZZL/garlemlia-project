use crate::core::error::MessageError;
use crate::data::garlemlia_protocol::GarlemliaMessage;
use crate::net::node::Node;
use async_trait::async_trait;
use primitive_types::U256;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;

/// A simple channel message that carries identifying information.
#[derive(Debug, Clone)]
pub struct MessageChannel {
    pub node_id: U256,
    pub msg: GarlemliaMessage,
}

/// We want this trait so that the message handler can be used as a "hook" for a simulator
/// to process messages without sending over IP
#[async_trait]
pub trait GMessage: Send + Sync {
    fn create(channel_count: u8) -> Box<dyn GMessage>
    where
        Self: Sized;
    async fn send_tx(&self, addr: SocketAddr, msg: MessageChannel) -> Result<(), MessageError>;
    async fn send_no_recv(
        &self,
        socket: &UdpSocket,
        from_node: Node,
        target: &SocketAddr,
        msg: &GarlemliaMessage,
    ) -> Result<Option<GarlemliaMessage>, MessageError>;
    async fn send(
        &self,
        socket: &UdpSocket,
        from_node: Node,
        target: &SocketAddr,
        msg: &GarlemliaMessage,
    ) -> Result<Option<GarlemliaMessage>, MessageError>;
    async fn recv(
        &self,
        timeout_ms: u64,
        src: &SocketAddr,
    ) -> Result<GarlemliaMessage, MessageError>;
    fn clone_box(&self) -> Box<dyn GMessage>;

    fn debug_fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "GMessage Trait Object")
    }
}

impl Clone for Box<dyn GMessage> {
    fn clone(&self) -> Box<dyn GMessage> {
        self.clone_box()
    }
}

impl Debug for dyn GMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        self.debug_fmt(f)
    }
}

/// Struct containing a MessageChannel used for receiving communications across threads
#[derive(Debug, Clone)]
pub struct HandlerChannelReceiver {
    id: u8,
    rx: Arc<Mutex<UnboundedReceiver<MessageChannel>>>,
}

/// Struct containing a MessageChannel used for sending communications across threads
#[derive(Debug, Clone)]
pub struct HandlerChannelSender {
    id: u8,
    pub tx: Arc<Mutex<UnboundedSender<MessageChannel>>>,
}

/// Struct containing the available and unavailable send / receive channels
#[derive(Debug, Default, Clone)]
pub struct GarlemliaMessageHandler {
    available_rx: Arc<Mutex<Vec<HandlerChannelReceiver>>>,
    unavailable_rx: Arc<Mutex<HashMap<String, HandlerChannelReceiver>>>,
    available_tx: Arc<Mutex<Vec<HandlerChannelSender>>>,
    unavailable_tx: Arc<Mutex<HashMap<String, HandlerChannelSender>>>,
}

#[async_trait]
impl GMessage for GarlemliaMessageHandler {
    fn create(channel_count: u8) -> Box<dyn GMessage> {
        // Build up our “available” pools:
        let mut rx_pool = Vec::with_capacity(channel_count as usize);
        let mut tx_pool = Vec::with_capacity(channel_count as usize);

        // Loop through to channel count
        for i in 0..channel_count {
            // Generate tx and rx
            let (tx, rx) = mpsc::unbounded_channel::<MessageChannel>();
            // Add tx and rx to rx and tx pools
            rx_pool.push(HandlerChannelReceiver {
                id: i,
                rx: Arc::new(Mutex::new(rx)),
            });
            tx_pool.push(HandlerChannelSender {
                id: i,
                tx: Arc::new(Mutex::new(tx)),
            });
        }

        // Initialize pools
        Box::new(GarlemliaMessageHandler {
            available_rx: Arc::new(Mutex::new(rx_pool)),
            available_tx: Arc::new(Mutex::new(tx_pool)),
            unavailable_rx: Arc::new(Mutex::new(HashMap::new())),
            unavailable_tx: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Look up the “unavailable” TX for this address. (i.e., a TX currently assigned to that address)
    async fn send_tx(&self, addr: SocketAddr, msg: MessageChannel) -> Result<(), MessageError> {
        // Get tx from mapped address
        let map = self.unavailable_tx.lock().await;
        let tx_info = map.get(&addr.to_string());

        // Verify tx channel exists
        match tx_info {
            Some(tx_good) => {
                // Lock tx channel
                let tx = tx_good.tx.lock().await;
                // Verify not closed
                if tx.is_closed() {
                    Err(MessageError::TXDropped)
                } else {
                    // Send to rx
                    let send_info = tx.send(msg);

                    // Verify tx sent
                    if send_info.is_err() {
                        Err(MessageError::TXSendError)
                    } else {
                        Ok(())
                    }
                }
            }
            None => Err(MessageError::NoTX),
        }
    }

    /// Function to send a message without mapping rx / tx channels
    async fn send_no_recv(
        &self,
        socket: &UdpSocket,
        _from_node: Node,
        target: &SocketAddr,
        msg: &GarlemliaMessage,
    ) -> Result<Option<GarlemliaMessage>, MessageError> {
        // Now actually send the UDP message
        let bytes =
            serde_json::to_vec(msg).map_err(|e| MessageError::SerializationError(e.to_string()))?;
        socket.send_to(&bytes, target).await?;
        Ok(None)
    }

    /// Takes an RX/TX from the “available” pool, assigns it to the `target`, and sends the given message.
    async fn send(
        &self,
        socket: &UdpSocket,
        _from_node: Node,
        target: &SocketAddr,
        msg: &GarlemliaMessage,
    ) -> Result<Option<GarlemliaMessage>, MessageError> {
        let mut need_rx = true;

        // Try once outside the loop
        {
            let mut rx_pool = self.available_rx.lock().await;
            // Attempt to get a rx channel from the pool
            if !rx_pool.is_empty() {
                need_rx = false;
                let mut tx_pool = self.available_tx.lock().await;

                // Pop one receiver
                let receiver = rx_pool.pop().unwrap();
                // Find a matching TX with the same ID
                if let Some(index) = tx_pool.iter().position(|tx| tx.id == receiver.id) {
                    let sender = tx_pool.remove(index);

                    // Move them to “unavailable”
                    println!("Setting used RX/TX at {}", target.to_string());
                    self.unavailable_rx
                        .lock()
                        .await
                        .insert(target.to_string(), receiver);
                    self.unavailable_tx
                        .lock()
                        .await
                        .insert(target.to_string(), sender);
                } else {
                    println!(
                        "Error: Could not find a matching TX for RX ID {}",
                        receiver.id
                    );
                }
            }
        }

        // If none were available, wait until something is freed
        while need_rx {
            println!("WAITING FOR RX TO BECOME AVAILABLE...");
            tokio::time::sleep(Duration::from_millis(10)).await;

            let mut rx_pool = self.available_rx.lock().await;
            if !rx_pool.is_empty() {
                need_rx = false;
                let mut tx_pool = self.available_tx.lock().await;

                // Pop one receiver
                let receiver = rx_pool.pop().unwrap();
                // Find a matching TX with the same ID
                if let Some(index) = tx_pool.iter().position(|tx| tx.id == receiver.id) {
                    let sender = tx_pool.remove(index);

                    // Move them to “unavailable”
                    println!("Setting used RX/TX at {}", target.to_string());
                    self.unavailable_rx
                        .lock()
                        .await
                        .insert(target.to_string(), receiver);
                    self.unavailable_tx
                        .lock()
                        .await
                        .insert(target.to_string(), sender);
                } else {
                    println!(
                        "Error: Could not find a matching TX for RX ID {}",
                        receiver.id
                    );
                }
            }
        }

        println!("Sent to {}", target);

        // Now actually send the UDP message
        let bytes =
            serde_json::to_vec(msg).map_err(|e| MessageError::SerializationError(e.to_string()))?;
        socket.send_to(&bytes, target).await?;
        Ok(None)
    }

    /// Receives a message from the “unavailable” RX assigned to `src`, then returns that RX/TX pair to the pool.
    async fn recv(
        &self,
        timeout_ms: u64,
        src: &SocketAddr,
    ) -> Result<GarlemliaMessage, MessageError> {
        // Attempt to find the assigned RX for this address
        let maybe_rx = {
            let mut rx_map = self.unavailable_rx.lock().await;
            rx_map.get_mut(&src.to_string()).cloned()
        };

        let channel_receiver = match maybe_rx {
            Some(rx) => rx,
            None => {
                println!("No RX found for address {:?}", src);
                return Err(MessageError::NoRX);
            }
        };

        // Actually receive from that channel with a timeout
        let msg_result = {
            let mut guard = channel_receiver.rx.lock().await;
            match timeout(Duration::from_millis(timeout_ms), guard.recv()).await {
                Ok(Some(msg_channel)) => Ok(msg_channel),
                Ok(None) => Err(MessageError::MissingResponse),
                Err(_) => Err(MessageError::Timeout),
            }
        };

        // Remove the TX from the unavailable set
        let mut tx_map = self.unavailable_tx.lock().await;
        let maybe_tx = tx_map.remove(&src.to_string());

        // Also remove the RX from the unavailable set
        let mut rx_map = self.unavailable_rx.lock().await;
        let maybe_rx2 = rx_map.remove(&src.to_string());

        // Add TX back to available pool
        if let Some(tx) = maybe_tx {
            self.available_tx.lock().await.push(tx);
        } else {
            println!("Warning: Could not find matching TX for {:?}", src);
        }

        // Add RX back to available tool
        if let Some(rx) = maybe_rx2 {
            self.available_rx.lock().await.push(rx);
        } else {
            println!("Warning: Could not find matching RX for {:?}", src);
        }

        // Return the final GarlemliaMessage or an error
        match msg_result {
            Ok(channel) => Ok(channel.msg),
            Err(e) => {
                println!("Error: Did not receive message due to {:?}", e);
                Err(e)
            }
        }
    }

    fn clone_box(&self) -> Box<dyn GMessage> {
        Box::new(self.clone())
    }
}
