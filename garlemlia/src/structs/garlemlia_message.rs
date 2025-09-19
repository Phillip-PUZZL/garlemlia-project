use std::collections::HashMap;
use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use async_trait::async_trait;
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;
use crate::file_utils::garlemlia_files::FileInfo;
use crate::structs::error::MessageError;
use crate::structs::file_chunks::{ChunkPartInfo, FileChunkInfo, ProxyChunkPartInfo, ProxyFileChunkInfo};
use crate::structs::garlemlia_data::GarlemliaData;
use crate::structs::garlic_message::{CloveRequestID, GarlicMessage};
use crate::structs::node::Node;
use crate::time_hash::time_based_hash::{HashLocation, RotatingHash};

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
    fn create(channel_count: u8) -> Box<dyn GMessage> where Self: Sized;
    async fn send_tx(&self, addr: SocketAddr, msg: MessageChannel) -> Result<(), MessageError>;
    async fn send_no_recv(&self, socket: &UdpSocket, from_node: Node, target: &SocketAddr, msg: &GarlemliaMessage) -> Result<Option<GarlemliaMessage>, MessageError>;
    async fn send(&self, socket: &UdpSocket, from_node: Node, target: &SocketAddr, msg: &GarlemliaMessage) -> Result<Option<GarlemliaMessage>, MessageError>;
    async fn recv(&self, timeout_ms: u64, src: &SocketAddr) -> Result<GarlemliaMessage, MessageError>;
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
            None => {
                Err(MessageError::NoTX)
            }
        }
    }

    /// Function to send a message without mapping rx / tx channels
    async fn send_no_recv(&self, socket: &UdpSocket, _from_node: Node, target: &SocketAddr, msg: &GarlemliaMessage) -> Result<Option<GarlemliaMessage>, MessageError> {
        // Now actually send the UDP message
        let bytes = serde_json::to_vec(msg)
            .map_err(|e| MessageError::SerializationError(e.to_string()))?;
        socket.send_to(&bytes, target).await?;
        Ok(None)
    }

    /// Takes an RX/TX from the “available” pool, assigns it to the `target`, and sends the given message.
    async fn send(&self, socket: &UdpSocket, _from_node: Node, target: &SocketAddr, msg: &GarlemliaMessage) -> Result<Option<GarlemliaMessage>, MessageError> {
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
                    self.unavailable_rx.lock().await.insert(target.to_string(), receiver);
                    self.unavailable_tx.lock().await.insert(target.to_string(), sender);
                } else {
                    println!("Error: Could not find a matching TX for RX ID {}", receiver.id);
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
                    self.unavailable_rx.lock().await.insert(target.to_string(), receiver);
                    self.unavailable_tx.lock().await.insert(target.to_string(), sender);
                } else {
                    println!("Error: Could not find a matching TX for RX ID {}", receiver.id);
                }
            }
        }

        println!("Sent to {}", target);

        // Now actually send the UDP message
        let bytes = serde_json::to_vec(msg)
            .map_err(|e| MessageError::SerializationError(e.to_string()))?;
        socket.send_to(&bytes, target).await?;
        Ok(None)
    }

    /// Receives a message from the “unavailable” RX assigned to `src`, then returns that RX/TX pair to the pool.
    async fn recv(&self, timeout_ms: u64, src: &SocketAddr) -> Result<GarlemliaMessage, MessageError> {
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

/// Struct containing the preliminary chunk information for a file
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InitialChunkInfo {
    pub index: usize,
    pub chunk_id: U256,
    pub size: usize
}

/// Enum containing requests for storing content
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum GarlemliaStoreRequest {
    Value { id: U256, value: String },
    Validator { id: U256, proxy_id: U256 },
    FileName { id: U256, name: String, file_type: String, size: usize, categories: Vec<String>, metadata_location: RotatingHash, key_location: RotatingHash },
    MetaData { id: U256, file_id: U256, chunk_info: Vec<InitialChunkInfo>, downloads: usize, availability: f64, metadata_location: RotatingHash },
    FileKey { id: U256, enc_file_id: U256, decryption_key: String, key_location: RotatingHash },
    FileChunkInfo { id: U256, request_id: U256, chunk_size: usize, parts_count: usize },
    FileChunkPart { id: U256, index: usize, part_size: usize, data: Vec<u8> }
}

impl GarlemliaStoreRequest {
    pub fn get_id(&self) -> U256 {
        match self {
            GarlemliaStoreRequest::Value { id, .. } => *id,
            GarlemliaStoreRequest::Validator { id, .. } => *id,
            GarlemliaStoreRequest::FileName { id, .. } => *id,
            GarlemliaStoreRequest::MetaData { id, .. } => *id,
            GarlemliaStoreRequest::FileKey { id, .. } => *id,
            GarlemliaStoreRequest::FileChunkInfo { id, .. } => *id,
            GarlemliaStoreRequest::FileChunkPart { id, .. } => *id,
        }
    }

    /// Convert this Store Request into its appropriate data type
    pub fn to_store_data(&self) -> Option<GarlemliaData> {
        match self {
            GarlemliaStoreRequest::Value { id, value } => {
                Some(GarlemliaData::Value {
                    id: id.clone(),
                    value: value.to_string()
                })
            }
            GarlemliaStoreRequest::FileName { id, name, file_type, size, categories, metadata_location, key_location } => {
                Some(GarlemliaData::FileName {
                    id: id.clone(),
                    name: name.clone(),
                    file_type: file_type.clone(),
                    size: size.clone(),
                    categories: categories.clone(),
                    metadata_location: metadata_location.clone(),
                    key_location: key_location.clone()
                })
            }
            GarlemliaStoreRequest::MetaData { id, file_id, chunk_info, downloads, availability, metadata_location } => {
                Some(GarlemliaData::MetaData {
                    id: id.clone(),
                    file_id: file_id.clone(),
                    chunk_info: chunk_info.clone(),
                    downloads: downloads.clone(),
                    availability: availability.clone(),
                    metadata_location: metadata_location.clone()
                })
            }
            GarlemliaStoreRequest::FileKey { id, enc_file_id, decryption_key, key_location } => {
                Some(GarlemliaData::FileKey {
                    id: id.clone(),
                    enc_file_id: enc_file_id.clone(),
                    decryption_key: decryption_key.clone(),
                    key_location: key_location.clone()
                })
            }
            GarlemliaStoreRequest::FileChunkInfo { id, chunk_size, .. } => {
                Some(GarlemliaData::FileChunk {
                    id: id.clone(),
                    size: chunk_size.clone()
                })
            }
            _ => {
                None
            }
        }
    }

    /// Get the proxy_id of a validator peer from the request
    pub fn validator_get_proxy_id(&self) -> Option<U256> {
        match self {
            GarlemliaStoreRequest::Validator { proxy_id, .. } => Some(*proxy_id),
            _ => None
        }
    }

    /// Check if this is a validator store request
    pub fn is_validator(&self) -> bool {
        match self {
            GarlemliaStoreRequest::Validator { .. } => true,
            _ => false
        }
    }

    /// Get the chunk part data from the request
    pub fn get_chunk_part_data(&self) -> Option<Vec<u8>> {
        match self {
            GarlemliaStoreRequest::FileChunkPart { data, .. } => Some(data.clone()),
            _ => None
        }
    }

    /// Get the chunk part index from the request
    pub fn get_chunk_part_index(&self) -> Option<usize> {
        match self {
            GarlemliaStoreRequest::FileChunkPart { index, .. } => Some(index.clone()),
            _ => None
        }
    }

    /// Get the file chunk info from the request
    pub fn get_file_chunk_info(&self) -> Option<FileChunkInfo> {
        match self {
            GarlemliaStoreRequest::FileChunkInfo { id, request_id, chunk_size, parts_count } => {
                Some(FileChunkInfo {
                    request_id: request_id.clone(),
                    chunk_id: id.clone(),
                    chunk_size: chunk_size.clone(),
                    parts_count: parts_count.clone(),
                    parts_info: vec![],
                })
            }
            _ => None
        }
    }

    /// Get the chunk part info from the request
    pub fn get_chunk_part_info(&self) -> Option<ChunkPartInfo> {
        match self {
            GarlemliaStoreRequest::FileChunkPart { part_size, index, .. } => {
                Some(ChunkPartInfo {
                    index: index.clone(),
                    size: part_size.clone()
                })
            }
            _ => None
        }
    }

    /// Get the chunk part info from the request, this is a proxy so we want the data as well
    /// since we don't store it on the disk
    pub fn get_proxy_chunk_part_info(&self) -> Option<ProxyChunkPartInfo> {
        match self {
            GarlemliaStoreRequest::FileChunkPart { part_size, index, data, .. } => {
                Some(ProxyChunkPartInfo {
                    index: index.clone(),
                    size: part_size.clone(),
                    data: data.clone()
                })
            }
            _ => None
        }
    }

    /// Check if this is a chunk part
    pub fn is_chunk_part(&self) -> bool {
        match self {
            GarlemliaStoreRequest::FileChunkPart { .. } => true,
            _ => false
        }
    }

    /// Check if this is the chunk info
    pub fn is_chunk_info(&self) -> bool {
        match self {
            GarlemliaStoreRequest::FileChunkInfo { .. } => true,
            _ => false
        }
    }
}

/// Enum containing request information for searches
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum GarlemliaFindRequest {
    Key { id: U256, request_id: U256 },
    Validator { id: U256, proxy_id: U256 }
}

impl GarlemliaFindRequest {
    pub fn get_id(&self) -> U256 {
        match self {
            GarlemliaFindRequest::Key { id, .. } => *id,
            GarlemliaFindRequest::Validator { id, .. } => *id,
        }
    }

    pub fn get_request_id(&self) -> Option<U256> {
        match self {
            GarlemliaFindRequest::Key { request_id, .. } => Some(*request_id),
            _ => None
        }
    }
}

/// Enum containing response information
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum GarlemliaResponse {
    Value { value: String },
    Validator { proxy: Option<SocketAddr> },
    FileName { name: String, file_type: String, size: usize, categories: Vec<String>, metadata_location: Vec<HashLocation>, key_location: Vec<HashLocation> },
    MetaData { file_id: U256, chunk_info: Vec<InitialChunkInfo>, downloads: usize, availability: f64 },
    FileKey { enc_file_id: U256, decryption_key: String },
    ChunkPart { request_id: U256, chunk_id: U256, part_size: usize, index: usize, data: Vec<u8> },
    ChunkPartInfo { chunk_id: U256, part_size: usize, index: usize },
    FileChunkInfo { request_id: U256, chunk_id: U256, chunk_size: usize, parts_count: usize, sender: Node }
}

impl GarlemliaResponse {
    /// If the response is for file information, it adds that information to the respective
    /// area in a FileInfo struct
    pub fn add_to_file_information(&self, mut file_info: FileInfo) -> Option<FileInfo> {
        match self {
            GarlemliaResponse::MetaData { file_id, chunk_info, .. } => {
                file_info.set_file_id(file_id.clone());
                file_info.set_chunk_info(chunk_info.clone());

                Some(file_info)
            }
            GarlemliaResponse::FileKey { enc_file_id, decryption_key } => {
                file_info.set_enc_file_id(enc_file_id.clone());
                file_info.set_decryption_key(decryption_key.clone());

                Some(file_info)
            }
            GarlemliaResponse::FileChunkInfo { chunk_id, .. } => {
                file_info.add_downloaded(chunk_id.clone());

                Some(file_info)
            }
            _ => {
                None
            }
        }
    }

    /// Check if this is file info
    pub fn is_file_chunk_info(&self) -> bool {
        match self {
            GarlemliaResponse::FileChunkInfo { .. } => true,
            _ => false
        }
    }

    /// Check if this is a chunk part
    pub fn is_chunk_part(&self) -> bool {
        match self {
            GarlemliaResponse::ChunkPart { .. } => true,
            _ => false
        }
    }

    /// Check if this is chunk part info
    pub fn is_chunk_part_info(&self) -> bool {
        match self {
            GarlemliaResponse::ChunkPartInfo { .. } => true,
            _ => false
        }
    }

    /// Get chunk ID if this is file info related
    pub fn get_chunk_id(&self) -> Option<U256> {
        match self {
            GarlemliaResponse::FileChunkInfo { chunk_id, .. } => Some(*chunk_id),
            GarlemliaResponse::ChunkPart { chunk_id, .. } => Some(*chunk_id),
            GarlemliaResponse::ChunkPartInfo { chunk_id, .. } => Some(*chunk_id),
            _ => None
        }
    }

    /// Get request ID from response
    pub fn get_request_id(&self) -> Option<U256> {
        match self {
            GarlemliaResponse::FileChunkInfo { request_id, .. } => Some(*request_id),
            GarlemliaResponse::ChunkPart { request_id, .. } => Some(*request_id),
            _ => None
        }
    }

    /// Get the index of a chunk part response
    pub fn get_chunk_part_index(&self) -> Option<usize> {
        match self {
            GarlemliaResponse::ChunkPart { index, .. } => Some(*index),
            GarlemliaResponse::ChunkPartInfo { index, .. } => Some(*index),
            _ => None
        }
    }

    /// Return the information from a chunk info response
    pub fn get_file_chunk_info(&self) -> Option<FileChunkInfo> {
        match self {
            GarlemliaResponse::FileChunkInfo { request_id, chunk_id, chunk_size, parts_count, .. } => {
                Some(FileChunkInfo {
                    request_id: request_id.clone(),
                    chunk_id: chunk_id.clone(),
                    chunk_size: chunk_size.clone(),
                    parts_count: parts_count.clone(),
                    parts_info: vec![],
                })
            }
            _ => None
        }
    }

    /// Return the information from a chunk info response as a proxy
    pub fn get_proxy_file_chunk_info(&self) -> Option<ProxyFileChunkInfo> {
        match self {
            GarlemliaResponse::FileChunkInfo { request_id, chunk_id, chunk_size, parts_count, .. } => {
                Some(ProxyFileChunkInfo {
                    request_id: request_id.clone(),
                    chunk_id: chunk_id.clone(),
                    chunk_size: chunk_size.clone(),
                    parts_count: parts_count.clone(),
                    parts_info: vec![],
                })
            }
            _ => None
        }
    }

    /// Get the chunk part / part info from a response
    pub fn get_chunk_part_info(&self) -> Option<ChunkPartInfo> {
        match self {
            GarlemliaResponse::ChunkPart { part_size, index, .. } => {
                Some(ChunkPartInfo {
                    index: index.clone(),
                    size: part_size.clone()
                })
            }
            GarlemliaResponse::ChunkPartInfo { part_size, index, .. } => {
                Some(ChunkPartInfo {
                    index: index.clone(),
                    size: part_size.clone()
                })
            }
            _ => None
        }
    }

    /// Get the chunk part as a proxy
    pub fn get_proxy_chunk_part_info(&self) -> Option<ProxyChunkPartInfo> {
        match self {
            GarlemliaResponse::ChunkPart { part_size, index, data, .. } => {
                Some(ProxyChunkPartInfo {
                    index: index.clone(),
                    size: part_size.clone(),
                    data: data.clone()
                })
            }
            _ => None
        }
    }

    /// Pull out just the chunk part data from the response
    pub fn get_chunk_part_data(&self) -> Option<Vec<u8>> {
        match self {
            GarlemliaResponse::ChunkPart { data, .. } => Some(data.clone()),
            _ => None
        }
    }
}

/// Enum containing information for the overarching Garlemlia Message
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum GarlemliaMessage {
    FindNode { id: U256, sender: Node },
    Store { key: U256, value: GarlemliaStoreRequest, sender: Node },
    FindValue { request: GarlemliaFindRequest, sender: Node },
    Response { nodes: Vec<Node>, value: Option<GarlemliaResponse>, sender: Node },
    Garlic { msg: GarlicMessage, sender: Node },
    Ping { sender: Node },
    Pong { sender: Node },
    SearchFile { request_id: CloveRequestID, proxy_id: U256, search_term: String, public_key: String, sender: Node, ttl: u8 },
    DownloadFileChunk { request: GarlemliaFindRequest, sender: Node },
    AgreeAlt { alt_sequence_number: U256, sender: Node },
    Stop { }
}

impl GarlemliaMessage {
    pub fn sender_id(&self) -> U256 {
        match self {
            GarlemliaMessage::FindNode { sender, .. } => sender.id.clone(),
            GarlemliaMessage::Store { sender, .. } => sender.id.clone(),
            GarlemliaMessage::FindValue { sender, .. } => sender.id.clone(),
            GarlemliaMessage::Response { sender, .. } => sender.id.clone(),
            GarlemliaMessage::Garlic { sender, .. } => sender.id.clone(),
            GarlemliaMessage::Ping { sender} => sender.id.clone(),
            GarlemliaMessage::Pong { sender, .. } => sender.id.clone(),
            GarlemliaMessage::SearchFile { sender, ..} => sender.id.clone(),
            GarlemliaMessage::DownloadFileChunk { sender, .. } => sender.id.clone(),
            GarlemliaMessage::AgreeAlt { sender, .. } => sender.id.clone(),
            GarlemliaMessage::Stop {} => U256::from(0)
        }
    }

    pub fn sender(&self) -> Option<Node> {
        match self {
            GarlemliaMessage::FindNode { sender, .. } => Some(sender.clone()),
            GarlemliaMessage::Store { sender, .. } => Some(sender.clone()),
            GarlemliaMessage::FindValue { sender, .. } => Some(sender.clone()),
            GarlemliaMessage::Response { sender, .. } => Some(sender.clone()),
            GarlemliaMessage::Garlic { sender, .. } => Some(sender.clone()),
            GarlemliaMessage::Ping { sender} => Some(sender.clone()),
            GarlemliaMessage::Pong { sender, .. } => Some(sender.clone()),
            GarlemliaMessage::SearchFile { sender, ..} => Some(sender.clone()),
            GarlemliaMessage::DownloadFileChunk { sender, .. } => Some(sender.clone()),
            GarlemliaMessage::AgreeAlt { sender, .. } => Some(sender.clone()),
            GarlemliaMessage::Stop {} => None
        }
    }
}