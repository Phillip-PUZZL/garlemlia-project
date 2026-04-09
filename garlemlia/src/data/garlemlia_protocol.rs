use super::file_chunks::{ChunkPartInfo, FileChunkInfo, ProxyChunkPartInfo, ProxyFileChunkInfo};
use super::garlemlia_data::GarlemliaData;
use crate::files::file_info::FileInfo;
use crate::garlic::protocol::clove::CloveRequestID;
use crate::garlic::protocol::garlic_message::GarlicMessage;
use crate::net::node::Node;
use crate::time::time_based_hash::{HashLocation, RotatingHash};
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::net::SocketAddr;

/// Struct containing the preliminary chunk information for a file
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InitialChunkInfo {
    pub index: usize,
    pub chunk_id: U256,
    pub size: usize,
}

/// Enum containing requests for storing content
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum GarlemliaStoreRequest {
    Value {
        id: U256,
        value: String,
    },
    Validator {
        id: U256,
        proxy_id: U256,
    },
    FileName {
        id: U256,
        name: String,
        file_type: String,
        size: usize,
        categories: Vec<String>,
        metadata_location: RotatingHash,
        key_location: RotatingHash,
    },
    MetaData {
        id: U256,
        file_id: U256,
        chunk_info: Vec<InitialChunkInfo>,
        downloads: usize,
        availability: f64,
        metadata_location: RotatingHash,
    },
    FileKey {
        id: U256,
        enc_file_id: U256,
        decryption_key: String,
        key_location: RotatingHash,
    },
    FileChunkInfo {
        id: U256,
        request_id: U256,
        chunk_size: usize,
        parts_count: usize,
    },
    FileChunkPart {
        id: U256,
        index: usize,
        part_size: usize,
        data: Vec<u8>,
    },
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
            GarlemliaStoreRequest::Value { id, value } => Some(GarlemliaData::Value {
                id: id.clone(),
                value: value.to_string(),
            }),
            GarlemliaStoreRequest::FileName {
                id,
                name,
                file_type,
                size,
                categories,
                metadata_location,
                key_location,
            } => Some(GarlemliaData::FileName {
                id: id.clone(),
                name: name.clone(),
                file_type: file_type.clone(),
                size: size.clone(),
                categories: categories.clone(),
                metadata_location: metadata_location.clone(),
                key_location: key_location.clone(),
            }),
            GarlemliaStoreRequest::MetaData {
                id,
                file_id,
                chunk_info,
                downloads,
                availability,
                metadata_location,
            } => Some(GarlemliaData::MetaData {
                id: id.clone(),
                file_id: file_id.clone(),
                chunk_info: chunk_info.clone(),
                downloads: downloads.clone(),
                availability: availability.clone(),
                metadata_location: metadata_location.clone(),
            }),
            GarlemliaStoreRequest::FileKey {
                id,
                enc_file_id,
                decryption_key,
                key_location,
            } => Some(GarlemliaData::FileKey {
                id: id.clone(),
                enc_file_id: enc_file_id.clone(),
                decryption_key: decryption_key.clone(),
                key_location: key_location.clone(),
            }),
            GarlemliaStoreRequest::FileChunkInfo { id, chunk_size, .. } => {
                Some(GarlemliaData::FileChunk {
                    id: id.clone(),
                    size: chunk_size.clone(),
                })
            }
            _ => None,
        }
    }

    /// Get the proxy_id of a validator peer from the request
    pub fn validator_get_proxy_id(&self) -> Option<U256> {
        match self {
            GarlemliaStoreRequest::Validator { proxy_id, .. } => Some(*proxy_id),
            _ => None,
        }
    }

    /// Check if this is a validator store request
    pub fn is_validator(&self) -> bool {
        match self {
            GarlemliaStoreRequest::Validator { .. } => true,
            _ => false,
        }
    }

    /// Get the chunk part data from the request
    pub fn get_chunk_part_data(&self) -> Option<Vec<u8>> {
        match self {
            GarlemliaStoreRequest::FileChunkPart { data, .. } => Some(data.clone()),
            _ => None,
        }
    }

    /// Get the chunk part index from the request
    pub fn get_chunk_part_index(&self) -> Option<usize> {
        match self {
            GarlemliaStoreRequest::FileChunkPart { index, .. } => Some(index.clone()),
            _ => None,
        }
    }

    /// Get the file chunk info from the request
    pub fn get_file_chunk_info(&self) -> Option<FileChunkInfo> {
        match self {
            GarlemliaStoreRequest::FileChunkInfo {
                id,
                request_id,
                chunk_size,
                parts_count,
            } => Some(FileChunkInfo {
                request_id: request_id.clone(),
                chunk_id: id.clone(),
                chunk_size: chunk_size.clone(),
                parts_count: parts_count.clone(),
                parts_info: vec![],
            }),
            _ => None,
        }
    }

    /// Get the chunk part info from the request
    pub fn get_chunk_part_info(&self) -> Option<ChunkPartInfo> {
        match self {
            GarlemliaStoreRequest::FileChunkPart {
                part_size, index, ..
            } => Some(ChunkPartInfo {
                index: index.clone(),
                size: part_size.clone(),
            }),
            _ => None,
        }
    }

    /// Get the chunk part info from the request, this is a proxy so we want the data as well
    /// since we don't store it on the disk
    pub fn get_proxy_chunk_part_info(&self) -> Option<ProxyChunkPartInfo> {
        match self {
            GarlemliaStoreRequest::FileChunkPart {
                part_size,
                index,
                data,
                ..
            } => Some(ProxyChunkPartInfo {
                index: index.clone(),
                size: part_size.clone(),
                data: data.clone(),
            }),
            _ => None,
        }
    }

    /// Check if this is a chunk part
    pub fn is_chunk_part(&self) -> bool {
        match self {
            GarlemliaStoreRequest::FileChunkPart { .. } => true,
            _ => false,
        }
    }

    /// Check if this is the chunk info
    pub fn is_chunk_info(&self) -> bool {
        match self {
            GarlemliaStoreRequest::FileChunkInfo { .. } => true,
            _ => false,
        }
    }
}

/// Enum containing request information for searches
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum GarlemliaFindRequest {
    Key { id: U256, request_id: U256 },
    Validator { id: U256, proxy_id: U256 },
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
            _ => None,
        }
    }
}

/// Enum containing response information
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum GarlemliaResponse {
    Value {
        value: String,
    },
    Validator {
        proxy: Option<SocketAddr>,
    },
    FileName {
        name: String,
        file_type: String,
        size: usize,
        categories: Vec<String>,
        metadata_location: Vec<HashLocation>,
        key_location: Vec<HashLocation>,
    },
    MetaData {
        file_id: U256,
        chunk_info: Vec<InitialChunkInfo>,
        downloads: usize,
        availability: f64,
    },
    FileKey {
        enc_file_id: U256,
        decryption_key: String,
    },
    ChunkPart {
        request_id: U256,
        chunk_id: U256,
        part_size: usize,
        index: usize,
        data: Vec<u8>,
    },
    ChunkPartInfo {
        chunk_id: U256,
        part_size: usize,
        index: usize,
    },
    FileChunkInfo {
        request_id: U256,
        chunk_id: U256,
        chunk_size: usize,
        parts_count: usize,
        sender: Node,
    },
}

impl GarlemliaResponse {
    /// If the response is for file information, it adds that information to the respective
    /// area in a FileInfo struct
    pub fn add_to_file_information(&self, mut file_info: FileInfo) -> Option<FileInfo> {
        match self {
            GarlemliaResponse::MetaData {
                file_id,
                chunk_info,
                ..
            } => {
                file_info.set_file_id(file_id.clone());
                file_info.set_chunk_info(chunk_info.clone());

                Some(file_info)
            }
            GarlemliaResponse::FileKey {
                enc_file_id,
                decryption_key,
            } => {
                file_info.set_enc_file_id(enc_file_id.clone());
                file_info.set_decryption_key(decryption_key.clone());

                Some(file_info)
            }
            GarlemliaResponse::FileChunkInfo { chunk_id, .. } => {
                file_info.add_downloaded(chunk_id.clone());

                Some(file_info)
            }
            _ => None,
        }
    }

    /// Check if this is file info
    pub fn is_file_chunk_info(&self) -> bool {
        match self {
            GarlemliaResponse::FileChunkInfo { .. } => true,
            _ => false,
        }
    }

    /// Check if this is a chunk part
    pub fn is_chunk_part(&self) -> bool {
        match self {
            GarlemliaResponse::ChunkPart { .. } => true,
            _ => false,
        }
    }

    /// Check if this is chunk part info
    pub fn is_chunk_part_info(&self) -> bool {
        match self {
            GarlemliaResponse::ChunkPartInfo { .. } => true,
            _ => false,
        }
    }

    /// Get chunk ID if this is file info related
    pub fn get_chunk_id(&self) -> Option<U256> {
        match self {
            GarlemliaResponse::FileChunkInfo { chunk_id, .. } => Some(*chunk_id),
            GarlemliaResponse::ChunkPart { chunk_id, .. } => Some(*chunk_id),
            GarlemliaResponse::ChunkPartInfo { chunk_id, .. } => Some(*chunk_id),
            _ => None,
        }
    }

    /// Get request ID from response
    pub fn get_request_id(&self) -> Option<U256> {
        match self {
            GarlemliaResponse::FileChunkInfo { request_id, .. } => Some(*request_id),
            GarlemliaResponse::ChunkPart { request_id, .. } => Some(*request_id),
            _ => None,
        }
    }

    /// Get the index of a chunk part response
    pub fn get_chunk_part_index(&self) -> Option<usize> {
        match self {
            GarlemliaResponse::ChunkPart { index, .. } => Some(*index),
            GarlemliaResponse::ChunkPartInfo { index, .. } => Some(*index),
            _ => None,
        }
    }

    /// Return the information from a chunk info response
    pub fn get_file_chunk_info(&self) -> Option<FileChunkInfo> {
        match self {
            GarlemliaResponse::FileChunkInfo {
                request_id,
                chunk_id,
                chunk_size,
                parts_count,
                ..
            } => Some(FileChunkInfo {
                request_id: request_id.clone(),
                chunk_id: chunk_id.clone(),
                chunk_size: chunk_size.clone(),
                parts_count: parts_count.clone(),
                parts_info: vec![],
            }),
            _ => None,
        }
    }

    /// Return the information from a chunk info response as a proxy
    pub fn get_proxy_file_chunk_info(&self) -> Option<ProxyFileChunkInfo> {
        match self {
            GarlemliaResponse::FileChunkInfo {
                request_id,
                chunk_id,
                chunk_size,
                parts_count,
                ..
            } => Some(ProxyFileChunkInfo {
                request_id: request_id.clone(),
                chunk_id: chunk_id.clone(),
                chunk_size: chunk_size.clone(),
                parts_count: parts_count.clone(),
                parts_info: vec![],
            }),
            _ => None,
        }
    }

    /// Get the chunk part / part info from a response
    pub fn get_chunk_part_info(&self) -> Option<ChunkPartInfo> {
        match self {
            GarlemliaResponse::ChunkPart {
                part_size, index, ..
            } => Some(ChunkPartInfo {
                index: index.clone(),
                size: part_size.clone(),
            }),
            GarlemliaResponse::ChunkPartInfo {
                part_size, index, ..
            } => Some(ChunkPartInfo {
                index: index.clone(),
                size: part_size.clone(),
            }),
            _ => None,
        }
    }

    /// Get the chunk part as a proxy
    pub fn get_proxy_chunk_part_info(&self) -> Option<ProxyChunkPartInfo> {
        match self {
            GarlemliaResponse::ChunkPart {
                part_size,
                index,
                data,
                ..
            } => Some(ProxyChunkPartInfo {
                index: index.clone(),
                size: part_size.clone(),
                data: data.clone(),
            }),
            _ => None,
        }
    }

    /// Pull out just the chunk part data from the response
    pub fn get_chunk_part_data(&self) -> Option<Vec<u8>> {
        match self {
            GarlemliaResponse::ChunkPart { data, .. } => Some(data.clone()),
            _ => None,
        }
    }
}

/// Enum containing information for the overarching Garlemlia Message
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum GarlemliaMessage {
    FindNode {
        id: U256,
        sender: Node,
    },
    Store {
        key: U256,
        value: GarlemliaStoreRequest,
        sender: Node,
    },
    FindValue {
        request: GarlemliaFindRequest,
        sender: Node,
    },
    Response {
        nodes: Vec<Node>,
        value: Option<GarlemliaResponse>,
        sender: Node,
    },
    Garlic {
        msg: GarlicMessage,
        sender: Node,
    },
    Ping {
        sender: Node,
    },
    Pong {
        sender: Node,
    },
    SearchFile {
        request_id: CloveRequestID,
        proxy_id: U256,
        search_term: String,
        public_key: String,
        sender: Node,
        ttl: u8,
    },
    DownloadFileChunk {
        request: GarlemliaFindRequest,
        sender: Node,
    },
    AgreeAlt {
        alt_sequence_number: U256,
        sender: Node,
    },
    Stop {},
}

impl GarlemliaMessage {
    pub fn sender_id(&self) -> U256 {
        match self {
            GarlemliaMessage::FindNode { sender, .. } => sender.id.clone(),
            GarlemliaMessage::Store { sender, .. } => sender.id.clone(),
            GarlemliaMessage::FindValue { sender, .. } => sender.id.clone(),
            GarlemliaMessage::Response { sender, .. } => sender.id.clone(),
            GarlemliaMessage::Garlic { sender, .. } => sender.id.clone(),
            GarlemliaMessage::Ping { sender } => sender.id.clone(),
            GarlemliaMessage::Pong { sender, .. } => sender.id.clone(),
            GarlemliaMessage::SearchFile { sender, .. } => sender.id.clone(),
            GarlemliaMessage::DownloadFileChunk { sender, .. } => sender.id.clone(),
            GarlemliaMessage::AgreeAlt { sender, .. } => sender.id.clone(),
            GarlemliaMessage::Stop {} => U256::from(0),
        }
    }

    pub fn sender(&self) -> Option<Node> {
        match self {
            GarlemliaMessage::FindNode { sender, .. } => Some(sender.clone()),
            GarlemliaMessage::Store { sender, .. } => Some(sender.clone()),
            GarlemliaMessage::FindValue { sender, .. } => Some(sender.clone()),
            GarlemliaMessage::Response { sender, .. } => Some(sender.clone()),
            GarlemliaMessage::Garlic { sender, .. } => Some(sender.clone()),
            GarlemliaMessage::Ping { sender } => Some(sender.clone()),
            GarlemliaMessage::Pong { sender, .. } => Some(sender.clone()),
            GarlemliaMessage::SearchFile { sender, .. } => Some(sender.clone()),
            GarlemliaMessage::DownloadFileChunk { sender, .. } => Some(sender.clone()),
            GarlemliaMessage::AgreeAlt { sender, .. } => Some(sender.clone()),
            GarlemliaMessage::Stop {} => None,
        }
    }
}
