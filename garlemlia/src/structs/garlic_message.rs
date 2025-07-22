use chrono::{DateTime, Utc};
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use crate::file_utils::garlemlia_files::{FileStorage, FileUpload};
use crate::helper_functions::helper_functions::u256_random;
use crate::structs::constants::SOCKET_FILE_DATA_MAX;
use crate::structs::garlemlia_message::{InitialChunkInfo, GarlemliaMessage, GarlemliaResponse, GarlemliaStoreRequest};
use crate::structs::node::Node;

/// GARLIC CAST STRUCTS

/// Clove struct containing information for messages which pass through this node
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Clove {
    pub sequence_number: U256,
    pub request_id: CloveRequestID,
    pub msg_fragment: Vec<u8>,
    pub key_fragment: Vec<u8>,
    pub sent: DateTime<Utc>,
    pub index: u8,
    pub ida_count: u8
}

impl Clove {
    pub fn update_sequence(&mut self, new_sequence_number: U256) -> Clove {
        self.sequence_number = new_sequence_number;
        self.clone()
    }
}

/// Association between a clove and its sender
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CloveData {
    pub clove: Clove,
    pub from: Node
}

/// Associating a sequence number with a node
#[derive(Clone, Debug, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub struct CloveNode {
    // The sequence number used when sending to this node
    // Most of the time it will be the chain sequence number, but if it is an alt node
    // then it will be the randomly generated sequence number
    pub sequence_number: U256,
    pub node: Node
}

/// Associate clove message with being a file chunk
#[derive(Clone, Debug)]
pub struct FileCloveMessage {
    pub is_file_chunk: bool,
    pub message: CloveMessage
}

/// Association between a request ID and the index of that clove in the Reed-Solomon erasure code
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct CloveRequestID {
    pub request_id: U256,
    pub index: u64
}

impl CloveRequestID {
    pub fn new(request_id: U256, index: u64) -> CloveRequestID {
        CloveRequestID {
            request_id,
            index,
        }
    }
}

/// Actual Clove Message types
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum CloveMessage {
    RequestProxy {
        msg: String,
        public_key: String,
    },
    ProxyInfo {
        public_key: String,
        starting_hops: u16
    },
    Store {
        request_id: CloveRequestID,
        data: GarlemliaStoreRequest
    },
    SearchOverlay {
        request_id: CloveRequestID,
        proxy_id: U256,
        search_term: String,
        public_key: String,
        ttl: u8
    },
    SearchGarlemlia {
        request_id: CloveRequestID,
        key: U256
    },
    Response {
        request_id: CloveRequestID,
        data: GarlemliaResponse
    },
    ResponseWithValidator {
        request_id: CloveRequestID,
        proxy_id: U256,
        clove_1: Clove,
        clove_2: Clove
    },
    FileChunkPart {
        request_id: CloveRequestID,
        data: GarlemliaResponse
    }
}

impl CloveMessage {
    /// Generate clove messages for file metadata
    pub async fn file_metadata_upload(file_info: FileUpload, request_id: Option<U256>) -> Vec<FileCloveMessage> {
        let mut file_messages = vec![];

        file_messages.push(FileCloveMessage { is_file_chunk: false, message: CloveMessage::Store { request_id: CloveRequestID::new(request_id.unwrap_or(u256_random()), 0), data: GarlemliaStoreRequest::FileName {
            id: file_info.id,
            name: file_info.name,
            file_type: file_info.file_type,
            size: file_info.size,
            categories: file_info.categories,
            metadata_location: file_info.metadata_location.clone(),
            key_location: file_info.key_location.clone()
        }}});
        file_messages.push(FileCloveMessage { is_file_chunk: false, message: CloveMessage::Store { request_id: CloveRequestID::new(request_id.unwrap_or(u256_random()), 1), data: GarlemliaStoreRequest::MetaData {
            id: file_info.metadata_location.get_current().unwrap().id,
            file_id: file_info.file_id,
            chunk_info: file_info.chunks.clone(),
            downloads: 0,
            availability: 1.0,
            metadata_location: file_info.metadata_location
        }}});
        file_messages.push(FileCloveMessage { is_file_chunk: false, message: CloveMessage::Store { request_id: CloveRequestID::new(request_id.unwrap_or(u256_random()), 2), data: GarlemliaStoreRequest::FileKey {
            id: file_info.key_location.get_current().unwrap().id,
            enc_file_id: file_info.enc_file_id,
            decryption_key: file_info.decryption_key,
            key_location: file_info.key_location
        }}});

        file_messages
    }

    /// Generate Clove messages for the actual file chunk data
    pub async fn file_chunk_to_upload(chunk: InitialChunkInfo, file_storage: FileStorage, request_id: Option<U256>) -> Vec<FileCloveMessage> {
        let mut chunk_part_messages = vec![];

        let yeet_request_id = request_id.unwrap_or(u256_random());

        let request_id_index = rand::random::<u64>();

        let mut chunk_data = file_storage.get_temp_chunk(chunk.chunk_id).await.unwrap();
        let part_size = SOCKET_FILE_DATA_MAX;

        let mut parts_file_messages: Vec<FileCloveMessage> = vec![];

        let mut total_parts = 0;
        while chunk_data.len() > 0 {
            let part_data: Vec<u8>;
            if part_size > chunk_data.len() {
                part_data = chunk_data.drain(..).collect();
            } else {
                part_data = chunk_data.drain(0..part_size).collect();
            }

            parts_file_messages.push(FileCloveMessage { is_file_chunk: true, message: CloveMessage::Store { request_id: CloveRequestID::new(yeet_request_id, request_id_index + 1 + total_parts), data: GarlemliaStoreRequest::FileChunkPart {
                id: chunk.chunk_id,
                index: total_parts as usize,
                part_size: part_data.len(),
                data: part_data
            }}});

            total_parts += 1;
        }

        chunk_part_messages.push(FileCloveMessage { is_file_chunk: true, message: CloveMessage::Store { request_id: CloveRequestID::new(yeet_request_id, request_id_index), data: GarlemliaStoreRequest::FileChunkInfo {
            id: chunk.chunk_id,
            request_id: yeet_request_id,
            chunk_size: chunk.size,
            parts_count: total_parts as usize
        }}});

        for item in parts_file_messages {
            chunk_part_messages.push(item);
        }

        chunk_part_messages
    }

    pub fn request_id(&self) -> Option<CloveRequestID> {
        match self {
            CloveMessage::RequestProxy { .. } => {None}
            CloveMessage::ProxyInfo { .. } => {None}
            CloveMessage::Store { request_id, .. } => {Some(request_id.clone())}
            CloveMessage::SearchOverlay { request_id, .. } => {Some(request_id.clone())}
            CloveMessage::SearchGarlemlia { request_id, .. } => {Some(request_id.clone())}
            CloveMessage::Response { request_id, .. } => {Some(request_id.clone())}
            CloveMessage::ResponseWithValidator { request_id, .. } => {Some(request_id.clone())}
            CloveMessage::FileChunkPart { request_id, .. } => {Some(request_id.clone())}
        }
    }

    pub fn proxy_id(&self) -> Option<U256> {
        match self {
            CloveMessage::RequestProxy { .. } => {None}
            CloveMessage::ProxyInfo { .. } => {None}
            CloveMessage::Store { .. } => {None}
            CloveMessage::SearchOverlay { proxy_id, .. } => {Some(proxy_id.clone())}
            CloveMessage::SearchGarlemlia { .. } => {None}
            CloveMessage::Response { .. } => {None}
            CloveMessage::ResponseWithValidator { proxy_id, .. } => {Some(proxy_id.clone())}
            CloveMessage::FileChunkPart { .. } => {None}
        }
    }

    pub fn is_request(&self) -> bool {
        match self {
            CloveMessage::RequestProxy { .. } => {false}
            CloveMessage::ProxyInfo { .. } => {false}
            CloveMessage::Store { .. } => {true}
            CloveMessage::SearchOverlay { .. } => {true}
            CloveMessage::SearchGarlemlia { .. } => {true}
            CloveMessage::Response { .. } => {true}
            CloveMessage::ResponseWithValidator { .. } => {true}
            CloveMessage::FileChunkPart { .. } => {true}
        }
    }
}

/// Garlic Message types
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum GarlicMessage {
    FindProxy {
        sequence_number: U256,
        clove: Clove
    },
    Forward {
        sequence_number: U256,
        clove: Clove
    },
    ProxyAgree {
        sequence_number: U256,
        updated_sequence_number: U256,
        hops: u16,
        clove: Clove
    },
    RequestAlt {
        alt_sequence_number: U256,
        next_hop: Node,
        last_hop: Node
    },
    RefreshAlt {
        sequence_number: U256
    },
    UpdateAlt {
        sequence_number: U256,
        alt_node: CloveNode
    },
    UpdateAltNextOrLast {
        sequence_number: U256,
        old_node: Node,
        new_node: Node
    },
    ResponseDirect {
        request_id: CloveRequestID,
        clove_1: Clove,
        clove_2: Clove
    },
    FileChunkPart {
        request_id: CloveRequestID,
        data: GarlemliaResponse
    }
}

impl GarlicMessage {
    pub fn sequence_number(&self) -> U256 {
        match self {
            GarlicMessage::FindProxy { sequence_number, .. } => {sequence_number.clone()}
            GarlicMessage::Forward { sequence_number, .. } => {sequence_number.clone()}
            GarlicMessage::ProxyAgree { sequence_number, .. } => {sequence_number.clone()}
            GarlicMessage::RequestAlt { .. } => {U256::from(0)}
            GarlicMessage::RefreshAlt { .. } => {U256::from(0)}
            GarlicMessage::UpdateAlt { .. } => {U256::from(0)}
            GarlicMessage::UpdateAltNextOrLast { .. } => {U256::from(0)}
            GarlicMessage::ResponseDirect { .. } => {U256::from(0)}
            GarlicMessage::FileChunkPart { .. } => {U256::from(0)}
        }
    }

    /// Updating sequence number of message - used when sending to what was once an alt node
    pub fn update_sequence_number(&mut self, new_sequence_number: U256) {
        match self {
            GarlicMessage::Forward { clove, .. } => {
                *self = GarlicMessage::Forward {
                    sequence_number: new_sequence_number,
                    clove: clove.update_sequence(new_sequence_number)
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
            GarlicMessage::FindProxy { clove, .. } => {Some(clove.clone().clone())}
            GarlicMessage::Forward { clove, .. } => {Some(clove.clone().clone())}
            GarlicMessage::ProxyAgree { clove, .. } => {Some(clove.clone())}
            GarlicMessage::RequestAlt { .. } => {None}
            GarlicMessage::RefreshAlt { .. } => {None}
            GarlicMessage::UpdateAlt { .. } => {None}
            GarlicMessage::UpdateAltNextOrLast { .. } => {None}
            GarlicMessage::ResponseDirect { .. } => {None}
            GarlicMessage::FileChunkPart { .. } => {None}
        }
    }

    pub fn build_send_is_alive(sender: Node) -> GarlemliaMessage {
        GarlemliaMessage::Pong {
            sender,
        }
    }

    pub fn build_send(sender: Node, msg: GarlicMessage) -> GarlemliaMessage {
        GarlemliaMessage::Garlic {
            msg,
            sender
        }
    }
}