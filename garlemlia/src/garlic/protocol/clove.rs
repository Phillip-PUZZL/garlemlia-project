use crate::core::constants::{DATA_SHARDS, DEFAULT_INDEX, MIN_PROXY_COUNT, SOCKET_FILE_DATA_MAX};
use crate::core::{u256_random, CloveMessageError};
use crate::data::garlemlia_protocol::{GarlemliaResponse, GarlemliaStoreRequest, InitialChunkInfo};
use crate::files::storage::FileStorage;
use crate::files::upload::FileUpload;
use crate::garlic::crypto::encryption::Encryption;
use crate::garlic::crypto::reconstruction::Reconstruction;
use crate::garlic::crypto::sharding::Sharding;
use crate::net::node::Node;
use chrono::{DateTime, Utc};
use primitive_types::U256;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::error::Error;

/// Clove struct containing information for messages which pass through this node
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Clove {
    pub sequence_number: U256,
    pub request_id: CloveRequestID,
    pub msg_fragment: Vec<u8>,
    pub key_fragment: Vec<u8>,
    pub sent: DateTime<Utc>,
    pub index: u8,
    pub ida_count: u8,
}

impl Clove {
    pub fn default() -> Clove {
        todo!()
    }
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
    pub from: Node,
}

/// Associating a sequence number with a node
#[derive(Clone, Debug, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub struct CloveNode {
    // The sequence number used when sending to this node
    // Most of the time it will be the chain sequence number, but if it is an alt node
    // then it will be the randomly generated sequence number
    pub sequence_number: U256,
    pub node: Node,
}

/// Associate clove message with being a file chunk
#[derive(Clone, Debug)]
pub struct FileCloveMessage {
    pub is_file_chunk: bool,
    pub message: CloveMessage,
}

/// Association between a request ID and the index of that clove in the Reed-Solomon erasure code
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct CloveRequestID {
    pub request_id: U256,
    pub index: u64,
}

impl CloveRequestID {
    pub fn new(request_id: U256, index: u64) -> CloveRequestID {
        CloveRequestID { request_id, index }
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
        starting_hops: u16,
    },
    Store {
        request_id: CloveRequestID,
        data: GarlemliaStoreRequest,
    },
    SearchOverlay {
        request_id: CloveRequestID,
        proxy_id: U256,
        search_term: String,
        public_key: String,
        ttl: u8,
    },
    SearchGarlemlia {
        request_id: CloveRequestID,
        key: U256,
    },
    Response {
        request_id: CloveRequestID,
        data: GarlemliaResponse,
    },
    ResponseWithValidator {
        request_id: CloveRequestID,
        proxy_id: U256,
        clove_1: Clove,
        clove_2: Clove,
    },
    FileChunkPart {
        request_id: CloveRequestID,
        data: GarlemliaResponse,
    },
}

impl CloveMessage {
    /// Generate clove messages for file metadata
    pub async fn file_metadata_upload(
        file_info: FileUpload,
        request_id: Option<U256>,
    ) -> Vec<FileCloveMessage> {
        let mut file_messages = vec![];

        file_messages.push(FileCloveMessage {
            is_file_chunk: false,
            message: CloveMessage::Store {
                request_id: CloveRequestID::new(request_id.unwrap_or(u256_random()), 0),
                data: GarlemliaStoreRequest::FileName {
                    id: file_info.id,
                    name: file_info.name,
                    file_type: file_info.file_type,
                    size: file_info.size,
                    categories: file_info.categories,
                    metadata_location: file_info.metadata_location.clone(),
                    key_location: file_info.key_location.clone(),
                },
            },
        });
        file_messages.push(FileCloveMessage {
            is_file_chunk: false,
            message: CloveMessage::Store {
                request_id: CloveRequestID::new(request_id.unwrap_or(u256_random()), 1),
                data: GarlemliaStoreRequest::MetaData {
                    id: file_info.metadata_location.get_current().unwrap().id,
                    file_id: file_info.file_id,
                    chunk_info: file_info.chunks.clone(),
                    downloads: 0,
                    availability: 1.0,
                    metadata_location: file_info.metadata_location,
                },
            },
        });
        file_messages.push(FileCloveMessage {
            is_file_chunk: false,
            message: CloveMessage::Store {
                request_id: CloveRequestID::new(request_id.unwrap_or(u256_random()), 2),
                data: GarlemliaStoreRequest::FileKey {
                    id: file_info.key_location.get_current().unwrap().id,
                    enc_file_id: file_info.enc_file_id,
                    decryption_key: file_info.decryption_key,
                    key_location: file_info.key_location,
                },
            },
        });

        file_messages
    }

    /// Generate Clove messages for the actual file chunk data
    pub async fn file_chunk_to_upload(
        chunk: InitialChunkInfo,
        file_storage: FileStorage,
        request_id: Option<U256>,
    ) -> Vec<FileCloveMessage> {
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

            parts_file_messages.push(FileCloveMessage {
                is_file_chunk: true,
                message: CloveMessage::Store {
                    request_id: CloveRequestID::new(
                        yeet_request_id,
                        request_id_index + 1 + total_parts,
                    ),
                    data: GarlemliaStoreRequest::FileChunkPart {
                        id: chunk.chunk_id,
                        index: total_parts as usize,
                        part_size: part_data.len(),
                        data: part_data,
                    },
                },
            });

            total_parts += 1;
        }

        chunk_part_messages.push(FileCloveMessage {
            is_file_chunk: true,
            message: CloveMessage::Store {
                request_id: CloveRequestID::new(yeet_request_id, request_id_index),
                data: GarlemliaStoreRequest::FileChunkInfo {
                    id: chunk.chunk_id,
                    request_id: yeet_request_id,
                    chunk_size: chunk.size,
                    parts_count: total_parts as usize,
                },
            },
        });

        for item in parts_file_messages {
            chunk_part_messages.push(item);
        }

        chunk_part_messages
    }

    pub fn request_id(&self) -> Option<CloveRequestID> {
        match self {
            CloveMessage::RequestProxy { .. } => None,
            CloveMessage::ProxyInfo { .. } => None,
            CloveMessage::Store { request_id, .. } => Some(request_id.clone()),
            CloveMessage::SearchOverlay { request_id, .. } => Some(request_id.clone()),
            CloveMessage::SearchGarlemlia { request_id, .. } => Some(request_id.clone()),
            CloveMessage::Response { request_id, .. } => Some(request_id.clone()),
            CloveMessage::ResponseWithValidator { request_id, .. } => Some(request_id.clone()),
            CloveMessage::FileChunkPart { request_id, .. } => Some(request_id.clone()),
        }
    }

    pub fn proxy_id(&self) -> Option<U256> {
        match self {
            CloveMessage::RequestProxy { .. } => None,
            CloveMessage::ProxyInfo { .. } => None,
            CloveMessage::Store { .. } => None,
            CloveMessage::SearchOverlay { proxy_id, .. } => Some(proxy_id.clone()),
            CloveMessage::SearchGarlemlia { .. } => None,
            CloveMessage::Response { .. } => None,
            CloveMessage::ResponseWithValidator { proxy_id, .. } => Some(proxy_id.clone()),
            CloveMessage::FileChunkPart { .. } => None,
        }
    }

    pub fn is_request(&self) -> bool {
        match self {
            CloveMessage::RequestProxy { .. } => false,
            CloveMessage::ProxyInfo { .. } => false,
            CloveMessage::Store { .. } => true,
            CloveMessage::SearchOverlay { .. } => true,
            CloveMessage::SearchGarlemlia { .. } => true,
            CloveMessage::Response { .. } => true,
            CloveMessage::ResponseWithValidator { .. } => true,
            CloveMessage::FileChunkPart { .. } => true,
        }
    }
}

pub(crate) trait TraitCloveProtocol {
    fn generate(
        msg: CloveMessage,
        count: u8,
        sequence_number: U256,
        recipient_pub_key: Option<RsaPublicKey>,
        request_id: Option<CloveRequestID>,
    ) -> Result<Vec<Clove>, Box<dyn Error>>;
    fn generate_internal(
        msg_serialized: Vec<u8>,
        count: u8,
        sequence_number: U256,
        recipient_pub_key: Option<RsaPublicKey>,
        request_id: CloveRequestID,
    ) -> Result<Vec<Clove>, Box<dyn Error>>;
    fn reconstruct_encrypted(
        clove_1: Clove,
        clove_2: Clove,
        private_key: RsaPrivateKey,
    ) -> Result<CloveMessage, CloveMessageError>;
    fn reconstruct(clove_1: Clove, clove_2: Clove) -> Result<CloveMessage, CloveMessageError>;
}

pub struct CloveProtocol;
impl TraitCloveProtocol for CloveProtocol {
    /// Generate cloves for message transmission with optional RSA encryption
    fn generate(
        msg: CloveMessage,
        count: u8,
        sequence_number: U256,
        recipient_pub_key: Option<RsaPublicKey>,
        request_id: Option<CloveRequestID>,
    ) -> Result<Vec<Clove>, Box<dyn Error>> {
        let msg_serialized = bincode::serialize(&msg).map_err(|e| Box::new(e) as Box<dyn Error>)?;

        let request_id =
            request_id.unwrap_or_else(|| CloveRequestID::new(u256_random(), DEFAULT_INDEX));

        CloveProtocol::generate_internal(
            msg_serialized,
            count,
            sequence_number,
            recipient_pub_key,
            request_id,
        )
    }

    /// Generates a set of `Clove` objects containing encrypted message data and keys, partitioned across shards
    /// using Reed-Solomon erasure coding.
    ///
    /// # Parameters
    /// - `msg_serialized` (`Vec<u8>`): The serialized message to be processed.
    /// - `count` (`u8`): The number of cloves (or shards) to generate. This will be clamped to a minimum value `MIN_PROXY_COUNT`.
    /// - `sequence_number` (`U256`): A unique sequence number for identifying the cloves in a sequence.
    /// - `recipient_pub_key` (`Option<RsaPublicKey>`): The optional RSA public key of the recipient. If provided, it will
    ///   be used to encrypt the generated symmetric encryption key.
    /// - `request_id` (`CloveRequestID`): An identifier for associating the cloves with a specific request.
    ///
    /// # Returns
    /// - `Result<Vec<Clove>, Box<dyn Error>>`:
    ///   - On success, returns a `Vec<Clove>` containing the generated clove objects.
    ///   - On failure, returns an error wrapped in a `Box<dyn Error>`.
    ///
    /// # Workflow
    /// 1. Ensures that the number of shards (`count`) meets the minimum proxy count threshold (`MIN_PROXY_COUNT`).
    /// 2. Generates a symmetric encryption key.
    /// 3. Pads the input message bytes to meet encryption requirements.
    /// 4. Encrypts the padded message using the generated symmetric key.
    /// 5. Encrypts the symmetric key itself using the recipient's RSA public key, if provided.
    /// 6. Uses Reed-Solomon erasure coding to split the encrypted message data and encrypted symmetric key
    ///    into multiple data and key shards.
    /// 7. Calls `generate_cloves`, which constructs the `Clove` objects by combining sequence information,
    ///    request identifiers, and shard data.
    ///
    /// # Errors
    /// This function may return various errors depending on execution failures, such as
    /// - Failure to generate the symmetric encryption key.
    /// - Failure to properly encrypt the message or key.
    /// - Errors during Reed-Solomon shard generation.
    /// - Any issues arising from `generate_cloves`.
    ///
    /// # Example
    ///
    /// use some_module::{clove_generator, CloveRequestID, RsaPublicKey};
    /// use ethereum_types::U256;
    ///
    /// let message = b"Hello, secure world!".to_vec();
    /// let count = 5;
    /// let sequence_number = U256::from(1234);
    /// let recipient_pub_key = Some(get_recipient_public_key());
    /// let request_id = CloveRequestID::new();
    ///
    /// let cloves = clove_generator(message, count, sequence_number, recipient_pub_key, request_id);
    /// match cloves {
    ///     Ok(cloves_vec) => {
    ///         for clove in cloves_vec {
    ///             println!("Generated Clove: {:?}", clove);
    ///         }
    ///     }
    ///     Err(e) => eprintln!("Failed to generate cloves: {}", e),
    /// }
    ///
    ///
    /// # Notes
    /// - The generated cloves can be used for secure, fault-tolerant transmission or storage of encrypted message data.
    /// - Since Reed-Solomon coding is employed, a subset of shards (meeting the data shard threshold) is sufficient to
    ///   reconstruct the original message and key.
    /// - Ensure that `MIN_PROXY_COUNT` and `DATA_SHARDS` are properly configured to meet your redundancy and reliability needs.
    fn generate_internal(
        msg_serialized: Vec<u8>,
        count: u8,
        sequence_number: U256,
        recipient_pub_key: Option<RsaPublicKey>,
        request_id: CloveRequestID,
    ) -> Result<Vec<Clove>, Box<dyn Error>> {
        let actual_count = count.max(MIN_PROXY_COUNT);
        let encryption_key = Encryption::generate_key()?;
        let padded_message = Encryption::pad_message(&msg_serialized);
        let encrypted_data = Encryption::encrypt_message(&padded_message, &encryption_key)?;
        let encrypted_key = Encryption::encrypt_key(encryption_key.to_vec(), recipient_pub_key)?;

        let (data_shards_vec, key_shards_vec) =
            Sharding::generate_reed_solomon_shards(encrypted_data, encrypted_key, actual_count)?;

        Sharding::generate_cloves(
            sequence_number,
            request_id,
            data_shards_vec,
            key_shards_vec,
            count.max(DATA_SHARDS as u8),
            actual_count,
        )
    }

    /// Reconstructs a CloveMessage from two clove fragments with RSA decryption.
    ///
    /// # Arguments
    /// * `clove_1` - First clove fragment
    /// * `clove_2` - Second clove fragment
    /// * `private_key` - RSA private key for decryption
    ///
    /// # Returns
    /// * `Result<CloveMessage, CloveMessageError>` - Reconstructed and decrypted message or error
    fn reconstruct_encrypted(
        clove_1: Clove,
        clove_2: Clove,
        private_key: RsaPrivateKey,
    ) -> Result<CloveMessage, CloveMessageError> {
        Reconstruction::clove_to_message(clove_1, clove_2, Some(private_key))
            .map_err(|e| CloveMessageError::DecryptionError(e))
    }

    /// Reconstructs a CloveMessage from two clove fragments without RSA decryption.
    ///
    /// # Arguments
    /// * `clove_1` - First clove fragment
    /// * `clove_2` - Second clove fragment
    ///
    /// # Returns
    /// * `Result<CloveMessage, CloveMessageError>` - Reconstructed message or error
    fn reconstruct(clove_1: Clove, clove_2: Clove) -> Result<CloveMessage, CloveMessageError> {
        Reconstruction::clove_to_message(clove_1, clove_2, None)
            .map_err(|e| CloveMessageError::DecodingError(e))
    }
}
