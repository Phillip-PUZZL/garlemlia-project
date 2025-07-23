use crate::structs::error::MessageError;
use crate::structs::garlic_message::CloveMessage;

// Default KBucket size
pub const DEFAULT_K: usize = 20;
// Maximum KBucket size (currently unused)
pub const MAX_K: usize = 40;
// Number of parallel iterations to perform on iterative lookups + maximum results
pub const LOOKUP_ALPHA: usize = 3;
// Maximum total network packet size to send
pub const SOCKET_DATA_MAX: usize = 49152;
// Maximum total network packet size which can be allocated for file data
pub const SOCKET_FILE_DATA_MAX: usize = 32768;

pub const PROXY_REQUEST_MESSAGE: &str = "Will proxy?";
pub const PROXY_RESPONSE_TIMEOUT_MS: u64 = 200;
pub const MIN_PROXY_COUNT: u8 = 2;
/// AES block size in bytes
pub const AES_BLOCK_SIZE: usize = 16;
/// Number of data shards used in Reed-Solomon encoding
pub const DATA_SHARDS: usize = 2;
pub const DEFAULT_INDEX: u64 = 0;
pub const MIN_SEARCH_COUNT: u8 = 2;
pub const DEFAULT_TTL: u8 = 5;
pub const PROXY_SEND_ERROR_NEIGHBOR1: u8 = 1;
pub const PROXY_SEND_ERROR_NEIGHBOR2: u8 = 2;
pub const PROXY_SEND_ERROR_BOTH: u8 = 3;
pub const MAX_BATCH_SIZE: usize = 50;
pub const MESSAGE_TIMEOUT_MS: u64 = 200;
pub const DEFAULT_RESPONSE: Option<CloveMessage> = None;

pub type EncryptionKey = [u8; 32];
pub type EncryptedData = Vec<u8>;
pub type CloveResult = Result<Option<CloveMessage>, MessageError>;