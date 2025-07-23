use std::error::Error;

/// Custom error type for messaging operations.
#[derive(Debug, Clone)]
pub enum MessageError {
    IoError(String),
    NoRX,
    NoTX,
    TXDropped,
    TXSendError,
    Timeout,
    MissingResponse,
    MissingNode,
    SerializationError(String),
    AcceptError,
    InvalidMessage,
    InvalidKey,
}

impl From<std::io::Error> for MessageError {
    fn from(err: std::io::Error) -> Self {
        // Convert IoError to string
        MessageError::IoError(err.to_string())
    }
}

/// Error type for clove message operations
#[derive(Debug)]
pub enum CloveMessageError {
    DecodingError(Box<dyn Error>),
    DecryptionError(Box<dyn Error>),
}

#[derive(Debug)]
enum ProxyRequestError {
    FirstNeighborFailed = 1,
    SecondNeighborFailed = 2,
    BothNeighborsFailed = 3,
}

impl From<u8> for ProxyRequestError {
    fn from(code: u8) -> Self {
        match code {
            1 => ProxyRequestError::FirstNeighborFailed,
            2 => ProxyRequestError::SecondNeighborFailed,
            3 => ProxyRequestError::BothNeighborsFailed,
            _ => panic!("Invalid error code"),
        }
    }
}
