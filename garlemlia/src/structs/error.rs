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
}

impl From<std::io::Error> for MessageError {
    fn from(err: std::io::Error) -> Self {
        // Convert IoError to string
        MessageError::IoError(err.to_string())
    }
}