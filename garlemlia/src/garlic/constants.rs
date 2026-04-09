use super::protocol::CloveMessage;
use crate::core::MessageError;

pub type CloveResult = Result<Option<CloveMessage>, MessageError>;
pub const DEFAULT_RESPONSE: Option<CloveMessage> = None;
