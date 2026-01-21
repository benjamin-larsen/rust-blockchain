use crate::{Error, Result};

#[derive(Debug)]
pub(crate) struct BasicHeader {
    pub(crate) msg_type: MessageType,
    pub(crate) msg_flags: u16,
    pub(crate) msg_length: u32,
}

#[repr(u16)]
#[derive(Debug, Copy, Clone)]
pub enum MessageType {
    Hello = 0
}

const MSG_HELLO: u16 = MessageType::Hello as u16;

pub(crate) fn validate_payload_size(header: &BasicHeader) -> bool {
    match header.msg_type {
        MessageType::Hello => header.msg_length >= 162 && header.msg_length <= 1024,

        _ => true
    }
}

impl MessageType {
    // Basic Message is one that is sent/received pre-authentication.
    pub fn is_basic(&self) -> bool {
        match self {
            MessageType::Hello => true,
            _ => false,
        }
    }
}

impl TryFrom<u16> for MessageType {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            MSG_HELLO => Ok(MessageType::Hello),

            _ => Err(Error::InvalidMessage)
        }
    }
}