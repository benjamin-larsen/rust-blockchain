use utils::slice_reader;
use crate::{Error, Result};

#[derive(Debug)]
pub(crate) struct BasicHeader {
    pub(crate) msg_type: MessageType,
    pub(crate) msg_flags: u16,
    pub(crate) msg_length: u32,
}

pub(crate) const BASIC_HEADER_SIZE: usize = 8;
pub(crate) const AUTH_HEADER_SIZE: usize = 32;

pub(crate) fn decode_basic_header(buf: [u8; BASIC_HEADER_SIZE]) -> Result<BasicHeader> {
    let mut offset: usize = 0;

    let header = BasicHeader {
        msg_type: MessageType::try_from(
            slice_reader::try_read_uint16(&buf, &mut offset)?
        )?,
        msg_flags: slice_reader::try_read_uint16(&buf, &mut offset)?,
        msg_length: slice_reader::try_read_uint32(&buf, &mut offset)?,
    };

    if !validate_payload_size(&header) {
        return Err(Error::InvalidPayloadSize);
    }

    Ok(header)
}

const MSG_HELLO: u16 = 0;
const MSG_PING: u16 = 1;

#[repr(u16)]
#[derive(Debug, Copy, Clone)]
pub enum MessageType {
    Hello = MSG_HELLO,
    Ping = MSG_PING,
}

pub(crate) fn validate_payload_size(header: &BasicHeader) -> bool {
    match header.msg_type {
        MessageType::Hello => header.msg_length >= 162 && header.msg_length <= 1024,
        MessageType::Ping => header.msg_length == 0
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
            MSG_PING => Ok(MessageType::Ping),

            _ => Err(Error::InvalidMessage)
        }
    }
}