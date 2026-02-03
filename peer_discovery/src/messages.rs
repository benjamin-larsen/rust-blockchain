use utils::{slice_reader, slice_writer};
use crate::{Error, Result};
use crate::conn_man::CONNECT_PAYLOAD;
use crate::constants::HEADER_SIZE;

#[derive(Debug)]
pub(crate) struct Header {
    pub(crate) msg_type: MessageType,
    pub(crate) msg_flags: u16
}

pub(crate) fn decode_header(buf: [u8; HEADER_SIZE]) -> Result<Header> {
    let mut offset: usize = 0;

    let header = Header {
        msg_type: MessageType::try_from(
            slice_reader::try_read_uint16(&buf, &mut offset)?
        )?,
        msg_flags: slice_reader::try_read_uint16(&buf, &mut offset)?,
    };

    Ok(header)
}

pub(crate) fn encode_header(header: &Header) -> Result<[u8; HEADER_SIZE]> {
    let mut buf = [0u8; HEADER_SIZE];
    let mut offset: usize = 0;
    
    slice_writer::try_write_uint16(header.msg_type as u16, &mut buf, &mut offset)?;
    slice_writer::try_write_uint16(header.msg_flags, &mut buf, &mut offset)?;
    
    Ok(buf)
}

const MSG_CONNECT: u16 = 0;
const MSG_PING: u16 = 1;
const MSG_PONG: u16 = 2;
const MSG_REQ_PEERS: u16 = 3;
const MSG_PEERS: u16 = 4;
const MSG_REQ_NET: u16 = 5;
const MSG_NET: u16 = 6;

#[repr(u16)]
#[derive(Debug, Copy, Clone)]
pub enum MessageType {
    Connect = MSG_CONNECT,
    Ping = MSG_PING,
    Pong = MSG_PONG,
    ReqPeers = MSG_REQ_PEERS,
    Peers = MSG_PEERS,
    ReqNet = MSG_REQ_NET,
    Net = MSG_NET,
}

pub(crate) fn validate_payload_size(header: &Header, payload_size: usize) -> bool {
    match header.msg_type {
        MessageType::Connect => payload_size == CONNECT_PAYLOAD,

        _ => false
    }
}

impl TryFrom<u16> for MessageType {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            MSG_CONNECT => Ok(MessageType::Connect),
            MSG_PING => Ok(MessageType::Ping),
            MSG_PONG => Ok(MessageType::Pong),
            MSG_REQ_PEERS => Ok(MessageType::ReqPeers),
            MSG_PEERS => Ok(MessageType::Peers),
            MSG_REQ_NET => Ok(MessageType::ReqNet),
            MSG_NET => Ok(MessageType::Net),

            _ => Err(Error::InvalidMessage)
        }
    }
}