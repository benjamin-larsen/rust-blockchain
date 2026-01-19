use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, BufStream};
use tokio::net::TcpStream;
use crate::server::Server;
use crate::messages::{MessageType, ValidatePayloadSize};
use crate::Error;
use crate::messages::BasicHeader;

pub enum SocketDirection {
    Inbound,
    Outbound,
}

pub struct Socket {
    stream: BufStream<TcpStream>,
    addr: SocketAddr,
    server: Arc<Server>,
    direction: SocketDirection,
}

impl Socket {
    pub fn new(stream: TcpStream, server: Arc<Server>, direction: SocketDirection) -> Result<Socket, Error> {
        Ok(Socket {
            addr: stream.peer_addr()?,
            stream: BufStream::new(stream),
            server,
            direction
        })
    }
    async fn read_basic_header(&mut self) -> Result<BasicHeader, Error> {
        let mut buf = [0u8; 8];
        self.stream.read_exact(&mut buf).await?;

        let header = BasicHeader {
            msg_type: MessageType::try_from(u16::from_le_bytes(buf[..2].try_into().unwrap()))?,
            msg_flags: u16::from_le_bytes(buf[2..4].try_into().unwrap()),
            msg_length: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
        };

        if !ValidatePayloadSize(&header) {
            return Err(Error::InvalidPayloadSize);
        }
        
        Ok(header)
    }

    async fn read_basic_message(&mut self) -> Result<(), Error> {
        let header = self.read_basic_header().await?;

        if !header.msg_type.is_basic() {
            return Err(Error::InvalidMessage);
        }

        println!("{:?}", header);

        let payload_len = header.msg_length as usize;

        let mut payload: Vec<u8> = Vec::with_capacity(payload_len);
        payload.resize(payload_len, 0);

        self.stream.read_exact(&mut payload).await?;

        println!("{:x?}", payload);

        Ok(())
    }
}

pub async fn handle_sock(mut socket: Socket) -> Result<(), Error> {
    loop {
        socket.read_basic_message().await?;
    }
}