use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, BufStream};
use tokio::net::TcpStream;
use crate::server::Server;
use crate::messages::{MessageType, validate_payload_size};
use crate::{Error, Result};
use crate::auth::process_auth;
use crate::messages::BasicHeader;
use utils::slice_reader;

pub enum SocketDirection {
    Inbound,
    Outbound,
}

pub struct Socket {
    pub addr: SocketAddr,
    pub direction: SocketDirection,
    pub(crate) stream: BufStream<TcpStream>,
    pub(crate) server: Arc<Server>,
}

impl Socket {
    pub fn new(stream: TcpStream, server: Arc<Server>, direction: SocketDirection) -> Result<Socket> {
        Ok(Socket {
            addr: stream.peer_addr()?,
            stream: BufStream::new(stream),
            server,
            direction
        })
    }
    async fn read_basic_header(&mut self) -> Result<BasicHeader> {
        let mut buf = [0u8; 8];
        let mut offset: usize = 0;
        self.stream.read_exact(&mut buf).await?;

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

    pub(crate) async fn read_basic_message(&mut self) -> Result<(BasicHeader, Vec<u8>)> {
        let header = self.read_basic_header().await?;

        if !header.msg_type.is_basic() {
            return Err(Error::InvalidMessage);
        }

        let payload_len = header.msg_length as usize;

        let mut payload: Vec<u8> = Vec::with_capacity(payload_len);
        payload.resize(payload_len, 0);

        self.stream.read_exact(&mut payload).await?;

        Ok((header, payload))
    }
}

pub async fn handle_sock(mut socket: Socket) -> Result<()> {
    let keypair = socket.server.config.keypair();
    println!("{:02X?}", keypair.as_bytes());
    println!("{:02X?}", keypair.verifying_key().as_bytes());

    process_auth(&mut socket).await?;

    loop {
        socket.read_basic_message().await?;
    }
}