use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufStream};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use crate::server::Server;
use crate::messages::{decode_basic_header, encode_basic_header};
use crate::{Error, Result};
use crate::messages::BasicHeader;

pub enum SocketDirection {
    Inbound,
    Outbound,
}

pub struct Socket {
    pub addr: SocketAddr,
    pub direction: SocketDirection,
    pub(crate) local_sequence: u64,
    pub(crate) remote_sequence: u64,
    pub(crate) hmac_key: Option<[u8; 32]>,
    pub(crate) stream: BufStream<TcpStream>,
    pub(crate) server: Arc<Server>,
    pub(crate) write_mu: Arc<Semaphore>
}

impl Socket {
    pub fn new(stream: TcpStream, server: Arc<Server>, direction: SocketDirection) -> Result<Socket> {
        Ok(Socket {
            addr: stream.peer_addr()?,
            direction,
            local_sequence: 0,
            remote_sequence: 0,
            hmac_key: None,
            stream: BufStream::new(stream),
            server,
            write_mu: Arc::new(Semaphore::new(1)),
        })
    }
    async fn read_basic_header(&mut self) -> Result<BasicHeader> {
        let mut buf = [0u8; 8];
        self.stream.read_exact(&mut buf).await?;

        let header = decode_basic_header(buf)?;

        Ok(header)
    }

    pub(crate) async fn write_basic_header(&mut self, header: &BasicHeader) -> Result<()> {
        let buf = encode_basic_header(header)?;
        self.stream.write_all(&buf).await?;

        Ok(())
    }

    pub(crate) async fn read_basic_message(&mut self) -> Result<(BasicHeader, Vec<u8>)> {
        let header = self.read_basic_header().await?;

        if !header.msg_type.is_basic() {
            return Err(Error::InvalidMessage);
        }

        let payload_len = header.msg_length as usize;

        let mut payload: Vec<u8> = vec![0; payload_len];

        self.stream.read_exact(&mut payload).await?;

        Ok((header, payload))
    }
}

pub async fn handle_sock(mut socket: Socket) -> Result<()> {
    socket.process_auth().await?;

    println!("Socket Authenticated.");

    loop {
        let (header, payload) = socket.read_authenticated_message().await?;

        println!("Got Message: {:?}, {:02X?}", header, payload);
    }
}