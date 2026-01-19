use std::sync::Arc;
use tokio::io::{AsyncReadExt, BufStream};
use tokio::net::TcpStream;
use crate::server::Server;

pub enum SocketDirection {
    Inbound,
    Outbound,
}

pub struct Socket {
    stream: BufStream<TcpStream>,
    server: Arc<Server>,
    direction: SocketDirection,
}

#[derive(Debug)]
struct BasicHeader {
    msg_type: u16,
    msg_flags: u16,
    msg_length: u32,
}

impl Socket {
    pub fn new(stream: TcpStream, server: Arc<Server>, direction: SocketDirection) -> Socket {
        Socket {
            stream: BufStream::new(stream),
            server,
            direction
        }
    }
    async fn read_basic_header(&mut self) -> Result<BasicHeader, std::io::Error> {
        let mut buf = [0u8; 8];
        self.stream.read_exact(&mut buf).await?;

        Ok(BasicHeader {
            msg_type: u16::from_le_bytes(buf[..2].try_into().unwrap()),
            msg_flags: u16::from_le_bytes(buf[2..4].try_into().unwrap()),
            msg_length: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
        })
    }
}

pub async fn handle_sock(mut socket: Socket) {
    loop {
        let Ok(header) = socket.read_basic_header().await else { return; };

        println!("{:?}", header);
    }
}