use std::net::SocketAddr;
use std::sync::Arc;
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufStream};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use crate::server::Server;
use crate::messages::{decode_basic_header, BASIC_HEADER_SIZE, AUTH_HEADER_SIZE};
use crate::{Error, Result};
use crate::auth::process_auth;
use crate::messages::BasicHeader;
use utils::{slice_writer};

type HmacSha256 = Hmac<Sha256>;

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
        let mut buf = [0u8; 8];
        let mut offset: usize = 0;

        slice_writer::try_write_uint16(header.msg_type as u16, &mut buf, &mut offset)?;
        slice_writer::try_write_uint16(header.msg_flags, &mut buf, &mut offset)?;
        slice_writer::try_write_uint32(header.msg_length, &mut buf, &mut offset)?;
        
        self.stream.write_all(&buf).await?;

        Ok(())
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

    pub(crate) async fn read_authenticated_message(&mut self) -> Result<(BasicHeader, Vec<u8>)> {
        let Some(hmac_key) = self.hmac_key else {
            return Err(Error::AuthError);
        };

        let expected_sequence = self.remote_sequence;

        self.remote_sequence += 1;

        let mut header_buf = [0u8; BASIC_HEADER_SIZE + AUTH_HEADER_SIZE];
        self.stream.read_exact(&mut header_buf).await?;

        let basic_header_buf = header_buf[0..BASIC_HEADER_SIZE]
            .try_into().map_err(|_| Error::AuthError)?;

        let header = decode_basic_header(basic_header_buf)?;

        if header.msg_type.is_basic() {
            return Err(Error::InvalidMessage);
        }

        // Read Authentication Headers
        let signature: [u8; AUTH_HEADER_SIZE] = header_buf[BASIC_HEADER_SIZE..BASIC_HEADER_SIZE + AUTH_HEADER_SIZE]
            .try_into().map_err(|_| Error::AuthError)?;

        let payload_len = header.msg_length as usize;

        let mut payload: Vec<u8> = Vec::with_capacity(payload_len);
        payload.resize(payload_len, 0);

        self.stream.read_exact(&mut payload).await?;

        let header_hash: [u8; 32] = Sha256::digest(&basic_header_buf).into();
        let payload_hash: [u8; 32] = Sha256::digest(&payload).into();

        let mut mac = HmacSha256::new_from_slice(&hmac_key)
            .map_err(|_| Error::HmacError)?;
        mac.update(&expected_sequence.to_le_bytes());
        mac.update(&header_hash);
        mac.update(&payload_hash);

        let expected_signature: [u8; 32] = mac.finalize().into_bytes().into();
        let is_valid: bool = expected_signature.ct_eq(&signature).into();

        if !is_valid {
            return Err(Error::InvalidMessage);
        }

        Ok((header, payload))
    }
}

pub async fn handle_sock(mut socket: Socket) -> Result<()> {
    process_auth(&mut socket).await?;

    println!("Socket Authenticated.");

    loop {
        let (header, payload) = socket.read_authenticated_message().await?;

        println!("Got Message: {:?}, {:02X?}", header, payload);
    }
}