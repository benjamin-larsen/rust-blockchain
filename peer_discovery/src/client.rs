use std::cell::RefCell;
use std::collections::HashMap;
use std::str::FromStr;
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use tokio::net::UdpSocket;
use utils::net::sockaddr_v6;
use utils::NodeConfig;
use crate::constants::{HEADER_SIZE, MAX_PACKET, MIN_AUTH_PACKET, SIGNATURE_SIZE};
use crate::{Error, Result};
use crate::conn_man::{Connection, CONNECT_PAYLOAD};
use crate::messages::{decode_header, validate_payload_size, MessageType};

pub struct Client {
    pub(crate) config: Arc<dyn NodeConfig>,
    pub(crate) socket: UdpSocket,
    pub(crate) active: u32,
    pub(crate) probe: u32,
    pub(crate) connections: RefCell<HashMap<SocketAddrV6, Connection>>
}

impl Client {
    pub(crate) async fn new(config: Arc<dyn NodeConfig>) -> Result<Arc<Client>> {

        let socket = UdpSocket::bind((config.server_addr(), config.discovery_port())).await?;

        println!("UDP socket: {}", socket.local_addr()?);

        Ok(
            Arc::new(Client {
                config,
                socket,
                active: 0,
                probe: 0,
                connections: RefCell::new(HashMap::new())
            })
        )
    }

    async fn process_message(self: &Arc<Self>, buf: &mut [u8]) -> Result<()> {
        let (len, addr) = self.socket.recv_from(buf).await?;
        let addr = sockaddr_v6(addr);

        if len < HEADER_SIZE {
            return Err(Error::InvalidPacket);
        }

        if len > MAX_PACKET {
            return Err(Error::InvalidPacket);
        }

        let header = decode_header(
            buf[0..HEADER_SIZE]
                .try_into()
                .map_err(|_| Error::UnknownError)?
        )?;

        if matches!(header.msg_type, MessageType::Connect) {
            let payload = &buf[HEADER_SIZE..len];
            
            if payload.len() != CONNECT_PAYLOAD {
                return Err(Error::InvalidMessage);
            }

            self.process_connect(addr, header.msg_flags, payload).await?;
        } else {
            if len < MIN_AUTH_PACKET {
                return Err(Error::InvalidPacket);
            }
            
            let signature: [u8; 32] = buf[HEADER_SIZE..MIN_AUTH_PACKET].try_into().map_err(|_| Error::UnknownError)?;
            let payload = &buf[MIN_AUTH_PACKET..len];
            
            if !validate_payload_size(&header, payload.len()) {
                return Err(Error::InvalidMessage);
            }
            
            let Some(connection) = self.connections.try_borrow()?.get(&addr) else {
                return Err(Error::Disconnected);
            };
        }
        
        Ok(())
    }

    pub(crate) async fn start_net(self: Arc<Self>) {
        let mut buf = [0u8; MAX_PACKET];

        loop {
            if let Err(err) = self.process_message(&mut buf).await {
                println!("Error processing message: {:?}", err);
            }
        }
    }
}