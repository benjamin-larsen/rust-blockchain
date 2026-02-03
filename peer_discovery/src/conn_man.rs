use std::collections::hash_map::Entry;
use std::net::SocketAddrV6;
use std::time::Duration;
use tokio::time::sleep;
use x25519_dalek::{PublicKey, StaticSecret};
use utils::{slice_reader, slice_writer, time, try_generate_rand};
use utils::net::sockaddr;
use crate::client::Client;
use crate::constants::{HEADER_SIZE, MIN_PROTOCOL_VERSION, NETWORK_MAGIC, NO_ATTEMPTS, PROTOCOL_VERSION};
use crate::{Error, Result};
use crate::messages::{encode_header, Header, MessageType};

pub const CONNECT_PAYLOAD: usize = 52;

pub(crate) struct ConnFlags(u32);

impl ConnFlags {
    pub const CONNECTED: u32 = 1 << 0;
    pub const ACTIVE:    u32 = 1 << 1;

    pub fn get_flag(&self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    pub fn set_flag(&mut self, flag: u32) {
        self.0 |= flag;
    }

    pub fn reset_flag(&mut self, flag: u32) {
        self.0 &= !flag;
    }
}

impl std::fmt::Debug for ConnFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut names = Vec::new();

        if self.get_flag(Self::CONNECTED) {
            names.push("CONNECTED");
        }
        if self.get_flag(Self::ACTIVE) {
            names.push("ACTIVE");
        }

        if names.len() == 0 {
            return write!(f, "ConnFlags(NONE)");
        }

        write!(f, "ConnFlags({})", names.join(" | "))
    }
}

#[derive(Debug)]
pub(crate) struct Connection {
    pub(crate) flags: ConnFlags,
    pub(crate) local_attempts: u8, // Sentinel for no attempts: 255
    pub(crate) external_attempts: u8, // Sentinel for no attempts: 255

    // X25519 Public Key
    pub(crate) local_public: [u8; 32],

    // When connected, Shared Secret, when not X25519 Secret Key
    pub(crate) secret: [u8; 32],

    pub(crate) remote_public: [u8; 32],
}

impl Connection {
    pub(crate) fn new(active: bool) -> Result<Self> {
        let mut flags: u32 = 0;

        if active {
            flags |= ConnFlags::ACTIVE;
        }

        let sk = StaticSecret::from(try_generate_rand::<32>()?);
        let pk = PublicKey::from(&sk).to_bytes();

        Ok(Connection {
            flags: ConnFlags(flags),
            local_attempts: NO_ATTEMPTS,
            external_attempts: NO_ATTEMPTS,
            local_public: pk,
            secret: sk.to_bytes(),
            remote_public: [0; 32],
        })
    }

    pub(crate) fn reset(&mut self) -> Result<()> {
        let sk = StaticSecret::from(try_generate_rand::<32>()?);
        let pk = PublicKey::from(&sk).to_bytes();

        self.local_public = pk;
        self.secret = sk.to_bytes();
        self.flags.reset_flag(ConnFlags::CONNECTED);
        self.local_attempts = NO_ATTEMPTS;

        Ok(())
    }

    pub(crate) fn set_connection(&mut self, remote_public: [u8; 32]) {
        if self.flags.get_flag(ConnFlags::CONNECTED) {
            panic!("already connected");
        }

        let sk = StaticSecret::from(self.secret);

        self.remote_public = remote_public;
        self.secret = sk.diffie_hellman(&PublicKey::from(remote_public)).to_bytes();

        self.flags.set_flag(ConnFlags::CONNECTED);
    }
}

#[derive(Debug)]
struct ConnectPayload {
    version: u32,
    magic: u64,
    public_key: [u8; 32],
    timestamp: u64
}

fn decode_connect(payload: &[u8]) -> Result<ConnectPayload> {
    if payload.len() != CONNECT_PAYLOAD {
        return Err(Error::InvalidMessage);
    }

    let mut offset = 0;

    Ok(ConnectPayload {
        version: slice_reader::try_read_uint32(payload, &mut offset)?,
        magic: slice_reader::try_read_uint64(payload, &mut offset)?,
        public_key: slice_reader::try_read_array::<32>(payload, &mut offset)?,
        timestamp: slice_reader::try_read_uint64(payload, &mut offset)?,
    })
}

fn validate_connect(payload: &ConnectPayload) -> Result<()> {
    if payload.version < MIN_PROTOCOL_VERSION {
        return Err(Error::InvalidVersion);
    }

    if payload.magic != NETWORK_MAGIC {
        return Err(Error::InvalidNetwork);
    }

    let now_timestamp = time::try_now().map_err(|_| Error::UnknownError)?;
    let is_past = now_timestamp > payload.timestamp;
    let diff = if is_past { now_timestamp - payload.timestamp } else { payload.timestamp - now_timestamp };

    // Do not allow more than 1 minute old, or 5 second in the future.
    if (is_past && diff >= time::MINUTE_MS) || (!is_past && diff >= (time::SECOND_MS * 5)) {
        return Err(Error::InvalidTime);
    }

    Ok(())
}

fn encode_connect(payload: &ConnectPayload) -> Result<[u8; CONNECT_PAYLOAD]> {
    let mut buf = [0u8; CONNECT_PAYLOAD];
    let mut offset: usize = 0;

    slice_writer::try_write_uint32(payload.version, &mut buf, &mut offset)?;
    slice_writer::try_write_uint64(payload.magic, &mut buf, &mut offset)?;
    slice_writer::try_write_array(&payload.public_key, &mut buf, &mut offset)?;
    slice_writer::try_write_uint64(payload.timestamp, &mut buf, &mut offset)?;

    Ok(buf)
}

#[derive(Debug)]
struct ConnectFlags {
    attempts: u8,
    received_conn: bool
}

fn decode_connect_flags(flags: u16) -> ConnectFlags {
    ConnectFlags {
        attempts: ((flags >> 1) & 0b1111) as u8,
        received_conn: (flags & 0b1) != 0
    }
}

fn encode_connect_flags(flag_opts: &ConnectFlags) -> Result<u16> {
    if flag_opts.attempts > 15 {
        return Err(Error::UnknownError);
    }

    let mut flags = (flag_opts.attempts << 1) as u16;

    if flag_opts.received_conn {
        flags |= 1;
    }

    Ok(flags)
}

impl Client {
    pub(crate) async fn process_connect(&self, addr: SocketAddrV6, flags: u16, payload: &[u8]) -> Result<()> {
        let payload = decode_connect(payload)?;
        validate_connect(&payload)?;

        let flags = decode_connect_flags(flags);
        let mut local_public = [0u8; 32];
        let mut local_attempts = NO_ATTEMPTS;

        // Have to scope this, as borrow can't exist when await is called.
        {
            let mut connections = self.connections.try_borrow_mut()?;

            let conn = match connections.entry(addr) {
                Entry::Occupied(entry) => {
                    let conn = entry.into_mut();

                    if conn.local_public == payload.public_key {
                        // ensure when connecting, to check if was removed
                        connections.remove(&addr);

                        return Err(Error::SelfConnect);
                    }

                    if conn.flags.get_flag(ConnFlags::CONNECTED) && conn.remote_public != payload.public_key {
                        if flags.received_conn {
                            // ensure when connecting, to check if was removed
                            connections.remove(&addr);

                            return Err(Error::Disconnected);
                        }

                        conn.reset()?;

                        println!("Swapped Connection");
                    } else if conn.external_attempts != NO_ATTEMPTS && conn.external_attempts >= flags.attempts {
                        return Err(Error::DuplicatePacket);
                    }

                    conn
                },
                Entry::Vacant(entry) => {
                    if flags.received_conn {
                        // no need to remove connection here, since Vacant means it doesn't exist.
                        return Err(Error::Disconnected);
                    }

                    let conn = Connection::new(false)?;
                    entry.insert(conn)
                }
            };

            conn.external_attempts = flags.attempts;

            if !conn.flags.get_flag(ConnFlags::CONNECTED) {
                conn.set_connection(payload.public_key);
            }

            if !flags.received_conn {
                if conn.local_attempts == NO_ATTEMPTS {
                    conn.local_attempts = 0;
                } else {
                    conn.local_attempts += 1;
                }

                local_public = conn.local_public;
                local_attempts = conn.local_attempts;
            }
        }

        if !flags.received_conn {
            let outbound_flags = encode_connect_flags(&ConnectFlags {
                attempts: local_attempts,
                received_conn: true
            })?;

            let header = encode_header(&Header {
                msg_type: MessageType::Connect,
                msg_flags: outbound_flags
            })?;

            let payload = encode_connect(&ConnectPayload {
                version: PROTOCOL_VERSION,
                magic: NETWORK_MAGIC,
                public_key: local_public,
                timestamp: time::try_now().map_err(|_| Error::UnknownError)?
            })?;

            let mut packet = [0u8; HEADER_SIZE + CONNECT_PAYLOAD];
            packet[0..HEADER_SIZE].copy_from_slice(&header);
            packet[HEADER_SIZE..HEADER_SIZE + CONNECT_PAYLOAD].copy_from_slice(&payload);

            println!("{:?}", addr);
            self.socket.send_to(&packet, sockaddr(addr)).await?;
            sleep(Duration::from_millis(100)).await;
        }

        Ok(())
    }
}