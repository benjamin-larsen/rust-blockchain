pub const NETWORK_MAGIC: u64 = 0xbe48e224b3ae4681;
pub const PROTOCOL_VERSION: u32 = 0;
pub const MIN_PROTOCOL_VERSION: u32 = 0;
pub const MAX_ACTIVE: u32 = 6;
pub const MAX_PROBE: u32 = 2;

pub const HEADER_SIZE: usize = 4;
pub const SIGNATURE_SIZE: usize = 32;
pub const MIN_AUTH_PACKET: usize = HEADER_SIZE + SIGNATURE_SIZE;
pub const MAX_PACKET: usize = 1060;

pub const NO_ATTEMPTS: u8 = 255;