use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use crate::{
    Error,
    Result,
    socket::{Socket}
};
use crate::messages::MessageType;
use crate::constants::{PROTOCOL_VERSION, NETWORK_MAGIC, MIN_PROTOCOL_VERSION};
use utils::{slice_reader, time};
use sha2::{Sha256, Digest};

#[derive(Debug)]
struct HelloPayload {
    version: u32,
    magic: u64,
    public_key: [u8; 32],
    session_token: [u8; 32],
    flags: u32,
    sequence: u64,
    timestamp: u64,
    signature: [u8; 64],
    sign_hash: [u8; 32]
}

async fn read_hello(socket: &mut Socket) -> Result<HelloPayload> {
    let (header, payload) = socket.read_basic_message().await?;

    if !matches!(header.msg_type, MessageType::Hello) {
        return Err(Error::InvalidMessage);
    }

    if payload.len() != 160 {
        return Err(Error::InvalidPayloadSize);
    }

    let payload_slice = payload.as_slice();
    let mut offset: usize = 0;

    let sign_hash: [u8; 32] = Sha256::digest(
        // Exclude Signature
        &payload.as_slice()[..payload_slice.len() - 64]
    ).into();

    Ok(HelloPayload {
        version: slice_reader::try_read_uint32(payload_slice, &mut offset)?,
        magic: slice_reader::try_read_uint64(payload_slice, &mut offset)?,
        public_key: slice_reader::try_read_array::<32>(payload_slice, &mut offset)?,
        session_token: slice_reader::try_read_array::<32>(payload_slice, &mut offset)?,
        flags: slice_reader::try_read_uint32(payload_slice, &mut offset)?,
        sequence: slice_reader::try_read_uint64(payload_slice, &mut offset)?,
        timestamp: slice_reader::try_read_uint64(payload_slice, &mut offset)?,
        signature: slice_reader::try_read_array::<64>(payload_slice, &mut offset)?,
        sign_hash
    })
}

fn validate_hello(payload: &HelloPayload) -> Result<()> {
    if payload.version < MIN_PROTOCOL_VERSION {
        return Err(Error::AuthError);
    }

    if payload.magic != NETWORK_MAGIC {
        return Err(Error::AuthError);
    }

    let now_timestamp = time::try_now()?;
    let is_past = now_timestamp > payload.timestamp;
    let diff = if is_past { now_timestamp - payload.timestamp } else { payload.timestamp - now_timestamp };

    // Do not allow more than 1 minute old, or 5 second in the future.
    if (is_past && diff >= time::MINUTE_MS) || (!is_past && diff >= (time::SECOND_MS * 5)) {
        return Err(Error::AuthError);
    }

    let public_key = VerifyingKey::from_bytes(&payload.public_key)?;
    public_key.verify(&payload.sign_hash, &Signature::from_bytes(&payload.signature))?;

    Ok(())
}

pub async fn process_auth(socket: &mut Socket) -> Result<()> {
    let hello_in = read_hello(socket).await?;
    validate_hello(&hello_in)?;

    Ok(())
}