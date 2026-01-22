use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use crate::{
    Error,
    Result,
    socket::{Socket}
};
use crate::messages::{BasicHeader, MessageType};
use crate::constants::{PROTOCOL_VERSION, NETWORK_MAGIC, MIN_PROTOCOL_VERSION};
use utils::{slice_reader, slice_writer, time, try_generate_rand};
use sha2::{Sha256, Digest};
use x25519_dalek::{PublicKey, StaticSecret};
use tokio::io::AsyncWriteExt;
use crate::messages::MessageType::Hello;

#[derive(Debug)]
struct HelloPayload {
    version: u32,
    magic: u64,
    public_key: [u8; 32],
    exch_key: [u8; 32],
    flags: u32,
    server_port: u16,
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

    if payload.len() < 162 {
        return Err(Error::InvalidPayloadSize);
    }

    let payload_slice = payload.as_slice();
    let payload_len = payload_slice.len();
    let mut offset: usize = 0;

    let sign_hash: [u8; 32] = Sha256::digest(
        // Exclude Signature
        &payload.as_slice()[..payload_len - 64]
    ).into();

    Ok(HelloPayload {
        version: slice_reader::try_read_uint32(payload_slice, &mut offset)?,
        magic: slice_reader::try_read_uint64(payload_slice, &mut offset)?,
        public_key: slice_reader::try_read_array::<32>(payload_slice, &mut offset)?,
        exch_key: slice_reader::try_read_array::<32>(payload_slice, &mut offset)?,
        flags: slice_reader::try_read_uint32(payload_slice, &mut offset)?,
        server_port: slice_reader::try_read_uint16(payload_slice, &mut offset)?,
        sequence: slice_reader::try_read_uint64(payload_slice, &mut offset)?,
        timestamp: slice_reader::try_read_uint64(payload_slice, &mut offset)?,

        // Get last 64 bytes as signature
        signature: payload_slice[payload_len - 64..].try_into().map_err(|_| slice_reader::ReadError)?,
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

fn encode_hello(socket: &Socket, exch_key: &[u8; 32]) -> Result<[u8; 162]> {
    let mut buf = [0u8; 162];
    let buffer_len = buf.len();
    let mut offset: usize = 0;

    let keypair = socket.server.config.keypair();
    let public_key = keypair.verifying_key().as_bytes().clone();

    slice_writer::try_write_uint32(PROTOCOL_VERSION, &mut buf, &mut offset)?;
    slice_writer::try_write_uint64(NETWORK_MAGIC, &mut buf, &mut offset)?;
    slice_writer::try_write_array(&public_key, &mut buf, &mut offset)?;
    slice_writer::try_write_array(exch_key, &mut buf, &mut offset)?;
    /* Node Flags */ slice_writer::try_write_uint32(0, &mut buf, &mut offset)?;
    slice_writer::try_write_uint16(socket.server.config.server_port(), &mut buf, &mut offset)?;
    slice_writer::try_write_uint64(socket.local_sequence, &mut buf, &mut offset)?;
    slice_writer::try_write_uint64(time::try_now()?, &mut buf, &mut offset)?;

    let sign_hash: [u8; 32] = Sha256::digest(
        &buf.as_slice()[..buffer_len - 64]
    ).into();

    let signature = keypair.sign(&sign_hash);

    buf[buffer_len - 64..].copy_from_slice(signature.to_bytes().as_slice());

    Ok(buf)
}

async fn write_hello(socket: &mut Socket, exch_key: &[u8; 32]) -> Result<()> {
    let payload = encode_hello(socket, &exch_key)?;
    let _guard = socket.write_mu.clone().acquire_owned().await?;

    socket.write_basic_header(&BasicHeader {
        msg_type: Hello,
        msg_flags: 0,
        msg_length: payload.len() as u32,
    }).await?;

    socket.stream.write_all(&payload).await?;
    socket.stream.flush().await?;

    Ok(())
}

pub async fn process_auth(socket: &mut Socket) -> Result<()> {
    let session_key = StaticSecret::from(try_generate_rand::<32>()?);

    write_hello(
        socket,
        &PublicKey::from(&session_key).to_bytes()
    ).await?;

    let hello_in = read_hello(socket).await?;
    // Validation should also include no duplicate Node PKs (or own Public Key)
    validate_hello(&hello_in)?;

    let shared_secret = session_key.diffie_hellman(
        &PublicKey::from(hello_in.exch_key)
    );

    socket.remote_sequence = hello_in.sequence;
    socket.hmac_key = Some(shared_secret.to_bytes());

    Ok(())
}