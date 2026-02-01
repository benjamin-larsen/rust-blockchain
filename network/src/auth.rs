use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use hmac::{Hmac,Mac};
use crate::{
    Error,
    Result,
    socket::{Socket}
};
use crate::messages::{decode_basic_header, encode_basic_header, BasicHeader, MessageType, AUTH_HEADER_SIZE, BASIC_HEADER_SIZE};
use crate::constants::{PROTOCOL_VERSION, NETWORK_MAGIC, MIN_PROTOCOL_VERSION};
use utils::{slice_reader, slice_writer, time, try_generate_rand};
use sha2::{Sha256, Digest};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::messages::MessageType::Hello;

type HmacSha256 = Hmac<Sha256>;

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

impl Socket {
    async fn read_hello(&mut self) -> Result<HelloPayload> {
        let (header, payload) = self.read_basic_message().await?;

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

    fn encode_hello(&self, exch_key: &[u8; 32]) -> Result<[u8; 162]> {
        let mut buf = [0u8; 162];
        let buffer_len = buf.len();
        let mut offset: usize = 0;

        let keypair = self.server.config.keypair();
        let public_key = keypair.verifying_key().as_bytes().clone();
        let local_port = self.server.config.server_port().unwrap_or(0);

        slice_writer::try_write_uint32(PROTOCOL_VERSION, &mut buf, &mut offset)?;
        slice_writer::try_write_uint64(NETWORK_MAGIC, &mut buf, &mut offset)?;
        slice_writer::try_write_array(&public_key, &mut buf, &mut offset)?;
        slice_writer::try_write_array(exch_key, &mut buf, &mut offset)?;
        /* Node Flags */ slice_writer::try_write_uint32(0, &mut buf, &mut offset)?;
        slice_writer::try_write_uint16(local_port, &mut buf, &mut offset)?;
        slice_writer::try_write_uint64(self.local_sequence, &mut buf, &mut offset)?;
        slice_writer::try_write_uint64(time::try_now()?, &mut buf, &mut offset)?;

        let sign_hash: [u8; 32] = Sha256::digest(
            &buf.as_slice()[..buffer_len - 64]
        ).into();

        let signature = keypair.sign(&sign_hash);

        buf[buffer_len - 64..].copy_from_slice(signature.to_bytes().as_slice());

        Ok(buf)
    }

    async fn write_hello(&mut self, exch_key: &[u8; 32]) -> Result<()> {
        let payload = self.encode_hello(&exch_key)?;
        let _guard = self.write_mu.clone().acquire_owned().await?;

        self.write_basic_header(&BasicHeader {
            msg_type: Hello,
            msg_flags: 0,
            msg_length: payload.len() as u32,
        }).await?;

        self.stream.write_all(&payload).await?;
        self.stream.flush().await?;

        Ok(())
    }

    pub async fn process_auth(&mut self) -> Result<()> {
        let session_key = StaticSecret::from(try_generate_rand::<32>()?);

        self.write_hello(
            &PublicKey::from(&session_key).to_bytes()
        ).await?;

        let hello_in = self.read_hello().await?;
        // Validation should also include no duplicate Node PKs (or own Public Key)
        validate_hello(&hello_in)?;
        
        let shared_secret = session_key.diffie_hellman(
            &PublicKey::from(hello_in.exch_key)
        );

        self.remote_sequence = hello_in.sequence;
        self.hmac_key = Some(shared_secret.to_bytes());

        Ok(())
    }

    pub(crate) async fn read_authenticated_message(&mut self) -> Result<(BasicHeader, Vec<u8>)> {
        let Some(hmac_key) = self.hmac_key else {
            return Err(Error::InvalidMessage);
        };

        let expected_sequence = self.remote_sequence;
        self.remote_sequence += 1;

        let mut header_buf = [0u8; BASIC_HEADER_SIZE + AUTH_HEADER_SIZE];
        self.stream.read_exact(&mut header_buf).await?;

        let basic_header_buf = header_buf[0..BASIC_HEADER_SIZE]
            .try_into().map_err(|_| Error::InvalidMessage)?;

        let header = decode_basic_header(basic_header_buf)?;

        if header.msg_type.is_basic() {
            return Err(Error::InvalidMessage);
        }

        // Read Authentication Headers
        let signature: [u8; AUTH_HEADER_SIZE] = header_buf[BASIC_HEADER_SIZE..BASIC_HEADER_SIZE + AUTH_HEADER_SIZE]
            .try_into().map_err(|_| Error::InvalidMessage)?;

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
            return Err(Error::AuthError);
        }

        Ok((header, payload))
    }

    pub(crate) async fn write_authenticated_message(&mut self, header: &BasicHeader, payload: Vec<u8>) -> Result<()> {
        let Some(hmac_key) = self.hmac_key else {
            return Err(Error::InvalidMessage);
        };

        let sequence = self.local_sequence;
        self.local_sequence += 1;

        let basic_header_buf = encode_basic_header(header)?;

        let header_hash: [u8; 32] = Sha256::digest(&basic_header_buf).into();
        let payload_hash: [u8; 32] = Sha256::digest(&payload).into();

        let mut mac = HmacSha256::new_from_slice(&hmac_key)
            .map_err(|_| Error::HmacError)?;
        mac.update(&sequence.to_le_bytes());
        mac.update(&header_hash);
        mac.update(&payload_hash);

        let signature: [u8; 32] = mac.finalize().into_bytes().into();

        {
            let _guard = self.write_mu.clone().acquire_owned().await?;

            // Basic Header
            self.stream.write_all(&basic_header_buf).await?;

            // Authentication Header
            self.stream.write_all(&signature).await?;

            self.stream.write_all(&payload).await?;
            self.stream.flush().await?;
        }

        Ok(())
    }
}