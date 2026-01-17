use sha2::{Sha256, Digest};
use bs58::{encode, decode, decode::Error as Base58Error};

#[derive(Debug)]
pub struct Address(pub [u8; 32]);
pub struct PublicKey(pub [u8; 32]);

#[derive(Debug)]
pub enum DecodeError {
    Base58(Base58Error),
    InvalidLength,
    InvalidChecksum
}

impl DecodeError {
    pub fn from_base58(error: Base58Error) -> DecodeError {
        match error {
            Base58Error::BufferTooSmall => DecodeError::InvalidLength,
            Base58Error::NoChecksum => DecodeError::InvalidLength,
            Base58Error::InvalidChecksum { checksum: _, expected_checksum: _  } =>
                DecodeError::InvalidChecksum,
            other => DecodeError::Base58(other)
        }
    }
}

impl Address {
    pub fn from_public(public_key: PublicKey) -> Self {
        public_key.to_address()
    }

    pub fn to_string(&self) -> String {
        encode(self.0)
            .with_check()
            .into_string()
    }

    pub fn from_string(string: &str) -> Result<Self, DecodeError> {
        let mut decode_buf: [u8; 36] = [0; 36];

        println!("{}", string);

        let decode_result = decode(string)
            .with_check(None)
            .onto(&mut decode_buf);

        match decode_result {
            Ok(len) => {
                if len != 32 {
                    return Err(DecodeError::InvalidLength);
                }

                let address: [u8; 32] = decode_buf[..32].try_into().unwrap();

                Ok(Address(address))
            }

            Err(e) => Err(DecodeError::from_base58(e))
        }
    }
}

impl PublicKey {
    pub fn to_address(&self) -> Address {
        // use a GUID prefix
        Address(Sha256::digest(self.0).into())
    }
}