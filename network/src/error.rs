#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
    ReadError(utils::slice_reader::ReadError),
    TimeError(utils::time::TimeError),
    SignatureError(ed25519_dalek::SignatureError),
    InvalidMessage,
    InvalidPayloadSize,
    AuthError,
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Error {
        Error::IoError(error)
    }
}

impl From<utils::slice_reader::ReadError> for Error {
    fn from(error: utils::slice_reader::ReadError) -> Error {
        Error::ReadError(error)
    }
}

impl From<utils::time::TimeError> for Error {
    fn from(error: utils::time::TimeError) -> Error {
        Error::TimeError(error)
    }
}

impl From<ed25519_dalek::SignatureError> for Error {
    fn from(error: ed25519_dalek::SignatureError) -> Error {
        Error::SignatureError(error)
    }
}

pub type Result<T> = std::result::Result<T, Error>;