#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
    AcquireError(tokio::sync::AcquireError),
    ReadError(utils::slice_reader::ReadError),
    WriteError(utils::slice_writer::WriteError),
    RandError(utils::RandError),
    TimeError(utils::time::TimeError),
    SignatureError(ed25519_dalek::SignatureError),
    HmacError,
    InvalidMessage,
    InvalidPayloadSize,
    AuthError,
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Error {
        Error::IoError(error)
    }
}

impl From<tokio::sync::AcquireError> for Error {
    fn from(error: tokio::sync::AcquireError) -> Error {
        Error::AcquireError(error)
    }
}

impl From<utils::slice_reader::ReadError> for Error {
    fn from(error: utils::slice_reader::ReadError) -> Error {
        Error::ReadError(error)
    }
}

impl From<utils::slice_writer::WriteError> for Error {
    fn from(error: utils::slice_writer::WriteError) -> Error {
        Error::WriteError(error)
    }
}

impl From<utils::RandError> for Error {
    fn from(error: utils::RandError) -> Error {
        Error::RandError(error)
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