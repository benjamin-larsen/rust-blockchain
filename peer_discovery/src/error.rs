#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
    ReadError(utils::slice_reader::ReadError),
    WriteError(utils::slice_writer::WriteError),
    BorrowError(std::cell::BorrowError),
    BorrowMutError(std::cell::BorrowMutError),
    RandError(utils::RandError),
    InvalidAddress,
    DuplicatePacket,
    InvalidPacket,
    InvalidMessage,
    Disconnected,
    SelfConnect,
    InvalidVersion,
    InvalidNetwork,
    InvalidTime,
    UnknownError
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

impl From<utils::slice_writer::WriteError> for Error {
    fn from(error: utils::slice_writer::WriteError) -> Error {
        Error::WriteError(error)
    }
}

impl From<std::cell::BorrowError> for Error {
    fn from(error: std::cell::BorrowError) -> Error {
        Error::BorrowError(error)
    }
}

impl From<std::cell::BorrowMutError> for Error {
    fn from(error: std::cell::BorrowMutError) -> Error {
        Error::BorrowMutError(error)
    }
}

impl From<utils::RandError> for Error {
    fn from(error: utils::RandError) -> Error {
        Error::RandError(error)
    }
}

pub type Result<T> = std::result::Result<T, Error>;