#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
    ReadError(utils::slice_reader::ReadError),
    InvalidMessage,
    InvalidPayloadSize
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

pub type Result<T> = std::result::Result<T, Error>;