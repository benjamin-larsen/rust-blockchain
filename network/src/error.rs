#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
    InvalidMessage,
    InvalidPayloadSize
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Error {
        Error::IoError(error)
    }
}