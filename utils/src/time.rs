use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};

pub const SECOND_MS: u64 = 1000;
pub const MINUTE_MS: u64 = SECOND_MS * 60;

#[derive(Debug)]
pub enum TimeError {
    SystemTimeError(SystemTimeError),
    InvalidTime,
}

pub fn try_now() -> Result<u64, TimeError> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(TimeError::SystemTimeError)?
            .as_millis()
    ).map_err(|_| TimeError::InvalidTime)
}

pub fn now() -> u64 {
    try_now().expect("UNIX Time Failed")
}