pub mod server;
pub mod messages;

pub use error::{Error, Result};

mod socket;
mod error;
mod auth;
mod constants;