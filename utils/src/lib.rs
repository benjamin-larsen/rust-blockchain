pub mod slice_reader;
pub mod slice_writer;
pub mod time;
mod rand;

pub use rand::{RandError, generate_rand, try_generate_rand};