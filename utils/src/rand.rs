use rand::rand_core::{OsError, OsRng};
use rand::TryRngCore;

pub type RandError = OsError;

pub fn try_generate_rand<const N: usize>() -> Result<[u8; N], RandError> {
    let mut secret_key = [0u8; N];
    OsRng.try_fill_bytes(&mut secret_key)?;
    
    Ok(secret_key)
}

pub fn generate_rand<const N: usize>() -> [u8; N] {
    try_generate_rand::<N>().expect("Failed to generate random number")
}