use std::sync::atomic::AtomicU16;
use ed25519_dalek::SigningKey;

pub trait NodeConfig: Send + Sync {
    fn server_addr(&self) -> &str;
    fn server_port(&self) -> Option<u16>;
    fn set_port(&self, port: u16);
    fn discovery_port(&self) -> u16;
    fn keypair(&self) -> &SigningKey;
}