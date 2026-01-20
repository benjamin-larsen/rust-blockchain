use std::sync::Arc;
use account::Address;
use network::{server, NodeConfig};
use tokio::runtime::Builder;
use std::thread::available_parallelism;
use ed25519_dalek::{SigningKey, VerifyingKey, SECRET_KEY_LENGTH};

use rand::TryRngCore;
use rand::rngs::OsRng;

struct TestNode {
    keypair: SigningKey,
}

impl NodeConfig for TestNode {
    fn server_addr(&self) -> &str {
        return "127.0.0.1:6350";
    }

    fn keypair(&self) -> &SigningKey {
        &self.keypair
    }
}

fn main() {
    let runtime = Builder::new_multi_thread()
        .worker_threads(available_parallelism().unwrap().get())
        .enable_io()
        .build()
        .unwrap();

    let rt_handle = runtime.handle();

    let addr: [u8; 32] = [50; 32];
    println!("{:?}", Address(addr).to_string());
    println!("{:?}", Address::from_string("P7C73q8RAy2XwNfjz6gHA6PvcSE5bbyiPQyE5QqqPpdMnwv3f"));

    let mut secret_key = [0u8; SECRET_KEY_LENGTH];
    OsRng.try_fill_bytes(&mut secret_key).unwrap();

    let node = Arc::new(TestNode{
        keypair: SigningKey::from(&secret_key),
    });

    println!("{:02X?}", secret_key);

    server::spawn(node.clone(), rt_handle);

    println!("Hello, world! {}", node.server_addr());

    std::thread::park();
}
