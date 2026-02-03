use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use account::Address;
use network::{server};
use utils::NodeConfig;
use tokio::runtime::Builder;
use std::thread::available_parallelism;
use ed25519_dalek::{SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use peer_discovery::start_discovery;
use utils::generate_rand;

struct TestNode {
    listen_addr: String,
    listen_port: AtomicU16,
    should_listen: bool,
    keypair: SigningKey,
}

impl NodeConfig for TestNode {
    fn server_addr(&self) -> &str {
        return self.listen_addr.as_str();
    }
    fn server_port(&self) -> Option<u16> {
        if !self.should_listen {
            return None;
        }

        return Some(self.listen_port.load(Ordering::Relaxed));
    }

    fn set_port(&self, port: u16) {
        self.listen_port.store(port, Ordering::Relaxed);
    }

    fn discovery_port(&self) -> u16 {
        return 1000;
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

    let secret_key = generate_rand();

    let node1 = Arc::new(TestNode{
        keypair: SigningKey::from(&secret_key),
        listen_addr: "127.0.0.1".to_string(),
        listen_port: AtomicU16::new(6350),
        should_listen: true,
    });

    let node2 = Arc::new(TestNode{
        keypair: SigningKey::from(&secret_key),
        listen_addr: "127.0.0.1".to_string(),
        listen_port: AtomicU16::new(0),
        should_listen: false, // Disable Listen
    });

    println!("{:02X?}", secret_key);

    let server1 = server::spawn(node1.clone(), rt_handle);
    let server2 = server::spawn(node2.clone(), rt_handle);

    start_discovery(node1.clone());
    //start_discovery(node2.clone());

    server2.connect("127.0.0.1:6350".parse().unwrap(), rt_handle);

    std::thread::park();
}
