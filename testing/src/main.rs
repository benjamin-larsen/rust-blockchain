use std::sync::Arc;
use account::Address;
use network::{server, NodeConfig};
use tokio::runtime::Builder;
use std::thread::available_parallelism;

struct TestNode {

}

impl NodeConfig for TestNode {
    fn server_addr(&self) -> &str {
        return "127.0.0.1:6350";
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

    let node = Arc::new(TestNode{});

    server::spawn(node.clone(), rt_handle);

    println!("Hello, world! {}", node.server_addr());

    std::thread::park();
}
