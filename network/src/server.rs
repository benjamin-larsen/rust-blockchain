use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::runtime::Handle;
use crate::socket::{handle_sock, SocketDirection, Socket};
use ed25519_dalek::SigningKey;

pub trait NodeConfig: Send + Sync {
    fn server_addr(&self) -> &str;
    fn keypair(&self) -> &SigningKey;
}

pub struct Server {
    pub(crate) config: Arc<dyn NodeConfig>,
}

async fn start_server(server: Arc<Server>) {
    let listener = TcpListener::bind(server.config.server_addr()).await.unwrap();

    loop {
        let Ok((socket, _)) = listener.accept().await else {
            println!("Failed to accept connection");
            continue;
        };

        let server_ref = server.clone();

        tokio::spawn(async move {
            let addr = socket.peer_addr();

            let Ok(socket) = Socket::new(
                socket,
                server_ref,
                SocketDirection::Inbound
            ) else {
                println!("Failed to initialize Socket.");
                return;
            };

            println!("Got connection from {:?}", addr);

            if let Err(err) = handle_sock(socket).await {
                println!("{:?}", err)
            }

            println!("Connection ended {:?}", addr);
        });
    }
}

pub fn spawn(
    config: Arc<dyn NodeConfig>,
    rt_handle: &Handle,
) {
    rt_handle.spawn(async move {
        let server = Arc::new(Server {
            config,
        });

        start_server(server).await;
    });
}