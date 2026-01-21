use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Handle;
use crate::socket::{handle_sock, SocketDirection, Socket};
use ed25519_dalek::SigningKey;

pub trait NodeConfig: Send + Sync {
    fn server_addr(&self) -> &str;
    fn server_port(&self) -> u16;
    fn keypair(&self) -> &SigningKey;
}
pub struct Server {
    pub(crate) config: Arc<dyn NodeConfig>,
}

impl Server {
    pub fn connect(self: &Arc<Server>, addr: SocketAddr, rt_handle: &Handle) {
        let server_clone = self.clone();

        rt_handle.spawn(async move {
            let Ok(stream) = TcpStream::connect(addr).await else {
                println!("Failed to connect.");
                return;
            };

            let addr = stream.peer_addr();

            let Ok(socket) = Socket::new(
                stream,
                server_clone,
                SocketDirection::Outbound
            ) else {
                println!("Failed to initialize Socket.");
                return;
            };

            println!("Connected to {:?}", addr);

            if let Err(err) = handle_sock(socket).await {
                println!("{:?}", err)
            }

            println!("Connection ended {:?}", addr);
        });
    }
}

async fn start_server(server: Arc<Server>) {
    let listener = TcpListener::bind((server.config.server_addr(), server.config.server_port())).await.unwrap();

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
) -> Arc<Server> {
    let server = Arc::new(Server {
        config,
    });

    if server.config.server_port() != 0 {
        let server_clone = server.clone();

        rt_handle.spawn(async move {
            start_server(server_clone).await;
        });
    }

    return server;
}