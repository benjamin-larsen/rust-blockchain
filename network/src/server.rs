use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::runtime::Handle;
use crate::{handle_sock, SocketDirection};
use crate::socket::Socket;

pub trait NodeConfig: Send + Sync {
    fn server_addr(&self) -> &str;
}

pub struct Server {
    config: Arc<dyn NodeConfig>,
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
            println!("Got connection from {:?}", socket.peer_addr());
            handle_sock(Socket {
                stream: socket,
                server: server_ref,
                direction: SocketDirection::Inbound
            }).await;
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