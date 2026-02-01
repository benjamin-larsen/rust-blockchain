use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Handle;
use utils::NodeConfig;
use crate::socket::{handle_sock, SocketDirection, Socket};

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

async fn start_server(server_addr: String, server_port: u16, server: Arc<Server>) {
    let listener = TcpListener::bind((server_addr, server_port)).await.unwrap();

    if server_port == 0 {
        let local_port = listener.local_addr().unwrap().port();

        if local_port == 0 {
            panic!("Invalid local port.");
        }
        server.config.set_port(local_port);
    }

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

    if let Some(server_port) = server.config.server_port() {
        rt_handle.spawn(start_server(
            server.config.server_addr().to_owned(),
            server_port,
            server.clone()
        ));
    }

    return server;
}