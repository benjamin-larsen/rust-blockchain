use std::sync::Arc;
use tokio::net::{TcpSocket, TcpStream};
use crate::server::Server;

pub enum SocketDirection {
    Inbound,
    Outbound,
}

pub struct Socket {
    pub stream: TcpStream,
    pub server: Arc<Server>,
    pub direction: SocketDirection
}

pub async fn handle_sock(socket: Socket) {
    loop {

    }
}