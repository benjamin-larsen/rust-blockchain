use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

pub fn sockaddr_v6(addr: SocketAddr) -> SocketAddrV6 {
    match addr {
        SocketAddr::V6(addr) => addr,
        SocketAddr::V4(addr) => {
            let ip = addr.ip().to_ipv6_mapped();

            SocketAddrV6::new(ip, addr.port(), 0, 0)
        }
    }
}

pub fn sockaddr(addr: SocketAddrV6) -> SocketAddr {
    if let Some(ip4) = addr.ip().to_ipv4() {
        let socket_addr = SocketAddrV4::new(ip4, addr.port());

        socket_addr.into()
    } else {
        addr.into()
    }
}