use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub(super) const SERVERS: [SocketAddr; 13] = [
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)), 53), // a.root-servers.net
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(170, 247, 170, 2)), 53), // b.root-servers.net
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 33, 4, 12)), 53), // c.root-servers.net
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(199, 7, 91, 13)), 53), // d.root-servers.net
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 203, 230, 10)), 53), // e.root-servers.net
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 5, 5, 241)), 53), // f.root-servers.net
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 112, 36, 4)), 53), // g.root-servers.net
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 97, 190, 53)), 53), // h.root-servers.net
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 36, 148, 17)), 53), // i.root-servers.net
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 58, 128, 30)), 53), // j.root-servers.net
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(193, 0, 14, 129)), 53), // k.root-servers.net
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(199, 7, 83, 42)), 53), // l.root-servers.net
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(202, 12, 27, 33)), 53), // m.root-servers.net
];
