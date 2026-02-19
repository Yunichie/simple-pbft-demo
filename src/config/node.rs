use std::net::SocketAddr;

#[derive(Clone)]
pub struct NodeConfig {
    id: u32,
    pub bind_addr: SocketAddr,
    pub peers: Vec<PeerConfig>,
}

#[derive(Clone)]
pub struct PeerConfig {
    pub id: u32,
    pub addr: SocketAddr,
}

pub fn get_node_config(node_id: u32) -> NodeConfig {
    // hardcoded 4 addrs for 4 nodes setup
    let all_addrs = vec![
        "127.0.0.1:5000",
        "127.0.0.1:5001",
        "127.0.0.1:5002",
        "127.0.0.1:5003",
    ];

    let bind_addr: SocketAddr = all_addrs[node_id as usize].parse().unwrap();

    let peers: Vec<PeerConfig> = all_addrs
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != node_id as usize)
        .map(|(i, addr)| PeerConfig {
            id: i as u32,
            addr: addr.parse().unwrap(),
        })
        .collect();

    NodeConfig {
        id: node_id,
        bind_addr,
        peers,
    }
}
