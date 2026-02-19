use simple_pbft_demo::{
    config::node::get_node_config,
    crypto::primitives::setup_crypto_for_node,
    network::{cert::NodeCert, network_layer::Network},
    state::replica::Replica,
};
use std::env;

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        std::process::exit(1);
    }

    let node_id: u32 = args[1].parse().unwrap();

    if node_id > 3 {
        std::process::exit(1);
    }

    println!("Starting node {}...", node_id);

    let config = get_node_config(node_id);
    let (crypto, peer_pk) = setup_crypto_for_node(node_id).await;
    let certs = NodeCert::generate(node_id);
    let mut network = Network::new(node_id, config.bind_addr, &certs, 4);
    network.spawn_acceptor();
    println!("Node {} listening on {}", node_id, config.bind_addr);
    let mut replica = Replica::new(node_id, 4, crypto);

    println!("Waiting for other nodes to start...");
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    println!("Connecting to peers...");
    for peer in &config.peers {
        println!("  Connecting to peer {} at {}...", peer.id, peer.addr);

        let mut retries = 5;
        loop {
            match network
                .connect_to_peer_with_timeout(peer.id, peer.addr)
                .await
            {
                Ok(_) => {
                    println!("Connected to peer {}", peer.id);
                    break;
                }
                Err(e) => {
                    retries -= 1;
                    if retries == 0 {
                        eprintln!("Failed to connect to peer {}: {:?}", peer.id, e);
                        eprintln!("Make sure node {} is running!", peer.id);
                        std::process::exit(1);
                    }
                    println!(
                        "Retrying connection to peer {} ({} attempts left)...",
                        peer.id, retries
                    );
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                }
            }
        }
    }

    println!(
        "Node {} ready! (Primary: {})",
        node_id,
        replica.is_primary()
    );

    Replica::run_replica(network, replica, config).await;
}
