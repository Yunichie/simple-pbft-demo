use ring::signature::Ed25519KeyPair;
use simple_pbft_demo::{
    crypto::primitives::Crypto,
    message::message_types::{PBFTMessage, Request},
};
use std::{collections::HashMap, net::SocketAddr};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <operation>", args[0]);
        eprintln!("  Example: {} 'PUT:name:Alice'", args[0]);
        std::process::exit(1);
    }

    let operation = args[1].as_bytes().to_vec();

    let primary_addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

    let client_pkcs8 = Crypto::generate_keypair();
    let kp = Ed25519KeyPair::from_pkcs8(client_pkcs8.as_ref()).unwrap();
    let client_crypto = Crypto::new(kp, 999, HashMap::new());

    let request = Request {
        operation,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64,
        client_id: 999,
    };

    let signed_request = client_crypto.create_signed_message(request);
    let message = PBFTMessage::Request(signed_request);

    println!("Sending request to primary...");
}
