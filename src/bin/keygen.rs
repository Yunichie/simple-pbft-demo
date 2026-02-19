use ring::signature::{Ed25519KeyPair, KeyPair};
use std::path::Path;

#[tokio::main]
async fn main() {
    let keys_dir = Path::new("keys");

    tokio::fs::create_dir_all(keys_dir)
        .await
        .expect("Failed to create keys directory");

    println!("Generating keys for 4 nodes...");

    for node_id in 0..4 {
        let key_path = keys_dir.join(format!("node_{}.key", node_id));
        let pub_path = keys_dir.join(format!("node_{}.pub", node_id));

        if key_path.exists() {
            println!("Node {} keys already exist, skipping", node_id);
            continue;
        }

        let rng = ring::rand::SystemRandom::new();
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).expect("Key generation failed");

        let keypair =
            Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).expect("Failed to parse keypair");
        let pub_key = keypair.public_key().as_ref();

        tokio::fs::write(&key_path, pkcs8_bytes.as_ref())
            .await
            .expect("Failed to write private key");
        tokio::fs::write(&pub_path, pub_key)
            .await
            .expect("Failed to write public key");

        println!("Generated keys for node {}", node_id);
    }

    println!("\nAll keys generated successfully!");
    println!("Keys are stored in the 'keys' directory");
}
