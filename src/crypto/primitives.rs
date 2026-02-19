use postcard;
use ring::{
    rand::SystemRandom,
    signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey},
};
use serde::Serialize;
use std::{collections::HashMap, path::Path};
use tokio::fs;

use crate::message::message_types::{
    Commit, PBFTMessage, PrePrepare, Prepare, Request, SignedMessage,
};

pub struct Crypto {
    keypair: Ed25519KeyPair,
    id: u32,
    peer_public_keys: HashMap<u32, Vec<u8>>,
}

impl Crypto {
    pub fn new(keypair: Ed25519KeyPair, id: u32, peer_public_keys: HashMap<u32, Vec<u8>>) -> Self {
        Crypto {
            keypair,
            id,
            peer_public_keys,
        }
    }

    pub fn get_pub_key(&self) -> Vec<u8> {
        self.keypair.public_key().as_ref().to_vec()
    }

    pub fn generate_keypair() -> Vec<u8> {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        pkcs8.as_ref().to_vec()
    }

    pub fn sign<T: Serialize>(&self, message: &T) -> Vec<u8> {
        let serialized = postcard::to_allocvec(message).unwrap();
        let signature = self.keypair.sign(&serialized);
        signature.as_ref().to_vec()
    }

    pub fn create_signed_message<T: Serialize>(&self, message: T) -> SignedMessage<T> {
        let signature = self.sign(&message);
        SignedMessage {
            message,
            signature,
            signer_id: self.id,
        }
    }

    pub fn verify_signed_message<T: Serialize>(&self, signed_msg: &SignedMessage<T>) -> bool {
        let pk_bytes = match self.peer_public_keys.get(&signed_msg.signer_id) {
            Some(pk) => pk,
            None => return false,
        };

        let serialized = match postcard::to_allocvec(&signed_msg.message) {
            Ok(data) => data,
            Err(_) => return false,
        };

        let pk = UnparsedPublicKey::new(&ED25519, pk_bytes);
        pk.verify(&serialized, &signed_msg.signature).is_ok()
    }
}

impl Crypto {
    fn sign_request(&self, request: Request) -> SignedMessage<Request> {
        self.create_signed_message(request)
    }

    fn sign_pre_prepare(&self, pre_prepare: PrePrepare) -> SignedMessage<PrePrepare> {
        self.create_signed_message(pre_prepare)
    }

    fn sign_prepare(&self, prepare: Prepare) -> SignedMessage<Prepare> {
        self.create_signed_message(prepare)
    }

    fn sign_commit(&self, commit: Commit) -> SignedMessage<Commit> {
        self.create_signed_message(commit)
    }

    pub fn verify_pbft_message(&self, message: &PBFTMessage) -> bool {
        match message {
            PBFTMessage::Request(request) => self.verify_signed_message(request),
            PBFTMessage::PrePrepare(pre_prepare) => self.verify_signed_message(pre_prepare),
            PBFTMessage::Prepare(prepare) => self.verify_signed_message(prepare),
            PBFTMessage::Commit(commit) => self.verify_signed_message(commit),
            PBFTMessage::Reply(reply) => self.verify_signed_message(reply),
        }
    }
}

pub async fn setup_crypto_for_node(node_id: u32) -> (Crypto, HashMap<u32, Vec<u8>>) {
    let keys_dir = Path::new("keys");

    let my_key_path = keys_dir.join(format!("node_{}.key", node_id));
    let my_pub_path = keys_dir.join(format!("node_{}.pub", node_id));

    if !my_key_path.exists() {
        panic!("Keys not found! Run 'cargo run --bin keygen' first");
    }

    let pkcs8_bytes = fs::read(&my_key_path)
        .await
        .expect("Failed to read private key");

    let my_keypair = Ed25519KeyPair::from_pkcs8(&pkcs8_bytes).expect("Failed to parse keypair");

    let mut peer_public_keys = HashMap::new();
    for peer_id in 0..4 {
        if peer_id == node_id {
            continue;
        }

        let peer_pub_path = keys_dir.join(format!("node_{}.pub", peer_id));

        if !peer_pub_path.exists() {
            panic!(
                "Peer {} public key not found! Run 'cargo run --bin keygen' first",
                peer_id
            );
        }

        let pub_key = fs::read(&peer_pub_path)
            .await
            .expect(&format!("Failed to read public key for peer {}", peer_id));

        peer_public_keys.insert(peer_id, pub_key);
    }

    let crypto = Crypto::new(my_keypair, node_id, peer_public_keys.clone());

    (crypto, peer_public_keys)
}
