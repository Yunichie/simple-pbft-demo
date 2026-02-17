use postcard;
use ring::{
    rand::SystemRandom,
    signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey},
};
use serde::Serialize;
use std::collections::HashMap;

use crate::message::message_types::SignedMessage;

struct Crypto {
    keypair: Ed25519KeyPair,
    id: u32,
    peer_public_keys: HashMap<u32, Vec<u8>>,
}

impl Crypto {
    fn new(keypair: Ed25519KeyPair, id: u32, peer_public_keys: HashMap<u32, Vec<u8>>) -> Self {
        Crypto {
            keypair,
            id,
            peer_public_keys,
        }
    }

    fn get_pub_key(&self) -> Vec<u8> {
        self.keypair.public_key().as_ref().to_vec()
    }

    fn generate_keypair() -> Vec<u8> {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        pkcs8.as_ref().to_vec()
    }

    fn sign<T: Serialize>(&self, message: &T) -> Vec<u8> {
        let serialized = postcard::to_allocvec(message).unwrap();
        let signature = self.keypair.sign(&serialized);
        signature.as_ref().to_vec()
    }

    fn create_signed_message<T: Serialize>(&self, message: T) -> SignedMessage<T> {
        let signature = self.sign(&message);
        SignedMessage {
            message,
            signature,
            signer_id: self.id,
        }
    }

    fn verify_signed_message<T: Serialize>(&self, signed_msg: &SignedMessage<T>) -> bool {
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
