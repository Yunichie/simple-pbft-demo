use quinn::{ClientConfig, Endpoint};
use ring::signature::Ed25519KeyPair;
use simple_pbft_demo::{
    crypto::primitives::Crypto,
    message::message_types::{PBFTMessage, Request},
};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};

fn make_insecure_client_config() -> rustls::ClientConfig {
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerification))
        .with_no_client_auth()
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

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

    println!("Sending request to primary at {}...", primary_addr);

    let rustls_client_cfg = make_insecure_client_config();
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    let quinn_client_cfg = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(rustls_client_cfg).unwrap(),
    ));

    endpoint.set_default_client_config(quinn_client_cfg);

    let connection = endpoint
        .connect(primary_addr, "peer")
        .expect("Failed to initiate connection")
        .await
        .expect("Failed to connect to primary");

    println!("Connected! Sending request...");

    let mut send_stream = connection.open_uni().await.unwrap();
    let serialized = postcard::to_allocvec(&message).unwrap();
    let len = serialized.len() as u32;

    send_stream
        .write_all(&len.to_be_bytes())
        .await
        .expect("Failed to write length");
    send_stream
        .write_all(&serialized)
        .await
        .expect("Failed to write message");
    send_stream.finish().expect("Failed to finish stream");

    println!("Request sent");

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    connection.close(0u32.into(), b"Done");
    endpoint.wait_idle().await;
}

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};

#[derive(Debug)]
struct SkipVerification;

impl rustls::client::danger::ServerCertVerifier for SkipVerification {
    fn verify_server_cert(
        &self,
        _end_entity_cert: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _sig: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _sig: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}
