use rcgen::generate_simple_self_signed;
use rustls::{ClientConfig, ServerConfig};
use std::sync::Arc;

pub struct NodeCert {
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
}

impl NodeCert {
    fn generate(node_id: u32) -> Self {
        let subject_name = vec![format!("node-{}", node_id)];
        let cert = generate_simple_self_signed(subject_name).unwrap();

        NodeCert {
            cert_der: cert.cert.der().to_vec(),
            key_der: cert.signing_key.serialize_der(),
        }
    }
}

pub fn make_server_config(cert: &NodeCert) -> ServerConfig {
    let cert_chain = vec![rustls::pki_types::CertificateDer::from(
        cert.cert_der.clone(),
    )];
    let key = rustls::pki_types::PrivateKeyDer::try_from(cert.key_der.clone()).unwrap();

    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .unwrap()
}

pub fn make_client_config() -> ClientConfig {
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerification))
        .with_no_client_auth();
    config
}

#[derive(Debug)]
struct SkipVerification;

impl rustls::client::danger::ServerCertVerifier for SkipVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer,
        _intermediates: &[rustls::pki_types::CertificateDer],
        _server_name: &rustls::pki_types::ServerName,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }
}
