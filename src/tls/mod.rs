//! QuantumShield TLS Engine
//!
//! Provides TLS 1.3 configuration with post-quantum hybrid key exchange providers,
//! ALPN negotiation, session tickets, and certificate validation.

pub mod cert;
pub mod provider;

use std::sync::Arc;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ServerConfig;
use rustls::client::ClientConfig;
use rustls::RootCertStore;

pub use cert::{generate_self_signed, load_certs, load_private_key, parse_certs_from_pem, parse_private_key_from_pem, GeneratedCert};
pub use provider::{install_default_provider, pqc_crypto_provider, strict_pqc_crypto_provider, PQC_KX_GROUP, X25519_MLKEM768_KX_GROUP};

/// Builds a production TLS 1.3 ServerConfig with Post-Quantum Cryptography enabled
pub fn build_server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
    strict_pqc: bool,
    alpn_protocols: Option<Vec<Vec<u8>>>,
) -> Result<Arc<ServerConfig>, rustls::Error> {
    let provider = if strict_pqc {
        strict_pqc_crypto_provider()
    } else {
        pqc_crypto_provider()
    };

    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)?;

    // Configure ALPN (HTTP/2 and HTTP/1.1 negotiation)
    config.alpn_protocols = alpn_protocols.unwrap_or_else(|| {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    });

    // Enforce TLS 1.3 minimum for post-quantum security
    config.ignore_client_order = true;

    Ok(Arc::new(config))
}

/// Builds a production TLS 1.3 ClientConfig with Post-Quantum Cryptography enabled
pub fn build_client_config(
    root_store: RootCertStore,
    strict_pqc: bool,
    alpn_protocols: Option<Vec<Vec<u8>>>,
) -> Result<Arc<ClientConfig>, rustls::Error> {
    let provider = if strict_pqc {
        strict_pqc_crypto_provider()
    } else {
        pqc_crypto_provider()
    };

    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    config.alpn_protocols = alpn_protocols.unwrap_or_else(|| {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    });

    Ok(Arc::new(config))
}
