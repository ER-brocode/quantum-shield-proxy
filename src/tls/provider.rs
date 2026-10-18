//! Post-Quantum Cryptography Provider for rustls 1.3
//!
//! Implements `rustls::crypto::SupportedKxGroup` and `rustls::crypto::ActiveKeyExchange`
//! for the hybrid X25519 + ML-KEM-768 key exchange group (`NamedGroup::X25519MLKEM768`, 0x11ec).

use std::fmt::Debug;
use std::sync::Arc;
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup};
use rustls::{Error as RustlsError, NamedGroup};

use crate::crypto::hybrid_kem::{
    encapsulate, HybridCiphertext, HybridKeyPair, HybridPublicKey,
};

/// The standard IETF codepoint for hybrid X25519 + ML-KEM-768 (draft-ietf-tls-hybrid-design)
pub const PQC_KX_GROUP: NamedGroup = NamedGroup::X25519MLKEM768;

/// Static instance of the QuantumShield Hybrid KX Group
pub static X25519_MLKEM768_KX_GROUP: X25519MlKem768KxGroup = X25519MlKem768KxGroup;

#[derive(Debug)]
pub struct X25519MlKem768KxGroup;

impl SupportedKxGroup for X25519MlKem768KxGroup {
    /// Client-side start: generates ephemeral hybrid keypair (X25519 + ML-KEM-768)
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, RustlsError> {
        let keypair = HybridKeyPair::generate();
        let pub_bytes = keypair.public_key.to_bytes().to_vec();

        Ok(Box::new(ActiveHybridKeyExchange {
            keypair: Some(keypair),
            pub_key: pub_bytes,
        }))
    }

    /// Server-side start & complete: given client's hybrid public key share,
    /// encapsulates post-quantum shared secret and returns server's ciphertext share
    fn start_and_complete(&self, peer_pub_key: &[u8]) -> Result<CompletedKeyExchange, RustlsError> {
        let client_pub = HybridPublicKey::from_bytes(peer_pub_key)
            .map_err(|e| RustlsError::General(format!("Invalid client PQC hybrid public key: {}", e)))?;

        let (ciphertext, shared_secret) = encapsulate(&client_pub)
            .map_err(|e| RustlsError::General(format!("Server PQC encapsulation failed: {}", e)))?;

        let server_share = ciphertext.to_bytes().to_vec();
        let ss = SharedSecret::from(shared_secret.as_bytes().as_slice());

        Ok(CompletedKeyExchange {
            group: PQC_KX_GROUP,
            pub_key: server_share,
            secret: ss,
        })
    }

    fn name(&self) -> NamedGroup {
        PQC_KX_GROUP
    }
}

/// Active key exchange handle held by client awaiting server's key share
struct ActiveHybridKeyExchange {
    keypair: Option<HybridKeyPair>,
    pub_key: Vec<u8>,
}

impl Debug for ActiveHybridKeyExchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActiveHybridKeyExchange")
            .field("pub_key_len", &self.pub_key.len())
            .finish()
    }
}

impl ActiveKeyExchange for ActiveHybridKeyExchange {
    /// Client-side complete: receives server's hybrid ciphertext and decapsulates the shared secret
    fn complete(mut self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, RustlsError> {
        let keypair = self.keypair.take()
            .ok_or_else(|| RustlsError::General("Hybrid keypair already consumed".into()))?;

        let server_ct = HybridCiphertext::from_bytes(peer_pub_key)
            .map_err(|e| RustlsError::General(format!("Invalid server PQC ciphertext: {}", e)))?;

        let shared_secret = keypair.decapsulate(&server_ct)
            .map_err(|e| RustlsError::General(format!("Client PQC decapsulation failed: {}", e)))?;

        Ok(SharedSecret::from(shared_secret.as_bytes().as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        PQC_KX_GROUP
    }
}

/// Constructs a full `CryptoProvider` configured with hybrid Post-Quantum Cryptography
/// as the highest-priority key exchange group, with fallback to classical X25519 and Secp256r1.
pub fn pqc_crypto_provider() -> CryptoProvider {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.kx_groups = vec![
        &X25519_MLKEM768_KX_GROUP,
        rustls::crypto::ring::kx_group::X25519,
        rustls::crypto::ring::kx_group::SECP256R1,
    ];
    provider
}

/// Constructs a strict PQC-only `CryptoProvider` that enforces NIST FIPS 203 ML-KEM-768
/// and rejects any legacy classical-only handshakes.
pub fn strict_pqc_crypto_provider() -> CryptoProvider {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.kx_groups = vec![&X25519_MLKEM768_KX_GROUP];
    provider
}

/// Installs the QuantumShield PQC CryptoProvider as the process-wide default for rustls
pub fn install_default_provider() -> Result<(), Arc<CryptoProvider>> {
    pqc_crypto_provider().install_default()
}
