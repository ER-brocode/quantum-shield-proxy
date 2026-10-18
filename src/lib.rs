//! QuantumShield Proxy - High Performance Post-Quantum Cryptography TLS 1.3 Reverse Gateway
//!
//! QuantumShield Proxy terminates TLS 1.3 connections using NIST FIPS 203 (ML-KEM-768 / Kyber768)
//! and NIST FIPS 204 (ML-DSA-65 / Dilithium3) post-quantum cryptography, safeguarding against
//! future quantum cryptanalysis and "Harvest Now, Decrypt Later" adversaries.

pub mod config;
pub mod crypto;
pub mod gateway;
pub mod tls;

pub use config::GatewayConfig;
pub use crypto::hybrid_kem::{
    HybridCiphertext, HybridKeyPair, HybridPublicKey, HybridSharedSecret,
};
pub use gateway::{
    BalancingStrategy, GatewayMetrics, GatewayOptions, LoadBalancer, QuantumGateway,
};
pub use tls::{
    build_client_config, build_server_config, generate_self_signed, pqc_crypto_provider,
};
