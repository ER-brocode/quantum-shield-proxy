//! QuantumShield Cryptographic Engine
//!
//! Provides NIST FIPS 203 (ML-KEM-768 / CRYSTALS-Kyber) and NIST FIPS 204
//! (ML-DSA-65 / CRYSTALS-Dilithium) quantum-resistant primitives, as well as
//! the hybrid X25519 + ML-KEM-768 key exchange mechanism conforming to
//! `draft-ietf-tls-hybrid-design` and `draft-kwiatkowski-tls-ecdhe-mlkem`.

pub mod dilithium;
pub mod hybrid_kem;

pub use dilithium::{
    DilithiumKeyPair, DilithiumPublicKey, DilithiumSecretKey, DilithiumSignature,
    DILITHIUM_PUBLIC_KEY_SIZE, DILITHIUM_SIGNATURE_SIZE,
};
pub use hybrid_kem::{
    HybridCiphertext, HybridKeyPair, HybridPublicKey, HybridSharedSecret, HYBRID_CIPHERTEXT_SIZE,
    HYBRID_PUBLIC_KEY_SIZE, HYBRID_SHARED_SECRET_SIZE,
};
