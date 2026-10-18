//! Hybrid Key Encapsulation Mechanism (X25519 + ML-KEM-768 / Kyber768)
//!
//! Implements post-quantum hybrid key exchange as specified in
//! draft-ietf-tls-hybrid-design and draft-kwiatkowski-tls-ecdhe-mlkem.
//!
//! Combining the battle-tested classical ECDH (X25519) with the lattice-based
//! NIST FIPS 203 ML-KEM-768 ensures that security holds as long as *at least one*
//! of the underlying primitives remains unbroken ("dual security").

use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, Encoded, MlKem768, MlKem768Params, SharedSecret};
use rand::rngs::OsRng;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

/// Wire size of X25519 public key in bytes
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;

/// Wire size of ML-KEM-768 (Kyber768) encapsulation key (FIPS 203)
pub const MLKEM768_ENCAPS_KEY_SIZE: usize = 1184;

/// Wire size of ML-KEM-768 ciphertext (FIPS 203)
pub const MLKEM768_CIPHERTEXT_SIZE: usize = 1088;

/// Wire size of hybrid public key: X25519 (32) + ML-KEM-768 (1184) = 1216 bytes
pub const HYBRID_PUBLIC_KEY_SIZE: usize = X25519_PUBLIC_KEY_SIZE + MLKEM768_ENCAPS_KEY_SIZE;

/// Wire size of hybrid ciphertext: X25519 ephemeral public key (32) + ML-KEM-768 ciphertext (1088) = 1120 bytes
pub const HYBRID_CIPHERTEXT_SIZE: usize = X25519_PUBLIC_KEY_SIZE + MLKEM768_CIPHERTEXT_SIZE;

/// Derived hybrid shared secret size (32 bytes / 256 bits for TLS 1.3 key schedule)
pub const HYBRID_SHARED_SECRET_SIZE: usize = 32;

/// Domain separation label for HKDF extraction & expansion
const HYBRID_KDF_LABEL: &[u8] = b"tls13 x25519_mlkem768 hybrid key exchange";

#[derive(Error, Debug, PartialEq, Eq)]
pub enum HybridCryptoError {
    #[error("Invalid public key length: expected {expected}, got {actual}")]
    InvalidPublicKeyLength { expected: usize, actual: usize },

    #[error("Invalid ciphertext length: expected {expected}, got {actual}")]
    InvalidCiphertextLength { expected: usize, actual: usize },

    #[error("ML-KEM key encapsulation failure")]
    EncapsulationFailed,

    #[error("ML-KEM key decapsulation failure")]
    DecapsulationFailed,

    #[error("Classical X25519 Diffie-Hellman computation resulted in all-zero shared secret")]
    WeakSharedSecret,

    #[error("KDF expansion failed")]
    KdfExpansionFailed,
}

/// Hybrid public key containing both classical X25519 and post-quantum ML-KEM-768 components
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridPublicKey {
    pub x25519_public: [u8; X25519_PUBLIC_KEY_SIZE],
    pub mlkem_public: [u8; MLKEM768_ENCAPS_KEY_SIZE],
}

impl HybridPublicKey {
    /// Creates a hybrid public key from separate components
    pub fn new(x25519: [u8; X25519_PUBLIC_KEY_SIZE], mlkem: [u8; MLKEM768_ENCAPS_KEY_SIZE]) -> Self {
        Self {
            x25519_public: x25519,
            mlkem_public: mlkem,
        }
    }

    /// Serializes the hybrid public key to raw wire bytes (1216 bytes)
    pub fn to_bytes(&self) -> [u8; HYBRID_PUBLIC_KEY_SIZE] {
        let mut out = [0u8; HYBRID_PUBLIC_KEY_SIZE];
        out[..X25519_PUBLIC_KEY_SIZE].copy_from_slice(&self.x25519_public);
        out[X25519_PUBLIC_KEY_SIZE..].copy_from_slice(&self.mlkem_public);
        out
    }

    /// Deserializes a hybrid public key from wire bytes
    pub fn from_bytes(slice: &[u8]) -> Result<Self, HybridCryptoError> {
        if slice.len() != HYBRID_PUBLIC_KEY_SIZE {
            return Err(HybridCryptoError::InvalidPublicKeyLength {
                expected: HYBRID_PUBLIC_KEY_SIZE,
                actual: slice.len(),
            });
        }
        let mut x25519 = [0u8; X25519_PUBLIC_KEY_SIZE];
        let mut mlkem = [0u8; MLKEM768_ENCAPS_KEY_SIZE];
        x25519.copy_from_slice(&slice[..X25519_PUBLIC_KEY_SIZE]);
        mlkem.copy_from_slice(&slice[X25519_PUBLIC_KEY_SIZE..]);
        Ok(Self {
            x25519_public: x25519,
            mlkem_public: mlkem,
        })
    }
}

/// Hybrid ciphertext containing the server's ephemeral X25519 public key and ML-KEM-768 ciphertext
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridCiphertext {
    pub x25519_ephemeral: [u8; X25519_PUBLIC_KEY_SIZE],
    pub mlkem_ciphertext: [u8; MLKEM768_CIPHERTEXT_SIZE],
}

impl HybridCiphertext {
    pub fn new(x25519: [u8; X25519_PUBLIC_KEY_SIZE], mlkem_ct: [u8; MLKEM768_CIPHERTEXT_SIZE]) -> Self {
        Self {
            x25519_ephemeral: x25519,
            mlkem_ciphertext: mlkem_ct,
        }
    }

    pub fn to_bytes(&self) -> [u8; HYBRID_CIPHERTEXT_SIZE] {
        let mut out = [0u8; HYBRID_CIPHERTEXT_SIZE];
        out[..X25519_PUBLIC_KEY_SIZE].copy_from_slice(&self.x25519_ephemeral);
        out[X25519_PUBLIC_KEY_SIZE..].copy_from_slice(&self.mlkem_ciphertext);
        out
    }

    pub fn from_bytes(slice: &[u8]) -> Result<Self, HybridCryptoError> {
        if slice.len() != HYBRID_CIPHERTEXT_SIZE {
            return Err(HybridCryptoError::InvalidCiphertextLength {
                expected: HYBRID_CIPHERTEXT_SIZE,
                actual: slice.len(),
            });
        }
        let mut x25519 = [0u8; X25519_PUBLIC_KEY_SIZE];
        let mut mlkem_ct = [0u8; MLKEM768_CIPHERTEXT_SIZE];
        x25519.copy_from_slice(&slice[..X25519_PUBLIC_KEY_SIZE]);
        mlkem_ct.copy_from_slice(&slice[X25519_PUBLIC_KEY_SIZE..]);
        Ok(Self {
            x25519_ephemeral: x25519,
            mlkem_ciphertext: mlkem_ct,
        })
    }
}

/// Hybrid shared secret wrapped in constant-time zeroization protections
#[derive(Clone)]
pub struct HybridSharedSecret([u8; HYBRID_SHARED_SECRET_SIZE]);

impl HybridSharedSecret {
    pub fn new(bytes: [u8; HYBRID_SHARED_SECRET_SIZE]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; HYBRID_SHARED_SECRET_SIZE] {
        &self.0
    }
}

impl std::fmt::Debug for HybridSharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HybridSharedSecret([REDACTED])")
    }
}

impl Drop for HybridSharedSecret {
    fn drop(&mut self) {
        // Zeroize memory upon drop
        for b in self.0.iter_mut() {
            *b = 0;
        }
    }
}

/// Hybrid keypair generated on the client or server side
pub struct HybridKeyPair {
    x25519_secret: EphemeralSecret,
    pub public_key: HybridPublicKey,
    mlkem_decaps_key: <MlKem768 as ml_kem::KemCore>::DecapsulationKey,
}

impl HybridKeyPair {
    /// Generates a fresh hybrid keypair using OS cryptographically secure random number generator
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let x25519_secret = EphemeralSecret::random_from_rng(&mut rng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        let (dk, ek) = ml_kem::MlKem768::generate(&mut rng);
        let ek_bytes = ek.as_bytes();

        let mut mlkem_pub = [0u8; MLKEM768_ENCAPS_KEY_SIZE];
        mlkem_pub.copy_from_slice(ek_bytes.as_slice());

        let public_key = HybridPublicKey::new(*x25519_public.as_bytes(), mlkem_pub);

        Self {
            x25519_secret,
            public_key,
            mlkem_decaps_key: dk,
        }
    }

    /// Client-side decapsulation: consumes keypair, decapsulates peer's ciphertext,
    /// and derives the identical hybrid shared secret
    pub fn decapsulate(self, ciphertext: &HybridCiphertext) -> Result<HybridSharedSecret, HybridCryptoError> {
        // 1. Classical X25519 Diffie-Hellman
        let peer_x25519 = X25519PublicKey::from(ciphertext.x25519_ephemeral);
        let classical_ss = self.x25519_secret.diffie_hellman(&peer_x25519);
        let classical_bytes = classical_ss.as_bytes();

        // Check for contributory behavior (all zeroes)
        let zero_secret = [0u8; 32];
        if classical_bytes.ct_eq(&zero_secret).into() {
            return Err(HybridCryptoError::WeakSharedSecret);
        }

        // 2. ML-KEM-768 Decapsulation (FIPS 203)
        let ct_encoded = Ciphertext::<MlKem768Params>::from_bytes(
            &ciphertext.mlkem_ciphertext.into()
        );
        let pq_ss = self.mlkem_decaps_key.decapsulate(&ct_encoded);

        // 3. Derive combined hybrid shared secret via HKDF-SHA256
        let final_ss = derive_hybrid_secret(classical_bytes, pq_ss.as_slice())?;
        Ok(HybridSharedSecret::new(final_ss))
    }
}

/// Server-side encapsulation: given client's hybrid public key, encapsulates a shared secret
/// and returns both the ciphertext to transmit and the derived shared secret.
pub fn encapsulate(peer_public: &HybridPublicKey) -> Result<(HybridCiphertext, HybridSharedSecret), HybridCryptoError> {
    let mut rng = OsRng;

    // 1. Classical X25519 ephemeral key generation and DH
    let server_secret = EphemeralSecret::random_from_rng(&mut rng);
    let server_pub = X25519PublicKey::from(&server_secret);
    let client_x25519 = X25519PublicKey::from(peer_public.x25519_public);
    let classical_ss = server_secret.diffie_hellman(&client_x25519);
    let classical_bytes = classical_ss.as_bytes();

    let zero_secret = [0u8; 32];
    if classical_bytes.ct_eq(&zero_secret).into() {
        return Err(HybridCryptoError::WeakSharedSecret);
    }

    // 2. ML-KEM-768 Encapsulation (FIPS 203)
    let ek_encoded = Encoded::<ml_kem::EncapsulationKey<MlKem768Params>>::from_bytes(
        &peer_public.mlkem_public.into()
    );
    let ek = ml_kem::EncapsulationKey::<MlKem768Params>::from_bytes(&ek_encoded);

    let (ct, pq_ss) = ek.encapsulate(&mut rng)
        .map_err(|_| HybridCryptoError::EncapsulationFailed)?;

    let mut mlkem_ct_bytes = [0u8; MLKEM768_CIPHERTEXT_SIZE];
    mlkem_ct_bytes.copy_from_slice(ct.as_bytes().as_slice());

    let ciphertext = HybridCiphertext::new(*server_pub.as_bytes(), mlkem_ct_bytes);

    // 3. Derive combined hybrid shared secret via HKDF-SHA256
    let final_ss = derive_hybrid_secret(classical_bytes, pq_ss.as_slice())?;
    Ok((ciphertext, HybridSharedSecret::new(final_ss)))
}

/// Derives a 32-byte final shared secret from classical and post-quantum secrets using HKDF-SHA256
fn derive_hybrid_secret(classical: &[u8], pq: &[u8]) -> Result<[u8; HYBRID_SHARED_SECRET_SIZE], HybridCryptoError> {
    // IKM = classical_shared_secret || pq_shared_secret
    let mut ikm = Vec::with_capacity(classical.len() + pq.len());
    ikm.extend_from_slice(classical);
    ikm.extend_from_slice(pq);

    let salt = sha2::Sha256::digest(b"X25519Kyber768Draft00");
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);

    let mut okm = [0u8; HYBRID_SHARED_SECRET_SIZE];
    hk.expand(HYBRID_KDF_LABEL, &mut okm)
        .map_err(|_| HybridCryptoError::KdfExpansionFailed)?;

    Ok(okm)
}

use sha2::Digest;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_kem_roundtrip() {
        // Client generates keypair
        let client_keypair = HybridKeyPair::generate();
        let client_pub = client_keypair.public_key.clone();

        // Wire serialization check
        let pub_bytes = client_pub.to_bytes();
        assert_eq!(pub_bytes.len(), HYBRID_PUBLIC_KEY_SIZE);
        let parsed_pub = HybridPublicKey::from_bytes(&pub_bytes).unwrap();
        assert_eq!(client_pub, parsed_pub);

        // Server encapsulates
        let (ciphertext, server_ss) = encapsulate(&parsed_pub).expect("Encapsulation should succeed");

        // Wire ciphertext serialization check
        let ct_bytes = ciphertext.to_bytes();
        assert_eq!(ct_bytes.len(), HYBRID_CIPHERTEXT_SIZE);
        let parsed_ct = HybridCiphertext::from_bytes(&ct_bytes).unwrap();
        assert_eq!(ciphertext, parsed_ct);

        // Client decapsulates
        let client_ss = client_keypair.decapsulate(&parsed_ct).expect("Decapsulation should succeed");

        // Shared secrets must match identically
        assert_eq!(server_ss.as_bytes(), client_ss.as_bytes());
        assert_eq!(client_ss.as_bytes().len(), HYBRID_SHARED_SECRET_SIZE);
    }
}
