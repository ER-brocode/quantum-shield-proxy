//! Quantum-Safe Digital Signatures (NIST FIPS 204 ML-DSA-65 / CRYSTALS-Dilithium3)
//!
//! Provides post-quantum digital signature generation and verification for
//! quantum-resistant certificate chains, mutual TLS authentication, and origin verification.

use ml_dsa::KeyExport;
use ml_dsa::MlDsa65;
use rand::rngs::OsRng;
use thiserror::Error;

/// ML-DSA-65 public key size (1952 bytes)
pub const DILITHIUM_PUBLIC_KEY_SIZE: usize = 1952;

/// ML-DSA-65 secret key size (4032 bytes)
pub const DILITHIUM_SECRET_KEY_SIZE: usize = 4032;

/// ML-DSA-65 signature size (3309 bytes)
pub const DILITHIUM_SIGNATURE_SIZE: usize = 3309;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum DilithiumError {
    #[error("Invalid public key length: expected {expected}, got {actual}")]
    InvalidPublicKeyLength { expected: usize, actual: usize },

    #[error("Invalid secret key length: expected {expected}, got {actual}")]
    InvalidSecretKeyLength { expected: usize, actual: usize },

    #[error("Invalid signature length: expected {expected}, got {actual}")]
    InvalidSignatureLength { expected: usize, actual: usize },

    #[error("Digital signature verification failed")]
    VerificationFailed,

    #[error("Key generation error: {0}")]
    KeyGenError(String),
}

/// ML-DSA-65 public verification key
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DilithiumPublicKey {
    bytes: Vec<u8>,
}

impl DilithiumPublicKey {
    pub fn from_bytes(slice: &[u8]) -> Result<Self, DilithiumError> {
        if slice.len() != DILITHIUM_PUBLIC_KEY_SIZE {
            return Err(DilithiumError::InvalidPublicKeyLength {
                expected: DILITHIUM_PUBLIC_KEY_SIZE,
                actual: slice.len(),
            });
        }
        Ok(Self {
            bytes: slice.to_vec(),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// ML-DSA-65 secret signing key
#[derive(Clone)]
pub struct DilithiumSecretKey {
    bytes: Vec<u8>,
}

impl DilithiumSecretKey {
    pub fn from_bytes(slice: &[u8]) -> Result<Self, DilithiumError> {
        if slice.len() != DILITHIUM_SECRET_KEY_SIZE {
            return Err(DilithiumError::InvalidSecretKeyLength {
                expected: DILITHIUM_SECRET_KEY_SIZE,
                actual: slice.len(),
            });
        }
        Ok(Self {
            bytes: slice.to_vec(),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for DilithiumSecretKey {
    fn drop(&mut self) {
        for b in self.bytes.iter_mut() {
            *b = 0;
        }
    }
}

/// ML-DSA-65 signature
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DilithiumSignature {
    bytes: Vec<u8>,
}

impl DilithiumSignature {
    pub fn from_bytes(slice: &[u8]) -> Result<Self, DilithiumError> {
        if slice.len() != DILITHIUM_SIGNATURE_SIZE {
            return Err(DilithiumError::InvalidSignatureLength {
                expected: DILITHIUM_SIGNATURE_SIZE,
                actual: slice.len(),
            });
        }
        Ok(Self {
            bytes: slice.to_vec(),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Keypair for signing and verification
pub struct DilithiumKeyPair {
    pub public_key: DilithiumPublicKey,
    pub secret_key: DilithiumSecretKey,
    inner_signing_key: ml_dsa::SigningKey<MlDsa65>,
}

impl DilithiumKeyPair {
    /// Generates a fresh ML-DSA-65 keypair
    pub fn generate() -> Result<Self, DilithiumError> {
        let mut rng = OsRng;
        let signing_key = ml_dsa::SigningKey::<MlDsa65>::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        let pk_bytes = verifying_key.to_encoded_point();
        let sk_bytes = signing_key.to_encoded_point();

        Ok(Self {
            public_key: DilithiumPublicKey {
                bytes: pk_bytes.as_slice().to_vec(),
            },
            secret_key: DilithiumSecretKey {
                bytes: sk_bytes.as_slice().to_vec(),
            },
            inner_signing_key: signing_key,
        })
    }

    /// Signs a message using the ML-DSA-65 secret key
    pub fn sign(&self, message: &[u8]) -> DilithiumSignature {
        let mut rng = OsRng;
        use ml_dsa::signature::RandomizedSigner;
        let sig = self.inner_signing_key.sign_with_rng(&mut rng, message);
        DilithiumSignature {
            bytes: sig.to_encoded_point().as_slice().to_vec(),
        }
    }
}

/// Verifies an ML-DSA-65 signature against a message and public key
pub fn verify(
    public_key: &DilithiumPublicKey,
    message: &[u8],
    signature: &DilithiumSignature,
) -> Result<(), DilithiumError> {
    use ml_dsa::signature::Verifier;
    let vk = ml_dsa::VerifyingKey::<MlDsa65>::from_encoded_point(&ml_dsa::EncodedPoint::<
        ml_dsa::VerifyingKey<MlDsa65>,
    >::from_bytes(
        public_key.as_bytes().into()
    ))
    .map_err(|_| DilithiumError::VerificationFailed)?;

    let sig = ml_dsa::Signature::<MlDsa65>::from_encoded_point(&ml_dsa::EncodedPoint::<
        ml_dsa::Signature<MlDsa65>,
    >::from_bytes(
        signature.as_bytes().into()
    ))
    .map_err(|_| DilithiumError::VerificationFailed)?;

    vk.verify(message, &sig)
        .map_err(|_| DilithiumError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dilithium_sign_verify_roundtrip() {
        let keypair = DilithiumKeyPair::generate().expect("Keygen should succeed");
        let msg = b"Quantum-Shield TLS 1.3 reverse gateway signature test";

        let sig = keypair.sign(msg);
        assert_eq!(sig.as_bytes().len(), DILITHIUM_SIGNATURE_SIZE);

        // Verify valid signature
        let verify_res = verify(&keypair.public_key, msg, &sig);
        assert!(verify_res.is_ok());

        // Verify tampered message fails
        let tampered_msg = b"Tampered message content";
        let tampered_res = verify(&keypair.public_key, tampered_msg, &sig);
        assert!(tampered_res.is_err());
    }
}
