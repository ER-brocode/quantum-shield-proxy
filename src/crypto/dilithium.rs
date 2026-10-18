//! Quantum-Safe Digital Signatures (NIST FIPS 204 ML-DSA-65 / CRYSTALS-Dilithium3)
//!
//! Provides post-quantum digital signature generation and verification for
//! quantum-resistant certificate chains, mutual TLS authentication, and origin verification.

use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use thiserror::Error;

/// ML-DSA-65 public key size (1952 bytes)
pub const DILITHIUM_PUBLIC_KEY_SIZE: usize = 1952;

/// ML-DSA-65 secret key seed size (32 bytes)
pub const DILITHIUM_SECRET_KEY_SIZE: usize = 32;

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

/// ML-DSA-65 secret signing key seed
#[derive(Clone)]
pub struct DilithiumSecretKey {
    bytes: [u8; DILITHIUM_SECRET_KEY_SIZE],
}

impl DilithiumSecretKey {
    pub fn from_bytes(slice: &[u8]) -> Result<Self, DilithiumError> {
        if slice.len() != DILITHIUM_SECRET_KEY_SIZE {
            return Err(DilithiumError::InvalidSecretKeyLength {
                expected: DILITHIUM_SECRET_KEY_SIZE,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; DILITHIUM_SECRET_KEY_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8; DILITHIUM_SECRET_KEY_SIZE] {
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
    inner_signing_key: SigningKey<MlDsa65>,
}

impl DilithiumKeyPair {
    /// Generates a fresh ML-DSA-65 keypair from OS entropy
    pub fn generate() -> Result<Self, DilithiumError> {
        let mut rng = OsRng;
        let mut seed = [0u8; DILITHIUM_SECRET_KEY_SIZE];
        rng.fill_bytes(&mut seed);

        let seed_arr = hybrid_array::Array::from(seed);
        let signing_key = SigningKey::<MlDsa65>::from_seed(&seed_arr);
        let verifying_key: VerifyingKey<MlDsa65> = signing_key.verifying_key();
        let enc_vk = verifying_key.encode();

        Ok(Self {
            public_key: DilithiumPublicKey {
                bytes: enc_vk.as_slice().to_vec(),
            },
            secret_key: DilithiumSecretKey { bytes: seed },
            inner_signing_key: signing_key,
        })
    }

    /// Signs a message using the ML-DSA-65 secret key
    pub fn sign(&self, message: &[u8]) -> DilithiumSignature {
        let sig: Signature<MlDsa65> = self.inner_signing_key.sign(message);
        let enc_sig = sig.encode();
        DilithiumSignature {
            bytes: enc_sig.as_slice().to_vec(),
        }
    }
}

/// Verifies an ML-DSA-65 signature against a message and public key
pub fn verify(
    public_key: &DilithiumPublicKey,
    message: &[u8],
    signature: &DilithiumSignature,
) -> Result<(), DilithiumError> {
    if public_key.as_bytes().len() != DILITHIUM_PUBLIC_KEY_SIZE {
        return Err(DilithiumError::InvalidPublicKeyLength {
            expected: DILITHIUM_PUBLIC_KEY_SIZE,
            actual: public_key.as_bytes().len(),
        });
    }

    let enc_vk = EncodedVerifyingKey::<MlDsa65>::try_from(public_key.as_bytes()).map_err(|_| {
        DilithiumError::InvalidPublicKeyLength {
            expected: DILITHIUM_PUBLIC_KEY_SIZE,
            actual: public_key.as_bytes().len(),
        }
    })?;
    let vk = VerifyingKey::<MlDsa65>::decode(&enc_vk);

    let enc_sig = EncodedSignature::<MlDsa65>::try_from(signature.as_bytes()).map_err(|_| {
        DilithiumError::InvalidSignatureLength {
            expected: DILITHIUM_SIGNATURE_SIZE,
            actual: signature.as_bytes().len(),
        }
    })?;
    let sig = Signature::<MlDsa65>::decode(&enc_sig).ok_or(DilithiumError::VerificationFailed)?;

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

        let verify_res = verify(&keypair.public_key, msg, &sig);
        assert!(verify_res.is_ok());

        let tampered_msg = b"Tampered message content";
        let tampered_res = verify(&keypair.public_key, tampered_msg, &sig);
        assert!(tampered_res.is_err());
    }
}
