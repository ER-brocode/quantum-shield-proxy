//! TLS Certificate and Key Management
//!
//! Provides utilities for generating quantum-ready self-signed X.509 certificates,
//! loading PEM-encoded certificate chains and private keys, and configuring
//! rustls certificate verifiers.

use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CertError {
    #[error("IO error reading certificate/key: {0}")]
    Io(#[from] std::io::Error),

    #[error("Certificate generation error: {0}")]
    Generation(String),

    #[error("No certificates found in PEM file: {0}")]
    NoCertificatesFound(String),

    #[error("No private key found in PEM file: {0}")]
    NoPrivateKeyFound(String),

    #[error("Failed to parse private key: {0}")]
    ParsePrivateKey(String),
}

/// Generated in-memory certificate and private key in PEM format
pub struct GeneratedCert {
    pub cert_pem: String,
    pub key_pem: String,
}

/// Generates a self-signed certificate and PKCS#8 private key for the given domain names
pub fn generate_self_signed(domains: Vec<String>) -> Result<GeneratedCert, CertError> {
    let mut params =
        rcgen::CertificateParams::new(domains).map_err(|e| CertError::Generation(e.to_string()))?;

    // Configure certificate metadata
    params.distinguished_name.push(
        rcgen::DnType::OrganizationName,
        "QuantumShield Security Gateway",
    );
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "QuantumShield PQC TLS Gateway");

    let key_pair = rcgen::KeyPair::generate().map_err(|e| CertError::Generation(e.to_string()))?;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| CertError::Generation(e.to_string()))?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    Ok(GeneratedCert { cert_pem, key_pem })
}

/// Loads a certificate chain from a PEM file
pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, CertError> {
    let certfile = File::open(path)?;
    let mut reader = BufReader::new(certfile);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(CertError::Io)?;

    if certs.is_empty() {
        return Err(CertError::NoCertificatesFound(path.display().to_string()));
    }

    Ok(certs)
}

/// Loads a private key (PKCS#8 or RSA) from a PEM file
pub fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, CertError> {
    let keyfile = File::open(path)?;
    let mut reader = BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).map_err(CertError::Io)? {
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => return Ok(PrivateKeyDer::Pkcs8(key)),
            Some(rustls_pemfile::Item::Sec1Key(key)) => return Ok(PrivateKeyDer::Sec1(key)),
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => return Ok(PrivateKeyDer::Pkcs1(key)),
            None => break,
            _ => continue,
        }
    }

    Err(CertError::NoPrivateKeyFound(path.display().to_string()))
}

/// Parses certificate chain from in-memory PEM string
pub fn parse_certs_from_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>, CertError> {
    let mut reader = BufReader::new(pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(CertError::Io)?;

    if certs.is_empty() {
        return Err(CertError::NoCertificatesFound("in-memory PEM".into()));
    }

    Ok(certs)
}

/// Parses private key from in-memory PEM string
pub fn parse_private_key_from_pem(pem: &str) -> Result<PrivateKeyDer<'static>, CertError> {
    let mut reader = BufReader::new(pem.as_bytes());

    loop {
        match rustls_pemfile::read_one(&mut reader).map_err(CertError::Io)? {
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => return Ok(PrivateKeyDer::Pkcs8(key)),
            Some(rustls_pemfile::Item::Sec1Key(key)) => return Ok(PrivateKeyDer::Sec1(key)),
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => return Ok(PrivateKeyDer::Pkcs1(key)),
            None => break,
            _ => continue,
        }
    }

    Err(CertError::NoPrivateKeyFound("in-memory PEM".into()))
}
