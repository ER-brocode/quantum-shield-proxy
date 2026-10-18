//! Configuration Management for QuantumShield Proxy
//!
//! Supports loading YAML/JSON configurations, environment variable overrides,
//! and sensible production defaults.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to read configuration file {0}: {1}")]
    Io(PathBuf, #[source] std::io::Error),

    #[error("Failed to parse YAML configuration: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("Invalid configuration: {0}")]
    Validation(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Address to bind the TLS reverse proxy to (e.g. "0.0.0.0:8443")
    #[serde(default = "default_listen_addr")]
    pub listen_addr: SocketAddr,

    /// Upstream backend pool (e.g. ["127.0.0.1:8080", "127.0.0.1:8081"])
    #[serde(default = "default_backends")]
    pub backends: Vec<String>,

    /// Load balancing strategy: "round_robin" or "least_connections"
    #[serde(default = "default_strategy")]
    pub balancing_strategy: String,

    /// Enforce strict PQC (reject classical-only TLS clients)
    #[serde(default = "default_strict_pqc")]
    pub strict_pqc: bool,

    /// Path to PEM-encoded certificate chain
    pub cert_path: Option<PathBuf>,

    /// Path to PEM-encoded private key
    pub key_path: Option<PathBuf>,

    /// Automatically generate self-signed certificates if none specified
    #[serde(default = "default_auto_cert")]
    pub auto_generate_cert: bool,

    /// Health check probe interval in seconds
    #[serde(default = "default_health_interval")]
    pub health_check_interval_secs: u64,

    /// Health check connection timeout in seconds
    #[serde(default = "default_health_timeout")]
    pub health_check_timeout_secs: u64,

    /// Inject X-Quantum-Shield and X-PQC telemetry headers
    #[serde(default = "default_inject_headers")]
    pub inject_headers: bool,

    /// Server identifier in HTTP responses
    #[serde(default = "default_server_name")]
    pub server_name: String,
}

fn default_listen_addr() -> SocketAddr {
    "0.0.0.0:8443".parse().unwrap()
}

fn default_backends() -> Vec<String> {
    vec!["127.0.0.1:8080".to_string()]
}

fn default_strategy() -> String {
    "round_robin".to_string()
}

fn default_strict_pqc() -> bool {
    false
}

fn default_auto_cert() -> bool {
    true
}

fn default_health_interval() -> u64 {
    10
}

fn default_health_timeout() -> u64 {
    2
}

fn default_inject_headers() -> bool {
    true
}

fn default_server_name() -> String {
    "QuantumShield-Gateway/1.0".to_string()
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            backends: default_backends(),
            balancing_strategy: default_strategy(),
            strict_pqc: default_strict_pqc(),
            cert_path: None,
            key_path: None,
            auto_generate_cert: default_auto_cert(),
            health_check_interval_secs: default_health_interval(),
            health_check_timeout_secs: default_health_timeout(),
            inject_headers: default_inject_headers(),
            server_name: default_server_name(),
        }
    }
}

impl GatewayConfig {
    /// Loads configuration from a YAML file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let p = path.as_ref().to_path_buf();
        let content = fs::read_to_string(&p).map_err(|e| ConfigError::Io(p.clone(), e))?;
        let config: Self = serde_yaml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Validates the configuration values
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.backends.is_empty() {
            return Err(ConfigError::Validation("At least one upstream backend must be specified".into()));
        }
        if !self.auto_generate_cert && (self.cert_path.is_none() || self.key_path.is_none()) {
            return Err(ConfigError::Validation(
                "cert_path and key_path must be specified when auto_generate_cert is disabled".into()
            ));
        }
        Ok(())
    }
}
