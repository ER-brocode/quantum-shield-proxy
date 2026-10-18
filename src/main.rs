//! QuantumShield Proxy - High Performance Post-Quantum Cryptography TLS 1.3 Reverse Gateway
//!
//! Main CLI executable providing reverse proxy serving, certificate generation,
//! PQC benchmarking, and self-diagnostic verification.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

use quantum_shield_proxy::config::GatewayConfig;
use quantum_shield_proxy::crypto::dilithium::DilithiumKeyPair;
use quantum_shield_proxy::crypto::hybrid_kem::{encapsulate, HybridKeyPair};
use quantum_shield_proxy::gateway::{
    BalancingStrategy, GatewayMetrics, GatewayOptions, LoadBalancer, QuantumGateway,
};
use quantum_shield_proxy::tls::{
    build_server_config, generate_self_signed, load_certs, load_private_key,
    parse_certs_from_pem, parse_private_key_from_pem,
};

#[derive(Parser)]
#[command(
    name = "quantum-shield-proxy",
    author = "koushik4475 <koushik4475@gmail.com>",
    version = "0.1.0",
    about = "Production-grade Post-Quantum Cryptography (PQC) TLS 1.3 Reverse Gateway in Rust",
    long_about = "QuantumShield Proxy terminates TLS 1.3 connections with NIST FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65) quantum-resistant cryptography, protecting enterprise backends against 'Harvest Now, Decrypt Later' (HNDL) attacks."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Log level: trace, debug, info, warn, error
    #[arg(short, long, default_value = "info", global = true)]
    log_level: Level,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the reverse proxy gateway
    Run {
        /// Path to configuration file (YAML)
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Override listen address (e.g. 0.0.0.0:8443)
        #[arg(short, long)]
        listen: Option<SocketAddr>,

        /// Upstream backend address (can specify multiple)
        #[arg(short, long)]
        backend: Vec<String>,

        /// Enforce strict PQC (reject classical-only clients)
        #[arg(long)]
        strict_pqc: bool,
    },

    /// Generate quantum-ready self-signed TLS certificates
    GenerateCerts {
        /// Domain names for Subject Alternative Names (SAN)
        #[arg(short, long, default_value = "localhost")]
        domain: Vec<String>,

        /// Output path for PEM certificate
        #[arg(long, default_value = "cert.pem")]
        cert_out: PathBuf,

        /// Output path for PEM private key
        #[arg(long, default_value = "key.pem")]
        key_out: PathBuf,
    },

    /// Benchmark ML-KEM-768 and hybrid key exchange throughput
    Benchmark {
        /// Number of iterations
        #[arg(short, long, default_value_t = 1000)]
        iterations: usize,
    },

    /// Run self-diagnostic verification of post-quantum cryptographic primitives
    Verify,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Initialize structured logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(cli.log_level)
        .with_target(false)
        .with_thread_ids(true)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    match cli.command {
        Commands::Run {
            config,
            listen,
            backend,
            strict_pqc,
        } => {
            let mut cfg = if let Some(path) = config {
                info!(path = ?path, "Loading configuration from file");
                GatewayConfig::load_from_file(path)?
            } else {
                info!("Using default gateway configuration");
                GatewayConfig::default()
            };

            if let Some(l) = listen {
                cfg.listen_addr = l;
            }
            if !backend.is_empty() {
                cfg.backends = backend;
            }
            if strict_pqc {
                cfg.strict_pqc = true;
            }

            run_gateway(cfg).await?;
        }

        Commands::GenerateCerts {
            domain,
            cert_out,
            key_out,
        } => {
            info!(domains = ?domain, "Generating self-signed quantum-ready certificate");
            let generated = generate_self_signed(domain)?;
            std::fs::write(&cert_out, generated.cert_pem)?;
            std::fs::write(&key_out, generated.key_pem)?;
            info!(cert = ?cert_out, key = ?key_out, "Certificate and private key generated successfully");
        }

        Commands::Benchmark { iterations } => {
            run_benchmark(iterations);
        }

        Commands::Verify => {
            run_verification()?;
        }
    }

    Ok(())
}

async fn run_gateway(cfg: GatewayConfig) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        listen = %cfg.listen_addr,
        backends = ?cfg.backends,
        strict_pqc = cfg.strict_pqc,
        "Initializing QuantumShield Reverse Gateway"
    );

    // Setup TLS Certificates
    let (cert_chain, private_key) = if cfg.auto_generate_cert || cfg.cert_path.is_none() {
        info!("Auto-generating self-signed TLS certificate for localhost...");
        let generated = generate_self_signed(vec!["localhost".into(), "127.0.0.1".into()])?;
        let certs = parse_certs_from_pem(&generated.cert_pem)?;
        let key = parse_private_key_from_pem(&generated.key_pem)?;
        (certs, key)
    } else {
        let cert_p = cfg.cert_path.as_ref().unwrap();
        let key_p = cfg.key_path.as_ref().unwrap();
        info!(cert = ?cert_p, key = ?key_p, "Loading TLS certificates from disk");
        let certs = load_certs(cert_p)?;
        let key = load_private_key(key_p)?;
        (certs, key)
    };

    let server_config = build_server_config(cert_chain, private_key, cfg.strict_pqc, None)?;
    let tls_acceptor = TlsAcceptor::from(server_config);

    // Setup Load Balancer & Health Checks
    let strategy = match cfg.balancing_strategy.as_str() {
        "least_connections" => BalancingStrategy::LeastConnections,
        _ => BalancingStrategy::RoundRobin,
    };

    let lb = Arc::new(LoadBalancer::new(cfg.backends.clone(), strategy));
    lb.clone().spawn_health_checker(
        Duration::from_secs(cfg.health_check_interval_secs),
        Duration::from_secs(cfg.health_check_timeout_secs),
    );

    let metrics = GatewayMetrics::new();
    let options = GatewayOptions {
        server_name: cfg.server_name,
        inject_headers: cfg.inject_headers,
        rate_limit_rps: 1000,
        client_timeout_secs: 30,
    };

    let gateway = Arc::new(QuantumGateway::new(
        cfg.listen_addr,
        tls_acceptor,
        lb,
        metrics,
        options,
    ));

    // Graceful shutdown channel
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    tokio::spawn(async move {
        if let Ok(()) = tokio::signal::ctrl_c().await {
            info!("Ctrl+C received! Initiating graceful shutdown...");
            let _ = shutdown_tx.send(true);
        }
    });

    gateway.run(shutdown_rx).await?;
    info!("QuantumShield Gateway stopped cleanly");
    Ok(())
}

fn run_benchmark(iterations: usize) {
    info!(iterations, "Starting Post-Quantum Cryptography performance benchmark");

    // Benchmark ML-KEM-768 Keygen
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = HybridKeyPair::generate();
    }
    let elapsed = start.elapsed();
    let keygen_ops_sec = iterations as f64 / elapsed.as_secs_f64();
    let keygen_us_per_op = elapsed.as_micros() as f64 / iterations as f64;

    // Benchmark Encapsulation
    let kp = HybridKeyPair::generate();
    let pk = kp.public_key.clone();
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = encapsulate(&pk).unwrap();
    }
    let elapsed = start.elapsed();
    let encaps_ops_sec = iterations as f64 / elapsed.as_secs_f64();
    let encaps_us_per_op = elapsed.as_micros() as f64 / iterations as f64;

    // Benchmark Decapsulation
    let (ct, _) = encapsulate(&pk).unwrap();
    let start = Instant::now();
    for _ in 0..iterations {
        // regenerate keypair clone to decapsulate repeatedly
        let test_kp = HybridKeyPair::generate();
        let (c, _) = encapsulate(&test_kp.public_key).unwrap();
        let _ = test_kp.decapsulate(&c).unwrap();
    }
    let elapsed = start.elapsed();
    let decaps_us_per_op = elapsed.as_micros() as f64 / iterations as f64;

    println!("\n=======================================================");
    println!("     QUANTUM-SHIELD CRYPTO BENCHMARK REPORT           ");
    println!("=======================================================");
    println!("Primitive: Hybrid X25519 + ML-KEM-768 (NIST FIPS 203)");
    println!("Iterations: {}", iterations);
    println!("-------------------------------------------------------");
    println!("Operation       | Latency (us/op) | Throughput (ops/sec)");
    println!("----------------+-----------------+--------------------");
    println!("Key Generation  | {:>15.2} | {:>18.1}", keygen_us_per_op, keygen_ops_sec);
    println!("Encapsulation   | {:>15.2} | {:>18.1}", encaps_us_per_op, encaps_ops_sec);
    println!("Decapsulation   | {:>15.2} | {:>18.1}", decaps_us_per_op, iterations as f64 / elapsed.as_secs_f64());
    println!("=======================================================\n");
}

fn run_verification() -> Result<(), Box<dyn std::error::Error>> {
    info!("Running self-diagnostic verification...");

    // 1. Verify ML-KEM-768 Hybrid Key Exchange
    print!("Testing Hybrid X25519 + ML-KEM-768 roundtrip... ");
    let client_kp = HybridKeyPair::generate();
    let (ciphertext, server_ss) = encapsulate(&client_kp.public_key)?;
    let client_ss = client_kp.decapsulate(&ciphertext)?;
    assert_eq!(server_ss.as_bytes(), client_ss.as_bytes());
    println!("PASSED (Shared secrets match perfectly)");

    // 2. Verify ML-DSA-65 Digital Signatures
    print!("Testing ML-DSA-65 (Dilithium3) sign and verify... ");
    let d_kp = DilithiumKeyPair::generate()?;
    let msg = b"Verification payload for QuantumShield Proxy";
    let sig = d_kp.sign(msg);
    quantum_shield_proxy::crypto::dilithium::verify(&d_kp.public_key, msg, &sig)?;
    println!("PASSED (Signature verified successfully)");

    // 3. Verify TLS Provider Construction
    print!("Testing rustls PQC Provider initialization... ");
    let provider = quantum_shield_proxy::tls::pqc_crypto_provider();
    assert!(!provider.kx_groups.is_empty());
    println!("PASSED (Hybrid KX Group registered)");

    println!("\nAll cryptographic self-diagnostics PASSED successfully!");
    Ok(())
}
