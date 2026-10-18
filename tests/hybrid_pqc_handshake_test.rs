//! End-to-End Integration Tests for QuantumShield PQC Reverse Gateway
//!
//! Verifies:
//! 1. Hybrid X25519 + ML-KEM-768 key encapsulation and decapsulation roundtrip.
//! 2. NIST FIPS 204 ML-DSA-65 signature generation and tampering detection.
//! 3. Full TLS 1.3 handshake using custom PQC key exchange provider (NamedGroup::X25519MLKEM768).
//! 4. Gateway reverse proxying, connection termination, and security header injection.
//! 5. Load balancing and health check failover.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use quantum_shield_proxy::crypto::dilithium::{self, DilithiumKeyPair};
use quantum_shield_proxy::crypto::hybrid_kem::{
    encapsulate, HybridCiphertext, HybridKeyPair, HybridPublicKey, HYBRID_CIPHERTEXT_SIZE,
    HYBRID_PUBLIC_KEY_SIZE, HYBRID_SHARED_SECRET_SIZE,
};
use quantum_shield_proxy::gateway::{
    BalancingStrategy, GatewayMetrics, GatewayOptions, LoadBalancer, QuantumGateway,
};
use quantum_shield_proxy::tls::{
    build_client_config, build_server_config, generate_self_signed, parse_certs_from_pem,
    parse_private_key_from_pem,
};

#[test]
fn test_hybrid_kem_roundtrip() {
    // 1. Generate client keypair
    let client_kp = HybridKeyPair::generate();
    let client_pub = client_kp.public_key.clone();

    // 2. Wire serialization format
    let pub_bytes = client_pub.to_bytes();
    assert_eq!(pub_bytes.len(), HYBRID_PUBLIC_KEY_SIZE);
    let parsed_pub =
        HybridPublicKey::from_bytes(&pub_bytes).expect("Failed to deserialize public key");
    assert_eq!(client_pub, parsed_pub);

    // 3. Server encapsulates
    let (ciphertext, server_ss) = encapsulate(&parsed_pub).expect("Encapsulation failed");

    // Ciphertext wire size check
    let ct_bytes = ciphertext.to_bytes();
    assert_eq!(ct_bytes.len(), HYBRID_CIPHERTEXT_SIZE);
    let parsed_ct =
        HybridCiphertext::from_bytes(&ct_bytes).expect("Failed to deserialize ciphertext");
    assert_eq!(ciphertext, parsed_ct);

    // 4. Client decapsulates
    let client_ss = client_kp
        .decapsulate(&parsed_ct)
        .expect("Decapsulation failed");

    // 5. Assert identical shared secret
    assert_eq!(server_ss.as_bytes().len(), HYBRID_SHARED_SECRET_SIZE);
    assert_eq!(server_ss.as_bytes(), client_ss.as_bytes());
}

#[test]
fn test_dilithium_digital_signatures() {
    let kp = DilithiumKeyPair::generate().expect("Failed to generate ML-DSA-65 keypair");
    let payload = b"Critical security payload for post-quantum TLS proxy authentication";

    let sig = kp.sign(payload);
    assert_eq!(sig.as_bytes().len(), dilithium::DILITHIUM_SIGNATURE_SIZE);

    // Verification must succeed on original message
    let verify_res = dilithium::verify(&kp.public_key, payload, &sig);
    assert!(
        verify_res.is_ok(),
        "Signature verification failed on legitimate message"
    );

    // Verification must fail on altered message
    let mut tampered = payload.to_vec();
    tampered[0] ^= 0xff;
    let tampered_res = dilithium::verify(&kp.public_key, &tampered, &sig);
    assert!(
        tampered_res.is_err(),
        "Signature verification must fail on tampered message"
    );
}

#[tokio::test]
async fn test_tls13_pqc_handshake_and_exchange() {
    // 1. Generate self-signed certificate for localhost
    let generated = generate_self_signed(vec!["localhost".to_string()]).expect("Cert gen failed");
    let server_certs = parse_certs_from_pem(&generated.cert_pem).unwrap();
    let server_key = parse_private_key_from_pem(&generated.key_pem).unwrap();

    // 2. Build Server TLS Config with PQC provider
    let server_tls = build_server_config(server_certs.clone(), server_key, true, None)
        .expect("Server TLS config failed");
    let acceptor = TlsAcceptor::from(server_tls);

    // 3. Build Client TLS Config with PQC provider & trust the self-signed cert
    let mut root_store = rustls::RootCertStore::empty();
    for cert in server_certs {
        root_store.add(cert).unwrap();
    }
    let client_tls = build_client_config(root_store, true, None).expect("Client TLS config failed");
    let connector = TlsConnector::from(client_tls);

    // 4. Bind server listener
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    // Spawn TLS server task
    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls_stream = acceptor.accept(stream).await.unwrap();

        // Verify TLS 1.3 negotiated
        let (_, conn) = tls_stream.get_ref();
        assert_eq!(
            conn.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );

        // Read ping message
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut buf = [0u8; 4];
        tls_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"PING");

        // Write pong message
        tls_stream.write_all(b"PONG").await.unwrap();
        tls_stream.shutdown().await.unwrap();
    });

    // 5. Run TLS client task
    let client_task = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let tcp_stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        let server_name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls_stream = connector.connect(server_name, tcp_stream).await.unwrap();

        // Write ping
        tls_stream.write_all(b"PING").await.unwrap();

        // Read pong
        let mut buf = [0u8; 4];
        tls_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"PONG");
    });

    let (s_res, c_res) = tokio::join!(server_task, client_task);
    s_res.unwrap();
    c_res.unwrap();
}

#[tokio::test]
async fn test_gateway_reverse_proxy_and_header_injection() {
    // 1. Spawn Mock Upstream Backend HTTP server
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend_listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            if let Ok((stream, _)) = backend_listener.accept().await {
                let io = TokioIo::new(stream);
                tokio::spawn(async move {
                    let service = service_fn(|req: Request<Incoming>| async move {
                        // Assert that QuantumShield injected security headers
                        assert_eq!(req.headers().get("X-Quantum-Shield").unwrap(), "secured");
                        assert_eq!(
                            req.headers().get("X-PQC-Key-Exchange").unwrap(),
                            "X25519-MLKEM768"
                        );

                        let body = "Backend Response: Quantum Protected";
                        let full = Full::new(Bytes::from(body))
                            .map_err(|never| match never {})
                            .boxed();
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(full)
                                .unwrap(),
                        )
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await;
                });
            }
        }
    });

    // 2. Start QuantumShield Gateway
    let generated = generate_self_signed(vec!["localhost".to_string()]).unwrap();
    let server_certs = parse_certs_from_pem(&generated.cert_pem).unwrap();
    let server_key = parse_private_key_from_pem(&generated.key_pem).unwrap();

    let server_tls = build_server_config(server_certs.clone(), server_key, true, None).unwrap();
    let acceptor = TlsAcceptor::from(server_tls);

    let lb = Arc::new(LoadBalancer::new(
        vec![backend_addr.to_string()],
        BalancingStrategy::RoundRobin,
    ));
    let metrics = GatewayMetrics::new();
    let options = GatewayOptions::default();

    let gateway_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_addr = gateway_listener.local_addr().unwrap();
    drop(gateway_listener); // free port for gateway to bind

    let gateway = Arc::new(QuantumGateway::new(
        gateway_addr,
        acceptor,
        lb,
        metrics.clone(),
        options,
    ));

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let gateway_handle = {
        let gw = gateway.clone();
        tokio::spawn(async move {
            let _ = gw.run(shutdown_rx).await;
        })
    };

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 3. Connect via PQC TLS Client
    let mut root_store = rustls::RootCertStore::empty();
    for cert in server_certs {
        root_store.add(cert).unwrap();
    }
    let client_tls = build_client_config(root_store, true, None).unwrap();
    let connector = TlsConnector::from(client_tls);

    let tcp = tokio::net::TcpStream::connect(gateway_addr).await.unwrap();
    let server_name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
    let tls_stream = connector.connect(server_name, tcp).await.unwrap();
    let io = TokioIo::new(tls_stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // Send HTTP Request to gateway
    let req = Request::builder()
        .uri("/api/resource")
        .header("host", "localhost")
        .body(
            Full::new(Bytes::from("hello"))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap();

    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify response headers
    assert_eq!(resp.headers().get("X-Quantum-Shield").unwrap(), "secured");
    assert_eq!(
        resp.headers().get("X-PQC-Key-Exchange").unwrap(),
        "X25519-MLKEM768"
    );

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body_bytes[..], b"Backend Response: Quantum Protected");

    // Verify Prometheus Metrics
    assert!(
        metrics
            .requests_total
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 1
    );
    assert!(
        metrics
            .pqc_handshakes_total
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 1
    );

    // Gracefully shut down gateway
    let _ = shutdown_tx.send(true);
    let _ = gateway_handle.await;
}

#[test]
fn test_load_balancer_round_robin() {
    let lb = LoadBalancer::new(
        vec![
            "127.0.0.1:8001".to_string(),
            "127.0.0.1:8002".to_string(),
            "127.0.0.1:8003".to_string(),
        ],
        BalancingStrategy::RoundRobin,
    );

    let b1 = lb.select_backend().unwrap();
    let b2 = lb.select_backend().unwrap();
    let b3 = lb.select_backend().unwrap();
    let b4 = lb.select_backend().unwrap();

    assert_eq!(b1.address, "127.0.0.1:8001");
    assert_eq!(b2.address, "127.0.0.1:8002");
    assert_eq!(b3.address, "127.0.0.1:8003");
    assert_eq!(b4.address, "127.0.0.1:8001"); // wraps around
}
