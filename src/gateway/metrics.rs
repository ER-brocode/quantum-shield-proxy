//! Observability & Prometheus Metrics Exporter
//!
//! Provides real-time metrics for TLS handshakes, PQC key exchange latency,
//! throughput, backend health, and active connection tracking.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Default)]
pub struct GatewayMetrics {
    pub requests_total: AtomicU64,
    pub pqc_handshakes_total: AtomicU64,
    pub legacy_handshakes_total: AtomicU64,
    pub failed_handshakes_total: AtomicU64,
    pub active_connections: AtomicI64,
    pub bytes_proxied: AtomicU64,
    pub total_handshake_duration_us: AtomicU64,
    pub backend_errors_total: AtomicU64,
}

impl GatewayMetrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn record_pqc_handshake(&self, duration: Duration) {
        self.pqc_handshakes_total.fetch_add(1, Ordering::Relaxed);
        self.total_handshake_duration_us.fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
    }

    pub fn record_legacy_handshake(&self, duration: Duration) {
        self.legacy_handshakes_total.fetch_add(1, Ordering::Relaxed);
        self.total_handshake_duration_us.fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
    }

    pub fn record_handshake_failure(&self) {
        self.failed_handshakes_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_active_connections(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_active_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_request(&self, bytes: u64) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        self.bytes_proxied.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_backend_error(&self) {
        self.backend_errors_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Formats metrics in standard Prometheus line protocol
    pub fn render_prometheus(&self) -> String {
        let pqc = self.pqc_handshakes_total.load(Ordering::Relaxed);
        let total_hs = pqc + self.legacy_handshakes_total.load(Ordering::Relaxed);
        let total_us = self.total_handshake_duration_us.load(Ordering::Relaxed);
        let avg_latency_ms = if total_hs > 0 {
            (total_us as f64 / total_hs as f64) / 1000.0
        } else {
            0.0
        };

        format!(
            "# HELP quantum_shield_requests_total Total number of HTTP requests processed.\n\
             # TYPE quantum_shield_requests_total counter\n\
             quantum_shield_requests_total {}\n\n\
             # HELP quantum_shield_handshakes_total TLS 1.3 handshakes by algorithm.\n\
             # TYPE quantum_shield_handshakes_total counter\n\
             quantum_shield_handshakes_total{{kem=\"x25519_kyber768\",status=\"success\"}} {}\n\
             quantum_shield_handshakes_total{{kem=\"classical\",status=\"success\"}} {}\n\
             quantum_shield_handshakes_total{{status=\"failure\"}} {}\n\n\
             # HELP quantum_shield_active_connections Current active TLS connections.\n\
             # TYPE quantum_shield_active_connections gauge\n\
             quantum_shield_active_connections {}\n\n\
             # HELP quantum_shield_bytes_proxied_total Total payload bytes proxied.\n\
             # TYPE quantum_shield_bytes_proxied_total counter\n\
             quantum_shield_bytes_proxied_total {}\n\n\
             # HELP quantum_shield_avg_handshake_latency_ms Average handshake latency in milliseconds.\n\
             # TYPE quantum_shield_avg_handshake_latency_ms gauge\n\
             quantum_shield_avg_handshake_latency_ms {:.3}\n\n\
             # HELP quantum_shield_backend_errors_total Upstream backend request failures.\n\
             # TYPE quantum_shield_backend_errors_total counter\n\
             quantum_shield_backend_errors_total {}\n",
            self.requests_total.load(Ordering::Relaxed),
            pqc,
            self.legacy_handshakes_total.load(Ordering::Relaxed),
            self.failed_handshakes_total.load(Ordering::Relaxed),
            self.active_connections.load(Ordering::Relaxed),
            self.bytes_proxied.load(Ordering::Relaxed),
            avg_latency_ms,
            self.backend_errors_total.load(Ordering::Relaxed)
        )
    }
}
