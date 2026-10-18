//! Upstream Backend Management & Load Balancing
//!
//! Provides Round-Robin and Least-Connections load balancing across upstream server pools,
//! with active background health checks and automatic failure recovery.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BalancingStrategy {
    RoundRobin,
    LeastConnections,
}

#[derive(Debug, Clone)]
pub struct Backend {
    pub address: String,
    pub healthy: Arc<AtomicBool>,
    pub active_connections: Arc<AtomicUsize>,
}

impl Backend {
    pub fn new(address: String) -> Self {
        Self {
            address,
            healthy: Arc::new(AtomicBool::new(true)),
            active_connections: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    pub fn active_conns(&self) -> usize {
        self.active_connections.load(Ordering::Relaxed)
    }

    pub fn inc_conns(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_conns(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct LoadBalancer {
    backends: Vec<Backend>,
    strategy: BalancingStrategy,
    rr_counter: AtomicUsize,
}

impl LoadBalancer {
    pub fn new(addresses: Vec<String>, strategy: BalancingStrategy) -> Self {
        let backends = addresses.into_iter().map(Backend::new).collect();
        Self {
            backends,
            strategy,
            rr_counter: AtomicUsize::new(0),
        }
    }

    pub fn backends(&self) -> &[Backend] {
        &self.backends
    }

    /// Selects an optimal healthy backend based on the chosen strategy
    pub fn select_backend(&self) -> Option<Backend> {
        let healthy_backends: Vec<&Backend> =
            self.backends.iter().filter(|b| b.is_healthy()).collect();

        if healthy_backends.is_empty() {
            // If all marked unhealthy, fallback to any backend to avoid hard blackhole
            warn!("All backends marked unhealthy! Falling back to unconstrained pool");
            return self.backends.first().cloned();
        }

        match self.strategy {
            BalancingStrategy::RoundRobin => {
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % healthy_backends.len();
                Some((*healthy_backends[idx]).clone())
            }
            BalancingStrategy::LeastConnections => {
                let chosen = healthy_backends
                    .into_iter()
                    .min_by_key(|b| b.active_conns())?;
                Some(chosen.clone())
            }
        }
    }

    /// Starts a background task performing periodic TCP health probes on all backends
    pub fn spawn_health_checker(self: Arc<Self>, interval: Duration, probe_timeout: Duration) {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;

                for backend in &self.backends {
                    let addr = backend.address.clone();
                    let healthy_flag = backend.healthy.clone();

                    tokio::spawn(async move {
                        // Extract host:port or assume port 80/443
                        let target = if addr.starts_with("http://") {
                            addr.trim_start_matches("http://")
                        } else if addr.starts_with("https://") {
                            addr.trim_start_matches("https://")
                        } else {
                            &addr
                        };

                        let host_port = if !target.contains(':') {
                            format!("{}:80", target)
                        } else {
                            target.to_string()
                        };

                        let probe_result = tokio::time::timeout(
                            probe_timeout,
                            tokio::net::TcpStream::connect(&host_port),
                        )
                        .await;

                        match probe_result {
                            Ok(Ok(_stream)) => {
                                let was_unhealthy = !healthy_flag.swap(true, Ordering::Relaxed);
                                if was_unhealthy {
                                    info!(backend = %addr, "Backend recovered and marked HEALTHY");
                                }
                            }
                            _ => {
                                let was_healthy = healthy_flag.swap(false, Ordering::Relaxed);
                                if was_healthy {
                                    error!(backend = %addr, "Backend health check failed; marked UNHEALTHY");
                                }
                            }
                        }
                    });
                }
            }
        });
    }
}
