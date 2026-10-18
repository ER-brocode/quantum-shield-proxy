//! QuantumShield Reverse Proxy Gateway
//!
//! Exposes the high-performance TLS 1.3 termination engine, load balancer,
//! and Prometheus observability subsystem.

pub mod load_balancer;
pub mod metrics;
pub mod proxy;

pub use load_balancer::{Backend, BalancingStrategy, LoadBalancer};
pub use metrics::GatewayMetrics;
pub use proxy::{GatewayOptions, QuantumGateway};
