# Build Stage
FROM rust:1-bookworm AS builder

WORKDIR /usr/src/quantum-shield-proxy
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests

RUN cargo build --release

# Runtime Stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /usr/src/quantum-shield-proxy/target/release/quantum-shield-proxy /usr/local/bin/quantum-shield-proxy
COPY quantum-shield.yaml /app/quantum-shield.yaml

# Create unprivileged user
RUN useradd -u 10001 -m -s /bin/bash appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8443

HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
    CMD curl -f -k https://127.0.0.1:8443/healthz || exit 1

ENTRYPOINT ["quantum-shield-proxy"]
CMD ["run", "--config", "/app/quantum-shield.yaml"]
