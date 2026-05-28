# Build stage
# Using the full image instead of slim to ensure all build-essential tools are present
FROM rust:1.85 AS builder
WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev gcc && \
    rm -rf /var/lib/apt/lists/*

# Copy only the dependency files to cache them
COPY Cargo.toml Cargo.lock ./

# Build the release binary
COPY . .
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim
WORKDIR /app

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /app/target/release/pkgd-registry-server /usr/local/bin/

# Copy templates directory which is required at runtime by Tera
COPY --from=builder /app/templates /app/templates

# Set default environment variables
# Note: These can be overridden by docker-compose or Portainer settings
ENV DATABASE_URL="postgres://atticl:XUk2k1BSm8nztlW5gz8U93qDPPoCLQ@172.21.0.2:5432/tornhost_db"
ENV RUST_LOG="info,pkgd_registry_server=debug"

# Expose the port the server listens on
EXPOSE 9999

# Run the binary
CMD ["pkgd-registry-server"]
