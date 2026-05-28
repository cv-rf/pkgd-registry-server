# --- Build Stage ---
FROM rust:1.80-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Create a dummy src/main.rs to build dependencies and cache them
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -f target/release/deps/pkgd_registry_server*

# Copy actual source and templates
COPY src ./src
COPY templates ./templates

# Build the real app
RUN cargo build --release

# --- Runtime Stage ---
FROM debian:slim AS runtime

WORKDIR /app

# Install runtime dependencies (SQLite and SSL)
RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy binary and assets
COPY --from:builder /app/target/release/pkgd-registry-server ./pkgd-registry-server
COPY --from:builder /app/templates ./templates

# Create storage directory
RUN mkdir -p storage/packages

# Expose the port
EXPOSE 9999

# Environment variables
ENV DATABASE_URL=sqlite://registry.db?mode=rwc
ENV RUST_LOG=info

# Run the server
CMD ["./pkgd-registry-server"]