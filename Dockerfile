# Build stage
FROM rust:1.80-slim AS builder
WORKDIR /app

# Install build dependencies (C compiler needed for SQLite and reqs)
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev gcc && \
    rm -rf /var/lib/apt/lists/*

COPY . .

# Use SQLx offline mode since .sqlx directory is present
ENV SQLX_OFFLINE=true

# Build the release binary
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
ENV DATABASE_URL="sqlite:/app/data/registry.db?mode=rwc"
ENV RUST_LOG="info,pkgd_registry_server=debug"

# Expose the port the server listens on
EXPOSE 9999

# Run the binary
CMD ["pkgd-registry-server"]