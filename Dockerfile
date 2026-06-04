# Build stage
FROM rust:1.95-alpine AS builder
WORKDIR /app

# Install system dependencies
RUN apk add --no-cache musl-dev pkgconfig openssl-dev gcc

# Create a dummy project to cache dependencies
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src

# Copy the actual source code and build the real binary
COPY . .
RUN cargo build --release

# Runtime stage
FROM alpine:latest
WORKDIR /app

# Install runtime dependencies including SSL and base libraries often needed by Rust
RUN apk add --no-cache ca-certificates libgcc libstdc++ openssl

# Copy binary from builder
COPY --from=builder /app/target/release/pkgd-registry-server /usr/local/bin/

# Copy templates directory which is required at runtime by Tera
COPY --from=builder /app/templates /app/templates

# Copy installation script
COPY --from=builder /app/install.sh /app/install.sh

# Set default environment variables
ENV DATABASE_URL="postgres://postgres:postgres@db:5432/pkgd_registry"
ENV RUST_LOG="info,pkgd_registry_server=debug,tower_http=info"
ENV RUST_BACKTRACE=1

# Expose the port the server listens on
EXPOSE 9999

# Run the binary with full path
ENTRYPOINT ["/usr/local/bin/pkgd-registry-server"]
