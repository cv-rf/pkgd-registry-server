# Build stage
FROM rust:1.95-alpine AS builder
WORKDIR /app

# Install system dependencies
RUN apk add --no-cache musl-dev pkgconfig openssl-dev gcc

# Copy only the dependency files to cache them
COPY Cargo.toml Cargo.lock ./

# Build the release binary
COPY . .
RUN cargo build --release

# Runtime stage
FROM alpine:latest
WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates

# Copy binary from builder
COPY --from=builder /app/target/release/pkgd-registry-server /usr/local/bin/

# Copy templates directory which is required at runtime by Tera
COPY --from=builder /app/templates /app/templates

# Set default environment variables
ENV DATABASE_URL="postgres://postgres:postgres@db:5432/pkgd_registry"
ENV RUST_LOG="info,pkgd_registry_server=debug"

# Expose the port the server listens on
EXPOSE 9999

# Run the binary
CMD ["pkgd-registry-server"]
