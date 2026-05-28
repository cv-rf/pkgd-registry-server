
FROM rustlang/rust:nightly-slim AS builder

WORKDIR /app

ENV SQLX_OFFLINE=true

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./

RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -f target/release/deps/pkgd_registry_server*

COPY src ./src
COPY templates ./templates
COPY .sqlx ./.sqlx

RUN cargo build --release

FROM debian:bookworm-slim AS runtime

WORKDIR /app

RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/pkgd-registry-server ./pkgd-registry-server
COPY --from=builder /app/templates ./templates

RUN mkdir -p storage/packages

EXPOSE 9999

ENV DATABASE_URL=sqlite:registry.db?mode=rwc
ENV RUST_LOG=info

CMD ["./pkgd-registry-server"]
