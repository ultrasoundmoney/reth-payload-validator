FROM rust as builder
WORKDIR /app

# Build deps. We replace our main.rs with a dummy.rs to avoid rebuilding the
# main executable, creating a cached layer for the dependencies.

# Reth requires libclang-dev and pkg-config to build.
RUN apt-get update && apt-get -y upgrade && apt-get install -y libclang-dev pkg-config

COPY Cargo.toml Cargo.lock ./
RUN mkdir src/
RUN echo "fn main() {}" > dummy.rs
RUN sed -i 's#src/main.rs#dummy.rs#' Cargo.toml
RUN cargo build --release

# Build executable.
RUN sed -i 's#dummy.rs#src/main.rs#' Cargo.toml
COPY src ./src
RUN cargo build --release

# Build runtime image.
FROM gcr.io/distroless/cc-debian12 AS runtime
WORKDIR /app
COPY --from=builder /app/target/release/reth-payload-validator /app/reth-payload-validator
ENTRYPOINT ["/app/reth-payload-validator"]
