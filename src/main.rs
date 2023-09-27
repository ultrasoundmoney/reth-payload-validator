//! Reth RPC extension to add endpoint for builder payload validation
//!
//! Run with
//!
//! ```not_rust
//! RUST_LOG=info cargo run -- node --full --metrics 127.0.0.1:9001 --http --enable-ext
//! ```
//!
//! This installs an additional RPC method that can be queried using the provided sample rpc
//! payload
//!
//! ```sh
//! curl --location 'localhost:8545/' --header 'Content-Type: application/json' --data @test/data/rpc_payload.json
//! ```
use clap::Parser;
use reth::cli::Cli;
use std::sync::Arc;

mod cli_ext;
use cli_ext::ValidationCliExt;

mod rpc;
use rpc::ValidationApiInner;

fn main() {
    Cli::<ValidationCliExt>::parse().run().unwrap();
}

/// The type that implements the `validation` rpc namespace trait
pub struct ValidationApi<Provider> {
    inner: Arc<ValidationApiInner<Provider>>,
}
