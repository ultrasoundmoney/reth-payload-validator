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
use reth_block_validator::ValidationCliExt;

fn main() {
    Cli::<ValidationCliExt>::parse().run().unwrap();
}
