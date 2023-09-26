//! Example of how to use additional rpc namespaces in the reth CLI
//!
//! Run with
//!
//! ```not_rust
//! cargo run -p additional-rpc-namespace-in-cli -- node --http --ws --enable-ext
//! ```
//!
//! This installs an additional RPC method `txpoolExt_transactionCount` that can queried via [cast](https://github.com/foundry-rs/foundry)
//!
//! ```sh
//! cast rpc txpoolExt_transactionCount
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

/// The type that implements the `txpool` rpc namespace trait
pub struct ValidationApi<Provider> {
    inner: Arc<ValidationApiInner<Provider>>,
}
