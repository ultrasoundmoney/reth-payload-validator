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
use reth_node_ethereum::EthereumNode;
use reth_payload_validator::{rpc::ValidationApiServer, ValidationApi, ValidationCliExt};

fn main() {
    Cli::<ValidationCliExt>::parse()
        .run(|builder, _args| async move {
            let handle = builder
                .node(EthereumNode::default())
                .extend_rpc_modules(move |ctx| {
                    // here we get the configured pool.
                    let provider = ctx.provider().clone();

                    let ext = ValidationApi::new(provider);

                    // now we merge our extension namespace into all configured transports
                    ctx.modules.merge_configured(ext.into_rpc())?;

                    println!("txpool extension enabled");
                    Ok(())
                })
                .launch()
                .await?;
            handle.wait_for_node_exit().await
        })
        .unwrap();
}
