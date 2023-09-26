use reth::{
    cli::{
        config::RethRpcConfig,
        ext::{RethCliExt, RethNodeCommandConfig},
    },
    network::{NetworkInfo, Peers},
    providers::{
        BlockReaderIdExt, CanonStateSubscriptions, ChainSpecProvider, ChangeSetReader,
        EvmEnvProvider, StateProviderFactory,
    },
    rpc::builder::{RethModuleRegistry, TransportRpcModules},
    tasks::TaskSpawner,
    transaction_pool::TransactionPool,
};

use crate::ValidationExt;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

/// The type that tells the reth CLI what extensions to use
pub struct MyRethCliExt;

impl RethCliExt for MyRethCliExt {
    /// This tells the reth CLI to install the `txpool` rpc namespace via `RethCliValidationExt`
    type Node = RethCliValidationExt;
}

/// Our custom cli args extension that adds one flag to reth default CLI.
#[derive(Debug, Clone, Copy, Default, clap::Args)]
pub struct RethCliValidationExt {
    /// CLI flag to enable the txpool extension namespace
    #[clap(long)]
    pub enable_ext: bool,
}

impl RethNodeCommandConfig for RethCliValidationExt {
    // This is the entrypoint for the CLI to extend the RPC server with custom rpc namespaces.
    fn extend_rpc_modules<Conf, Provider, Pool, Network, Tasks, Events>(
        &mut self,
        _config: &Conf,
        registry: &mut RethModuleRegistry<Provider, Pool, Network, Tasks, Events>,
        modules: &mut TransportRpcModules,
    ) -> eyre::Result<()>
    where
        Conf: RethRpcConfig,
        Provider: BlockReaderIdExt
            + StateProviderFactory
            + EvmEnvProvider
            + ChainSpecProvider
            + ChangeSetReader
            + Clone
            + Unpin
            + 'static,
        Pool: TransactionPool + Clone + 'static,
        Network: NetworkInfo + Peers + Clone + 'static,
        Tasks: TaskSpawner + Clone + 'static,
        Events: CanonStateSubscriptions + Clone + 'static,
    {
        if !self.enable_ext {
            return Ok(())
        }

        // here we get the configured pool type from the CLI.
        let provider = registry.provider().clone();
        let ext = ValidationExt::new(provider);

        // now we merge our extension namespace into all configured transports
        modules.merge_configured(ext.into_rpc())?;

        println!("txpool extension enabled");
        Ok(())
    }
}


