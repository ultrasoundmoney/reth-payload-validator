use reth::{
    cli::{
        config::RethRpcConfig,
        ext::{RethCliExt, RethNodeCommandConfig},
    },
    network::{NetworkInfo, Peers},
    providers::{
        AccountReader, BlockReaderIdExt, CanonStateSubscriptions, ChainSpecProvider,
        ChangeSetReader, EvmEnvProvider, StateProviderFactory,
    },
    rpc::builder::{RethModuleRegistry, TransportRpcModules},
    tasks::TaskSpawner,
    transaction_pool::TransactionPool,
};

use crate::rpc::ValidationApiServer;
use crate::ValidationApi;

/// The type that tells the reth CLI what extensions to use
pub struct ValidationCliExt;

impl RethCliExt for ValidationCliExt {
    /// This tells the reth CLI to install the `txpool` rpc namespace via `RethCliValidationApi`
    type Node = RethCliValidationApi;
}

/// Our custom cli args extension that adds one flag to reth default CLI.
#[derive(Debug, Clone, Copy, Default, clap::Args)]
pub struct RethCliValidationApi {
    /// CLI flag to enable the txpool extension namespace
    #[clap(long)]
    pub enable_ext: bool,
}

impl RethNodeCommandConfig for RethCliValidationApi {
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
            + AccountReader
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
            return Ok(());
        }

        // here we get the configured pool type from the CLI.
        let provider = registry.provider().clone();
        let ext = ValidationApi::new(provider);

        // now we merge our extension namespace into all configured transports
        modules.merge_configured(ext.into_rpc())?;

        println!("txpool extension enabled");
        Ok(())
    }
}
