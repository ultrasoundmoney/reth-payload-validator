use reth::cli::{
        config::RethRpcConfig,
        ext::{RethCliExt, RethNodeCommandConfig},
        components::{RethNodeComponents, RethRpcComponents},
    };

use crate::rpc::ValidationApiServer;
use crate::ValidationApi;

/// The type that tells the reth CLI what extensions to use
pub struct ValidationCliExt;

impl RethCliExt for ValidationCliExt {
    /// This tells the reth CLI to install the `validation` rpc namespace via `RethCliValidationApi`
    type Node = RethCliValidationApi;
}

/// Our custom cli args extension that adds one flag to reth default CLI.
#[derive(Debug, Clone, Copy, Default, clap::Args)]
pub struct RethCliValidationApi {
    /// CLI flag to enable the validation extension namespace
    #[clap(long)]
    pub enable_ext: bool,
}

impl RethNodeCommandConfig for RethCliValidationApi {
    // This is the entrypoint for the CLI to extend the RPC server with custom rpc namespaces.
    fn extend_rpc_modules<Conf, Reth>(
        &mut self,
        _config: &Conf,
        _components: &Reth,
        rpc_components: RethRpcComponents<'_, Reth>,
    ) -> eyre::Result<()>
    where
        Conf: RethRpcConfig,
        Reth: RethNodeComponents,
    {
        if !self.enable_ext {
            return Ok(());
        }

        // here we get the configured pool type from the CLI.
        let provider = rpc_components.registry.provider().clone();
        let ext = ValidationApi::new(provider);

        // now we merge our extension namespace into all configured transports
        rpc_components.modules.merge_configured(ext.into_rpc())?;

        println!("validation extension enabled");
        Ok(())
    }
}
