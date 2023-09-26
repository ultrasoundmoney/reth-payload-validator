use async_trait::async_trait;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

use reth::consensus_common::validation::full_validation;
use reth::providers::{
    AccountReader, BlockReaderIdExt, ChainSpecProvider, ChangeSetReader, HeaderProvider,
    StateProviderFactory, WithdrawalsProvider,
};
use reth::rpc::types_compat::engine::payload::try_into_sealed_block;
use reth::rpc::result::ToRpcResultExt;

use std::sync::Arc;

use crate::ValidationExt;


mod types;
use types::ExecutionPayloadValidation;

/// trait interface for a custom rpc namespace: `validation`
///
/// This defines an additional namespace where all methods are configured as trait functions.
#[rpc(server, namespace = "validationExt")]
#[async_trait]
pub trait ValidationApi {
    /// Validates a block submitted to the relay
    #[method(name = "validateBuilderSubmissionV1")]
    async fn validate_builder_submission_v1(
        &self,
        execution_payload: ExecutionPayloadValidation,
    ) -> RpcResult<()>;
}


impl<Provider> ValidationExt<Provider> {
    /// The provider that can interact with the chain.
    pub fn provider(&self) -> &Provider {
        &self.inner.provider
    }

    /// Create a new instance of the [ValidationExt]
    pub fn new(provider: Provider) -> Self {
        let inner = Arc::new(ValidationExtInner { provider });
        Self { inner }
    }
}

#[async_trait]
impl<Provider> ValidationApiServer for ValidationExt<Provider>
where
    Provider: BlockReaderIdExt
        + ChainSpecProvider
        + ChangeSetReader
        + StateProviderFactory
        + HeaderProvider
        + AccountReader
        + WithdrawalsProvider
        + 'static,
{
    /// Validates a block submitted to the relay
    async fn validate_builder_submission_v1(
        &self,
        execution_payload: ExecutionPayloadValidation,
    ) -> RpcResult<()> {
        let block = try_into_sealed_block(execution_payload.into(), None).map_ok_or_rpc_err()?;
        let chain_spec = self.provider().chain_spec();
        full_validation(&block, self.provider(), &chain_spec).map_ok_or_rpc_err()
    }
}

impl<Provider> std::fmt::Debug for ValidationExt<Provider> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidationApi").finish_non_exhaustive()
    }
}

impl<Provider> Clone for ValidationExt<Provider> {
    fn clone(&self) -> Self {
        Self { inner: Arc::clone(&self.inner) }
    }
}


pub struct ValidationExtInner<Provider> {
    /// The provider that can interact with the chain.
    provider: Provider,
}
