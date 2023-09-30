use async_trait::async_trait;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

use reth::consensus_common::validation::full_validation;
use reth::providers::{
    AccountReader, BlockReaderIdExt, ChainSpecProvider, ChangeSetReader, HeaderProvider,
    StateProviderFactory, WithdrawalsProvider,
};
use reth::rpc::compat::engine::payload::try_into_sealed_block;
use reth::rpc::result::ToRpcResult;

use std::sync::Arc;

use crate::ValidationApi;

mod types;
use types::ValidationRequestBody;

mod result;
use result::internal_rpc_err;

/// trait interface for a custom rpc namespace: `validation`
///
/// This defines an additional namespace where all methods are configured as trait functions.
#[rpc(server, namespace = "flashbots")]
#[async_trait]
pub trait ValidationApi {
    /// Validates a block submitted to the relay
    #[method(name = "validateBuilderSubmissionV2")]
    async fn validate_builder_submission_v2(
        &self,
        request_body: ValidationRequestBody,
    ) -> RpcResult<()>;
}

impl<Provider> ValidationApi<Provider> {
    /// The provider that can interact with the chain.
    pub fn provider(&self) -> &Provider {
        &self.inner.provider
    }

    /// Create a new instance of the [ValidationApi]
    pub fn new(provider: Provider) -> Self {
        let inner = Arc::new(ValidationApiInner { provider });
        Self { inner }
    }
}

#[async_trait]
impl<Provider> ValidationApiServer for ValidationApi<Provider>
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
    async fn validate_builder_submission_v2(
        &self,
        request_body: ValidationRequestBody,
    ) -> RpcResult<()> {
        let block =
            try_into_sealed_block(request_body.execution_payload.into(), None).to_rpc_result()?;
        let chain_spec = self.provider().chain_spec();

        if request_body.message.parent_hash != block.parent_hash {
            return Err(internal_rpc_err(format!(
                "incorrect ParentHash {}, expected {}",
                request_body.message.parent_hash, block.parent_hash
            )));
        }

        if request_body.message.block_hash != block.hash() {
            return Err(internal_rpc_err(format!(
                "incorrect BlockHash {}, expected {}",
                request_body.message.block_hash,
                block.hash()
            )));
        }

        if request_body.message.gas_limit != block.gas_limit {
            return Err(internal_rpc_err(format!(
                "incorrect GasLimit {}, expected {}",
                request_body.message.gas_limit, block.gas_limit
            )));
        }

        if request_body.message.gas_used != block.gas_used {
            return Err(internal_rpc_err(format!(
                "incorrect GasUsed {}, expected {}",
                request_body.message.gas_used, block.gas_used
            )));
        }

        full_validation(&block, self.provider(), &chain_spec).to_rpc_result()
    }
}

impl<Provider> std::fmt::Debug for ValidationApi<Provider> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidationApi").finish_non_exhaustive()
    }
}

impl<Provider> Clone for ValidationApi<Provider> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

pub struct ValidationApiInner<Provider> {
    /// The provider that can interact with the chain.
    provider: Provider,
}
