use async_trait::async_trait;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

use reth::consensus_common::validation::full_validation;
use reth::revm::{database::StateProviderDatabase, processor::EVMProcessor};
use reth::primitives::{Address, ChainSpec, SealedBlock, U256};
use reth::providers::{
    AccountReader, BlockExecutor, BlockReaderIdExt, ChainSpecProvider, ChangeSetReader, HeaderProvider,
    StateProviderFactory, WithdrawalsProvider,
};
use reth::rpc::compat::engine::payload::try_into_sealed_block;
use reth::rpc::result::ToRpcResult;

use std::sync::Arc;

use crate::ValidationApi;

mod types;
pub use types::ValidationRequestBody;

mod result;
use result::internal_rpc_err;

/// trait interface for a custom rpc namespace: `validation`
///
/// This defines an additional namespace where all methods are configured as trait functions.
#[rpc(client, server, namespace = "flashbots")]
#[async_trait]
pub trait ValidationApi {
    /// Validates a block submitted to the relay
    #[method(name = "validateBuilderSubmissionV2")]
    async fn validate_builder_submission_v2(
        &self,
        request_body: ValidationRequestBody,
    ) -> RpcResult<()>;
}

impl<Provider> ValidationApi<Provider> 
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
    /// The provider that can interact with the chain.
    pub fn provider(&self) -> &Provider {
        &self.inner.provider
    }

    /// Create a new instance of the [ValidationApi]
    pub fn new(provider: Provider) -> Self {
        let inner = Arc::new(ValidationApiInner { provider });
        Self { inner }
    }

    fn check_proposer_payment(
        &self,
        block: &SealedBlock,
        chain_spec: Arc<ChainSpec>,
        _expected_payment: &U256,
        _fee_recipient: &Address
    ) -> RpcResult<()> {
        let state_provider = self.provider().latest().to_rpc_result()?;
        let mut executor = EVMProcessor::new_with_db(chain_spec, StateProviderDatabase::new(state_provider));
        let unsealed_block =  block.clone().unseal();
        executor.execute_and_verify_receipt(&unsealed_block, block.difficulty, None).map_err(|e| internal_rpc_err(format!("Error executing block: {:}", e.to_string())))?;
        Ok(())
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
            try_into_sealed_block(request_body.execution_payload.clone().into(), None).to_rpc_result()?;
        let chain_spec = self.provider().chain_spec();

        compare_values(
            "ParentHash",
            request_body.message.parent_hash,
            block.parent_hash,
        )?;
        compare_values("BlockHash", request_body.message.block_hash, block.hash())?;
        compare_values("GasLimit", request_body.message.gas_limit, block.gas_limit)?;
        compare_values("GasUsed", request_body.message.gas_used, block.gas_used)?;

        full_validation(&block, self.provider(), &chain_spec).to_rpc_result()?;

        self.check_proposer_payment(
            &block,
            chain_spec.clone(),
            &request_body.message.value,
            &request_body.execution_payload.fee_recipient
        )
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

fn compare_values<T: std::cmp::PartialEq + std::fmt::Display>(
    name: &str,
    expected: T,
    actual: T,
) -> RpcResult<()> {
    if expected != actual {
        Err(internal_rpc_err(format!(
            "incorrect {} {}, expected {}",
            name, actual, expected
        )))
    } else {
        Ok(())
    }
}

