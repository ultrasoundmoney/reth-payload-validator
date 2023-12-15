use jsonrpsee::{core::RpcResult, proc_macros::rpc};

use crate::ValidationApi;
use reth::providers::{
    AccountReader, BlockReaderIdExt, ChainSpecProvider, HeaderProvider, StateProviderFactory,
    WithdrawalsProvider,
};
use std::sync::Arc;

mod types;
pub use types::*;

mod result;
mod utils;
mod validation;
use validation::ValidationRequest;

/// trait interface for a custom rpc namespace: `validation`
///
/// This defines an additional namespace where all methods are configured as trait functions.
#[rpc(client, server, namespace = "flashbots")]
pub trait ValidationApi {
    /// Validates a block submitted to the relay
    #[method(name = "validateBuilderSubmissionV2", blocking)]
    fn validate_builder_submission_v2(&self, request_body: ValidationRequestBody) -> RpcResult<()>;
}

impl<Provider> ValidationApi<Provider>
where
    Provider: BlockReaderIdExt
        + ChainSpecProvider
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
}

impl<Provider> ValidationApiServer for ValidationApi<Provider>
where
    Provider: BlockReaderIdExt
        + ChainSpecProvider
        + StateProviderFactory
        + HeaderProvider
        + AccountReader
        + WithdrawalsProvider
        + 'static,
{
    /// Validates a block submitted to the relay
    fn validate_builder_submission_v2(&self, request_body: ValidationRequestBody) -> RpcResult<()> {
        let request = ValidationRequest::new(request_body, self.provider());
        request.validate()
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
