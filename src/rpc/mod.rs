pub use crate::rpc::api::ValidationApiServer;
use async_trait::async_trait;
use jsonrpsee::core::RpcResult;
use jsonrpsee::types::error::ErrorCode;
use reth::providers::{
    AccountReader, BlockReaderIdExt, ChainSpecProvider, HeaderProvider, StateProviderFactory,
    WithdrawalsProvider,
};
use std::sync::Arc;
pub use types::*;
use validation::ValidationRequest;

mod api;
mod result;
mod types;
mod utils;
mod validation;

/// The type that implements the `validation` rpc namespace trait
pub struct ValidationApi<Provider> {
    inner: Arc<ValidationApiInner<Provider>>,
}

impl<Provider> ValidationApi<Provider>
where
    Provider: BlockReaderIdExt
        + ChainSpecProvider
        + StateProviderFactory
        + HeaderProvider
        + AccountReader
        + WithdrawalsProvider
        + Clone
        + 'static,
{
    /// The provider that can interact with the chain.
    pub fn provider(&self) -> Provider {
        self.inner.provider.clone()
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
        + StateProviderFactory
        + HeaderProvider
        + AccountReader
        + WithdrawalsProvider
        + Clone
        + 'static,
{
    /// Validates a block submitted to the relay
    async fn validate_builder_submission_v3(
        &self,
        request_body: ValidationRequestBody,
    ) -> RpcResult<()> {
        let request = ValidationRequest::new(request_body, self.provider());
        tokio::task::spawn_blocking(move || request.validate())
            .await
            .map_err(|_| ErrorCode::InternalError)?
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
