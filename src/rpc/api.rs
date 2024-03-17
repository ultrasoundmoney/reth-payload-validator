use crate::rpc::ValidationRequestBody;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;

/// trait interface for a custom rpc namespace: `validation`
///
/// This defines an additional namespace where all methods are configured as trait functions.
#[cfg_attr(not(test), rpc(server, namespace = "flashbots"))]
#[cfg_attr(test, rpc(server, client, namespace = "flashbots"))]
pub trait ValidationApi {
    /// Validates a block submitted to the relay
    #[method(name = "validateBuilderSubmissionV3")]
    async fn validate_builder_submission_v3(
        &self,
        request_body: ValidationRequestBody,
    ) -> RpcResult<()>;
}
