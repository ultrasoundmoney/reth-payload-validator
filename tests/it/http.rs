use jsonrpsee::{core::error::Error, http_client::HttpClientBuilder, server::ServerBuilder};
use reth::providers::test_utils::NoopProvider;
use reth_block_validator::rpc::{ValidationApiClient, ValidationApiServer, ValidationRequestBody};
use reth_block_validator::ValidationApi;

const VALIDATION_REQUEST_BODY: &str = include_str!("../../tests/data/single_payload.json");

#[tokio::test(flavor = "multi_thread")]
async fn test_call_admin_functions_ws() {
    let server_addr = start_server().await;
    let uri = format!("http://{}", server_addr);
    let client = HttpClientBuilder::default().build(&uri).unwrap();
    let validation_request_body: ValidationRequestBody =
        serde_json::from_str(VALIDATION_REQUEST_BODY).unwrap();
    let result = ValidationApiClient::validate_builder_submission_v2(
        &client,
        validation_request_body.clone(),
    )
    .await;
    let expected_message = format!(
        "Block parent [hash:{:?}] is not known.",
        validation_request_body.execution_payload.parent_hash
    );
    let error_message = get_call_error_message(result.unwrap_err()).unwrap();
    assert_eq!(error_message, expected_message);
}

async fn start_server() -> std::net::SocketAddr {
    let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    let provider = NoopProvider::default();
    let api = ValidationApi::new(provider);
    let server_handle = server.start(api.into_rpc());

    tokio::spawn(server_handle.stopped());

    addr
}

fn get_call_error_message(err: Error) -> Option<String> {
    match err {
        Error::Call(error_obj) => Some(error_obj.message().to_string()),
        _ => None,
    }
}
