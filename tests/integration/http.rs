use jsonrpsee::{
    core::error::Error,
    http_client::{HttpClient, HttpClientBuilder},
    server::ServerBuilder,
};
use reth::providers::test_utils::MockEthProvider;
use reth::primitives::{Address, Block, Bloom, Bytes, Header, B256, U256};
use reth_block_validator::rpc::{BidTrace, ExecutionPayloadValidation, ValidationApiClient, ValidationApiServer, ValidationRequestBody};
use reth_block_validator::ValidationApi;

const VALIDATION_REQUEST_BODY: &str = include_str!("../../tests/data/single_payload.json");

#[tokio::test(flavor = "multi_thread")]
async fn test_unknown_parent_hash() {
    let client = get_client(None).await;
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

#[tokio::test(flavor = "multi_thread")]
async fn test_valid_block() {
    let provider = MockEthProvider::default();
    let client = get_client(Some(provider.clone())).await;

    let base_fee_per_gas = 1_000_000_000;
    let block = Block {
        header: Header {
            parent_hash: B256::default(),
            beneficiary: Address::default(),
            logs_bloom: Bloom::default(),
            mix_hash: B256::default(),
            ommers_hash: B256::default(),
            receipts_root: B256::default(),
            state_root: B256::default(),
            transactions_root: B256::default(),
            withdrawals_root: Some(B256::default()),
            parent_beacon_block_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            extra_data: Bytes::default(),
            timestamp: 0,
            number: 0,
            gas_limit: 0,
            gas_used: 0,
            difficulty: U256::from(0),
            base_fee_per_gas: Some(base_fee_per_gas),
            nonce: 0,
        },
        body: vec![],
        ommers: vec![],
        withdrawals: Some(vec![]),
    };

    let block_hash = block.header.hash_slow();


    let mut validation_request_body = ValidationRequestBody {
        execution_payload: ExecutionPayloadValidation {
            parent_hash: block.header.parent_hash,
            state_root: block.header.state_root,
            receipts_root: block.header.receipts_root,
            logs_bloom: block.header.logs_bloom,
            gas_used: block.header.gas_used,
            gas_limit: block.header.gas_limit,
            timestamp: block.header.timestamp,
            extra_data: block.header.extra_data,
            base_fee_per_gas: U256::from(block.header.base_fee_per_gas.unwrap()),
            block_hash,
            block_number: block.header.number,
            fee_recipient: block.header.beneficiary,
            transactions: vec![],
            withdrawals:  vec![],
            prev_randao: B256::default(),
        },
        message: BidTrace::default(),
        registered_gas_limit: 0.to_string(),
        signature: Bytes::default(),
    };
        
        


    validation_request_body.execution_payload.base_fee_per_gas = U256::from(base_fee_per_gas);
    println!("validation_request_body: {:?}", validation_request_body);
    let result = ValidationApiClient::validate_builder_submission_v2(
        &client,
        validation_request_body.clone(),
    ).await;
    println!("result: {:?}", result);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_wrong_hash() {
    let client = get_client(None).await;

    let validation_request_body: ValidationRequestBody =
        serde_json::from_str(VALIDATION_REQUEST_BODY).unwrap();
    let old_timestamp = format!("{:}", validation_request_body.execution_payload.timestamp);
    let new_timestamp = "1234567";

    let validation_request_body_wrong_timestamp: ValidationRequestBody =
        serde_json::from_str(&VALIDATION_REQUEST_BODY.replace(&old_timestamp, new_timestamp))
            .unwrap();
    let result = ValidationApiClient::validate_builder_submission_v2(
        &client,
        validation_request_body_wrong_timestamp,
    )
    .await;
    let error_message = get_call_error_message(result.unwrap_err()).unwrap();
    assert!(error_message.contains("blockhash mismatch"));
}

async fn get_client(provider: Option<MockEthProvider>) -> HttpClient {
    let server_addr = start_server(provider).await;
    let uri = format!("http://{}", server_addr);
    HttpClientBuilder::default().build(uri).unwrap()
}

async fn start_server(provider: Option<MockEthProvider>) -> std::net::SocketAddr {
    let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    let provider = provider.unwrap_or_default();
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
