use jsonrpsee::{
    core::error::Error,
    http_client::{HttpClient, HttpClientBuilder},
    server::ServerBuilder,
};
use reth::primitives::{
    keccak256, sign_message, AccessList, Address, Block, Bytes, ReceiptWithBloom, Transaction,
    TransactionKind, TransactionSigned, TxEip1559, B256, U256,
};
use reth::revm::{database::StateProviderDatabase, processor::EVMProcessor};
use reth::rpc::compat::engine::payload::try_into_block;
use reth::{
    providers::test_utils::{ExtendedAccount, MockEthProvider},
    revm::primitives::FixedBytes,
};
use reth_block_validator::rpc::{ValidationApiClient, ValidationApiServer, ValidationRequestBody};
use reth_block_validator::ValidationApi;
use secp256k1::{rand, PublicKey, Secp256k1, SecretKey};
use std::time::{SystemTime, UNIX_EPOCH};

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
    let validation_request_body: ValidationRequestBody = generate_valid_request(provider, None);

    let result = ValidationApiClient::validate_builder_submission_v2(
        &client,
        validation_request_body.clone(),
    )
    .await;
    assert!(result.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_proposer_payment_validation_via_balance_change() {
    let provider = MockEthProvider::default();
    let client = get_client(Some(provider.clone())).await;
    let mut validation_request_body: ValidationRequestBody =
        generate_valid_request(provider.clone(), None);

    let (sender_secret_key, sender_address) = generate_random_key();
    provider.add_account(sender_address, ExtendedAccount::new(0, U256::MAX));
    let (_, receiver_address) = generate_random_key();

    let other_transaction = sign_transaction(
        &sender_secret_key,
        Transaction::Eip1559(TxEip1559 {
            chain_id: 1,
            nonce: 0,
            gas_limit: 21000,
            to: TransactionKind::Call(receiver_address),
            value: 1_000_000_u128,
            input: Bytes::default(),
            max_fee_per_gas: 0x4a817c800,
            max_priority_fee_per_gas: 0x3b9aca00,
            access_list: AccessList::default(),
        }),
    );

    // By adding additional transactions to the end we make sure that the reward is checked via the
    // block balance change
    validation_request_body = seal_request_body(add_transactions(
        validation_request_body,
        vec![other_transaction],
        provider,
    ));
    println!(
        "request_body_tx: {:#?}",
        validation_request_body.execution_payload.transactions
    );

    let result = ValidationApiClient::validate_builder_submission_v2(
        &client,
        validation_request_body.clone(),
    )
    .await;
    println!("result: {:#?}", result);
    assert!(result.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_proposer_spent_in_same_block() {
    let provider = MockEthProvider::default();
    let client = get_client(Some(provider.clone())).await;
    let (recipient_private_key, recipient_address) = generate_random_key();
    let mut validation_request_body: ValidationRequestBody =
        generate_valid_request(provider.clone(), Some(recipient_address));
    // Note: This is not necessary for this test but added here to make it otherwise identical to
    // the passing case with the reordered transactions
    provider.add_account(
        recipient_address,
        ExtendedAccount::new(0, validation_request_body.message.value),
    );

    let (sender_secret_key, sender_address) = generate_random_key();
    provider.add_account(sender_address, ExtendedAccount::new(0, U256::MAX));
    let (_, receiver_address) = generate_random_key();

    let amount_to_send = validation_request_body.message.value / U256::from(2);
    let spend_proposer_payment_tx = sign_transaction(
        &recipient_private_key,
        Transaction::Eip1559(TxEip1559 {
            chain_id: 1,
            nonce: 0,
            gas_limit: 21000,
            to: TransactionKind::Call(receiver_address),
            value: amount_to_send.try_into().unwrap(),
            input: Bytes::default(),
            max_fee_per_gas: 0x4a817c800,
            max_priority_fee_per_gas: 0x3b9aca00,
            access_list: AccessList::default(),
        }),
    );

    let other_transaction = sign_transaction(
        &sender_secret_key,
        Transaction::Eip1559(TxEip1559 {
            chain_id: 1,
            nonce: 0,
            gas_limit: 21000,
            to: TransactionKind::Call(receiver_address),
            value: 1_000_000_u128,
            input: Bytes::default(),
            max_fee_per_gas: 0x4a817c800,
            max_priority_fee_per_gas: 0x3b9aca00,
            access_list: AccessList::default(),
        }),
    );

    validation_request_body = seal_request_body(add_transactions(
        validation_request_body,
        vec![spend_proposer_payment_tx, other_transaction],
        provider,
    ));

    let result = ValidationApiClient::validate_builder_submission_v2(
        &client,
        validation_request_body.clone(),
    )
    .await;
    let error_message = get_call_error_message(result.unwrap_err()).unwrap();
    // Because the check based on the balance difference failed it will revert to checking the last
    // transaction and find that it is not going to the fee recipient
    assert!(error_message.contains("does not match fee recipient"));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_proposer_spent_in_same_block_but_payment_tx_last() {
    let provider = MockEthProvider::default();
    let client = get_client(Some(provider.clone())).await;
    let (recipient_private_key, recipient_address) = generate_random_key();
    let mut validation_request_body: ValidationRequestBody =
        generate_valid_request(provider.clone(), Some(recipient_address));
    provider.add_account(
        recipient_address,
        ExtendedAccount::new(0, validation_request_body.message.value),
    );

    let (sender_secret_key, sender_address) = generate_random_key();
    provider.add_account(sender_address, ExtendedAccount::new(0, U256::MAX));
    let (_, receiver_address) = generate_random_key();

    let amount_to_send = validation_request_body.message.value / U256::from(2);
    let spend_proposer_payment_tx = sign_transaction(
        &recipient_private_key,
        Transaction::Eip1559(TxEip1559 {
            chain_id: 1,
            nonce: 0,
            gas_limit: 21000,
            to: TransactionKind::Call(receiver_address),
            value: amount_to_send.try_into().unwrap(),
            input: Bytes::default(),
            max_fee_per_gas: 0x4a817c800,
            max_priority_fee_per_gas: 0x3b9aca00,
            access_list: AccessList::default(),
        }),
    );

    let other_transaction = sign_transaction(
        &sender_secret_key,
        Transaction::Eip1559(TxEip1559 {
            chain_id: 1,
            nonce: 0,
            gas_limit: 21000,
            to: TransactionKind::Call(receiver_address),
            value: 1_000_000_u128,
            input: Bytes::default(),
            max_fee_per_gas: 0x4a817c800,
            max_priority_fee_per_gas: 0x3b9aca00,
            access_list: AccessList::default(),
        }),
    );

    validation_request_body = add_transactions(
        validation_request_body,
        vec![spend_proposer_payment_tx, other_transaction],
        provider,
    );
    // Note that this reordering makes the payload verifiable by putting the proposer paymnent last
    validation_request_body.execution_payload.transactions = vec![
        validation_request_body.execution_payload.transactions[1].clone(),
        validation_request_body.execution_payload.transactions[2].clone(),
        validation_request_body.execution_payload.transactions[0].clone(),
    ];
    validation_request_body = seal_request_body(validation_request_body);

    let result = ValidationApiClient::validate_builder_submission_v2(
        &client,
        validation_request_body.clone(),
    )
    .await;
    assert!(result.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_insufficient_proposer_payment() {
    let provider = MockEthProvider::default();
    let client = get_client(Some(provider.clone())).await;

    let mut validation_request_body: ValidationRequestBody = generate_valid_request(provider, None);
    let original_proposer_payment = validation_request_body.message.value;
    let new_proposer_payment = original_proposer_payment + original_proposer_payment;
    validation_request_body.message.value = new_proposer_payment;
    let validation_request_body = seal_request_body(validation_request_body);

    let result = ValidationApiClient::validate_builder_submission_v2(
        &client,
        validation_request_body.clone(),
    )
    .await;

    let expected_error_message = format!(
        "Proposer payment tx value {:} does not match expected payment {:}",
        original_proposer_payment, new_proposer_payment
    );
    let error_message = get_call_error_message(result.unwrap_err()).unwrap();
    assert_eq!(error_message, expected_error_message);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_wrong_hash() {
    let provider = MockEthProvider::default();
    let client = get_client(Some(provider.clone())).await;

    let mut validation_request_body: ValidationRequestBody = generate_valid_request(provider, None);
    validation_request_body.execution_payload.timestamp =
        validation_request_body.execution_payload.timestamp + 1;

    let result =
        ValidationApiClient::validate_builder_submission_v2(&client, validation_request_body).await;
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

fn add_block(provider: MockEthProvider, gas_limit: u64, base_fee_per_gas: u64) -> Block {
    let block = generate_block(gas_limit, base_fee_per_gas);
    let block_hash = block.header.hash_slow();
    provider.add_block(block_hash, block.clone());
    block
}

fn generate_valid_request(
    provider: MockEthProvider,
    fee_recipient: Option<Address>,
) -> ValidationRequestBody {
    let base_fee_per_gas = 875000000;
    let start = SystemTime::now();
    let timestamp = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    let gas_limit = 1_000_000;
    let parent_block = add_block(provider.clone(), gas_limit, base_fee_per_gas);
    let parent_block_hash = parent_block.hash_slow();

    let fee_recipient = fee_recipient.unwrap_or(Address::random());

    let proposer_payment = 10_u128.pow(18);

    let (sender_secret_key, sender_address) = generate_random_key();
    provider.add_account(sender_address, ExtendedAccount::new(0, U256::MAX));

    let proposer_payment_transaction = sign_transaction(
        &sender_secret_key,
        Transaction::Eip1559(TxEip1559 {
            chain_id: 1,
            nonce: 0,
            gas_limit: 21000,
            to: TransactionKind::Call(fee_recipient),
            value: proposer_payment,
            input: Bytes::default(),
            max_fee_per_gas: 0x4a817c800,
            max_priority_fee_per_gas: 0x3b9aca00,
            access_list: AccessList::default(),
        }),
    );

    generate_validation_request_body(
        parent_block,
        parent_block_hash,
        fee_recipient,
        timestamp + 10,
        765625000,
        proposer_payment,
        provider.clone(),
        vec![proposer_payment_transaction],
    )
}

fn generate_block(gas_limit: u64, base_fee_per_gas: u64) -> Block {
    let payload = reth_block_validator::rpc::ExecutionPayloadValidation {
        gas_limit,
        base_fee_per_gas: U256::from(base_fee_per_gas),
        block_number: 18469910,
        ..Default::default()
    };
    try_into_block(payload.clone().into(), None).expect("failed to create block")
}

fn generate_validation_request_body(
    parent_block: Block,
    parent_block_hash: FixedBytes<32>,
    fee_recipient: Address,
    timestamp: u64,
    base_fee_per_gas: u64,
    proposer_fee: u128,
    provider: MockEthProvider,
    transactions: Vec<TransactionSigned>,
) -> ValidationRequestBody {
    let mut validation_request_body = ValidationRequestBody::default();
    validation_request_body.execution_payload.fee_recipient = fee_recipient;
    validation_request_body.execution_payload.base_fee_per_gas = U256::from(base_fee_per_gas);
    validation_request_body.execution_payload.timestamp = timestamp;
    validation_request_body.execution_payload.parent_hash = parent_block_hash;
    validation_request_body.execution_payload.block_number = parent_block.header.number + 1;
    validation_request_body.execution_payload.gas_limit = parent_block.gas_limit;
    validation_request_body.message.gas_limit = parent_block.gas_limit;
    validation_request_body.message.parent_hash = parent_block_hash;
    validation_request_body.message.value = U256::from(proposer_fee);

    seal_request_body(add_transactions(
        validation_request_body,
        transactions,
        provider.clone(),
    ))
}

fn add_transactions(
    mut validation_request_body: ValidationRequestBody,
    transactions: Vec<TransactionSigned>,
    provider: MockEthProvider,
) -> ValidationRequestBody {
    let mut encoded_transactions = transactions
        .iter()
        .map(|tx| tx.envelope_encoded())
        .collect();

    validation_request_body
        .execution_payload
        .transactions
        .append(&mut encoded_transactions);
    let block = try_into_block(
        validation_request_body.execution_payload.clone().into(),
        None,
    )
    .expect("failed to create block");
    let (receipts_root, cumulative_gas_used) = calculate_receipts_root(&block, provider);
    validation_request_body.execution_payload.gas_used = cumulative_gas_used;
    validation_request_body.message.gas_used = cumulative_gas_used;
    validation_request_body.execution_payload.receipts_root = receipts_root;
    validation_request_body
}

fn seal_request_body(mut validation_request_body: ValidationRequestBody) -> ValidationRequestBody {
    let block = try_into_block(
        validation_request_body.execution_payload.clone().into(),
        None,
    )
    .expect("failed to create block");
    let sealed_block = block.seal_slow();
    validation_request_body.execution_payload.block_hash = sealed_block.hash();
    validation_request_body.message.block_hash = sealed_block.hash();
    validation_request_body
}
fn calculate_receipts_root(block: &Block, provider: MockEthProvider) -> (B256, u64) {
    let chain_spec = provider.clone().chain_spec;
    let mut executor = EVMProcessor::new_with_db(chain_spec, StateProviderDatabase::new(provider));
    let (receipts, cumulative_gas_used) = executor
        .execute_transactions(block, U256::MAX, None)
        .unwrap();
    let receipts_with_bloom = receipts
        .iter()
        .map(|r| r.clone().into())
        .collect::<Vec<ReceiptWithBloom>>();
    let receipts_root = reth::primitives::proofs::calculate_receipt_root(&receipts_with_bloom);
    (receipts_root, cumulative_gas_used)
}

fn generate_random_key() -> (SecretKey, Address) {
    let secret_key = SecretKey::new(&mut rand::thread_rng());
    let secp = Secp256k1::new();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let hash = keccak256(&public_key.serialize_uncompressed()[1..]);
    let address = Address::from_slice(&hash[12..]);
    (secret_key, address)
}

fn sign_transaction(secret_key: &SecretKey, transaction: Transaction) -> TransactionSigned {
    let tx_signature_hash = transaction.signature_hash();
    let signature = sign_message(B256::from_slice(secret_key.as_ref()), tx_signature_hash).unwrap();
    TransactionSigned::from_transaction_and_signature(transaction, signature)
}
