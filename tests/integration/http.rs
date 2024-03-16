use jsonrpsee::{
    core::error::Error,
    http_client::{HttpClient, HttpClientBuilder},
    server::ServerBuilder,
};
use reth::blockchain_tree::noop::NoopBlockchainTree;
use reth::primitives::{
    keccak256, sign_message,
    stage::{StageCheckpoint, StageId},
    AccessList, Account, Address, Block, Bytes, Header, ReceiptWithBloom, Transaction,
    TransactionKind, TransactionSigned, TxEip1559, B256, GOERLI, U256,
};
use reth::providers::{
    providers::BlockchainProvider, BlockExecutor, ProviderFactory, StateRootProvider,
};
use reth::revm::{database::StateProviderDatabase, processor::EVMProcessor};
use reth::rpc::compat::engine::payload::try_into_block;
use reth_db::test_utils::{create_test_rw_db, TempDatabase};
use reth_db::transaction::{DbTx, DbTxMut};
use reth_db::{tables, DatabaseEnv};
use reth_payload_validator::rpc::{
    ValidationApiClient, ValidationApiServer, ValidationRequestBody,
};
use reth_payload_validator::ValidationApi;
use secp256k1::{rand, PublicKey, Secp256k1, SecretKey};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

type TestProviderFactory = ProviderFactory<Arc<TempDatabase<DatabaseEnv>>>;

#[tokio::test(flavor = "multi_thread")]
async fn test_valid_block() {
    let provider_factory = get_provider_factory();
    let validation_request_body: ValidationRequestBody =
        generate_valid_request(&provider_factory, None);
    let client = get_client(provider_factory).await;

    let result = ValidationApiClient::validate_builder_submission_v3(
        &client,
        validation_request_body.clone(),
    )
    .await;
    assert!(result.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_registered_gas_limit_too_low_block() {
    let provider_factory = get_provider_factory();
    let mut validation_request_body: ValidationRequestBody =
        generate_valid_request(&provider_factory, None);
    let client = get_client(provider_factory).await;

    validation_request_body.registered_gas_limit = 10_000;

    let result = ValidationApiClient::validate_builder_submission_v3(
        &client,
        validation_request_body.clone(),
    )
    .await;
    println!("{:?}", result);
    let error_message = get_call_error_message(result.unwrap_err()).unwrap();
    assert!(error_message.contains("Incorrect gas limit set"));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_invalid_state_root() {
    let provider_factory = get_provider_factory();
    let mut validation_request_body: ValidationRequestBody =
        generate_valid_request(&provider_factory, None);
    let client = get_client(provider_factory).await;
    validation_request_body.execution_payload.state_root = B256::default();
    validation_request_body = seal_request_body(validation_request_body);

    let result = ValidationApiClient::validate_builder_submission_v3(
        &client,
        validation_request_body.clone(),
    )
    .await;
    assert!(result.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_block_number_too_high() {
    let provider_factory = get_provider_factory();
    let mut validation_request_body: ValidationRequestBody =
        generate_valid_request(&provider_factory, None);
    validation_request_body.execution_payload.block_number += 1;
    validation_request_body = seal_request_body(validation_request_body);

    let client = get_client(provider_factory).await;
    let result = ValidationApiClient::validate_builder_submission_v3(
        &client,
        validation_request_body.clone(),
    )
    .await;
    let expected_message = format!(
        "block number {:} does not match parent block number {:}",
        validation_request_body.execution_payload.block_number,
        validation_request_body.execution_payload.block_number - 2
    );
    let error_message = get_call_error_message(result.unwrap_err()).unwrap();
    assert_eq!(error_message, expected_message);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_block_number_already_known() {
    let provider_factory = get_provider_factory();
    let validation_request_body: ValidationRequestBody =
        generate_valid_request(&provider_factory, None);
    let block = try_into_block(
        validation_request_body.execution_payload.clone().into(),
        Some(B256::with_last_byte(0x69)),
    )
    .expect("failed to create block");
    add_block_with_hash(&provider_factory, B256::random(), block);
    // Double check that the header for this number is known
    // assert!(provider
    //     .header_by_number(validation_request_body.execution_payload.block_number)
    //     .unwrap()
    //     .is_some());

    let client = get_client(provider_factory).await;
    let result = ValidationApiClient::validate_builder_submission_v3(
        &client,
        validation_request_body.clone(),
    )
    .await;
    // TODO: Verify that this is expected behaviour (if not check if specific to mock provider)
    assert!(result.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_block_hash_already_known() {
    let provider_factory = get_provider_factory();
    let validation_request_body: ValidationRequestBody =
        generate_valid_request(&provider_factory, None);
    let block = try_into_block(
        validation_request_body.execution_payload.clone().into(),
        Some(B256::with_last_byte(0x69)),
    )
    .expect("failed to create block");
    add_block_with_hash(
        &provider_factory,
        validation_request_body.execution_payload.block_hash,
        block,
    );

    let client = get_client(provider_factory).await;
    let result = ValidationApiClient::validate_builder_submission_v3(
        &client,
        validation_request_body.clone(),
    )
    .await;
    let expected_message = format!(
        "block with [hash={:?}, number={:}] is already known",
        validation_request_body.execution_payload.block_hash,
        validation_request_body.execution_payload.block_number
    );
    let error_message = get_call_error_message(result.unwrap_err()).unwrap();
    assert_eq!(error_message, expected_message);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_incorrect_parent() {
    let provider_factory = get_provider_factory();
    let mut validation_request_body: ValidationRequestBody =
        generate_valid_request(&provider_factory, None);

    let new_parent_hash = B256::random();
    validation_request_body.execution_payload.parent_hash = new_parent_hash;
    validation_request_body.message.parent_hash = new_parent_hash;
    validation_request_body = seal_request_body(validation_request_body);

    let client = get_client(provider_factory).await;
    let result = ValidationApiClient::validate_builder_submission_v3(
        &client,
        validation_request_body.clone(),
    )
    .await;
    let expected_message = format!("Parent block with hash {:?} not found", new_parent_hash);
    let error_message = get_call_error_message(result.unwrap_err()).unwrap();
    assert_eq!(error_message, expected_message);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_tx_nonce_too_low() {
    let provider_factory = get_provider_factory();
    let mut validation_request_body: ValidationRequestBody =
        generate_valid_request(&provider_factory, None);

    let (sender_secret_key, sender_address) = generate_random_key();
    add_account(
        &provider_factory,
        sender_address,
        Account {
            nonce: 0,
            balance: U256::MAX,
            bytecode_hash: None,
        },
    );
    let (_, receiver_address) = generate_random_key();

    let other_transaction = sign_transaction(
        &sender_secret_key,
        Transaction::Eip1559(TxEip1559 {
            chain_id: 5,
            nonce: 0, // Invalid Tx because nonce is too low
            gas_limit: 21000,
            to: TransactionKind::Call(receiver_address),
            value: 1_000_000_u128.into(),
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
        &provider_factory,
    ));

    add_account(
        &provider_factory,
        sender_address,
        Account {
            nonce: 1,
            balance: U256::MAX,
            bytecode_hash: None,
        },
    );

    let client = get_client(provider_factory).await;
    let result = ValidationApiClient::validate_builder_submission_v3(
        &client,
        validation_request_body.clone(),
    )
    .await;
    let expected_error_message = "transaction nonce is not consistent";
    let error_message = get_call_error_message(result.unwrap_err()).unwrap();
    assert_eq!(error_message, expected_error_message);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_proposer_payment_validation_via_balance_change() {
    let provider_factory = get_provider_factory();
    let mut validation_request_body: ValidationRequestBody =
        generate_valid_request(&provider_factory, None);

    let (sender_secret_key, sender_address) = generate_random_key();
    add_account(
        &provider_factory,
        sender_address,
        Account {
            nonce: 0,
            balance: U256::MAX,
            bytecode_hash: None,
        },
    );
    let (_, receiver_address) = generate_random_key();

    let other_transaction = sign_transaction(
        &sender_secret_key,
        Transaction::Eip1559(TxEip1559 {
            chain_id: 5,
            nonce: 0,
            gas_limit: 21000,
            to: TransactionKind::Call(receiver_address),
            value: 1_000_000_u128.into(),
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
        &provider_factory,
    ));
    let client = get_client(provider_factory).await;
    let result = ValidationApiClient::validate_builder_submission_v3(
        &client,
        validation_request_body.clone(),
    )
    .await;
    assert!(result.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_proposer_spent_in_same_block() {
    let provider_factory = get_provider_factory();
    let (recipient_private_key, recipient_address) = generate_random_key();
    let mut validation_request_body: ValidationRequestBody =
        generate_valid_request(&provider_factory, Some(recipient_address));
    // Note: This is not necessary for this test but added here to make it otherwise identical to
    // the passing case with the reordered transactions
    add_account(
        &provider_factory,
        recipient_address,
        Account {
            nonce: 0,
            balance: validation_request_body.message.value,
            bytecode_hash: None,
        },
    );

    let (sender_secret_key, sender_address) = generate_random_key();
    add_account(
        &provider_factory,
        sender_address,
        Account {
            nonce: 0,
            balance: U256::MAX,
            bytecode_hash: None,
        },
    );
    let (_, receiver_address) = generate_random_key();

    let amount_to_send = validation_request_body.message.value / U256::from(2);
    let spend_proposer_payment_tx = sign_transaction(
        &recipient_private_key,
        Transaction::Eip1559(TxEip1559 {
            chain_id: 5,
            nonce: 0,
            gas_limit: 21000,
            to: TransactionKind::Call(receiver_address),
            value: amount_to_send.into(),
            input: Bytes::default(),
            max_fee_per_gas: 0x4a817c800,
            max_priority_fee_per_gas: 0x3b9aca00,
            access_list: AccessList::default(),
        }),
    );

    let other_transaction = sign_transaction(
        &sender_secret_key,
        Transaction::Eip1559(TxEip1559 {
            chain_id: 5,
            nonce: 0,
            gas_limit: 21000,
            to: TransactionKind::Call(receiver_address),
            value: 1_000_000_u128.into(),
            input: Bytes::default(),
            max_fee_per_gas: 0x4a817c800,
            max_priority_fee_per_gas: 0x3b9aca00,
            access_list: AccessList::default(),
        }),
    );

    validation_request_body = seal_request_body(add_transactions(
        validation_request_body,
        vec![spend_proposer_payment_tx, other_transaction],
        &provider_factory,
    ));

    let client = get_client(provider_factory).await;
    let result = ValidationApiClient::validate_builder_submission_v3(
        &client,
        validation_request_body.clone(),
    )
    .await;
    println!("result {:?}", result);
    let error_message = get_call_error_message(result.unwrap_err()).unwrap();
    // Because the check based on the balance difference failed it will revert to checking the last
    // transaction and find that it is not going to the fee recipient
    assert!(error_message.contains("does not match fee recipient"));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_proposer_spent_in_same_block_but_payment_tx_last() {
    let provider_factory = get_provider_factory();
    let (recipient_private_key, recipient_address) = generate_random_key();
    let mut validation_request_body: ValidationRequestBody =
        generate_valid_request(&provider_factory, Some(recipient_address));
    add_account(
        &provider_factory,
        recipient_address,
        Account {
            nonce: 0,
            balance: validation_request_body.message.value,
            bytecode_hash: None,
        },
    );

    let (sender_secret_key, sender_address) = generate_random_key();
    add_account(
        &provider_factory,
        sender_address,
        Account {
            nonce: 0,
            balance: U256::MAX,
            bytecode_hash: None,
        },
    );
    let (_, receiver_address) = generate_random_key();

    let amount_to_send = validation_request_body.message.value / U256::from(2);
    let spend_proposer_payment_tx = sign_transaction(
        &recipient_private_key,
        Transaction::Eip1559(TxEip1559 {
            chain_id: 5,
            nonce: 0,
            gas_limit: 21000,
            to: TransactionKind::Call(receiver_address),
            value: amount_to_send.into(),
            input: Bytes::default(),
            max_fee_per_gas: 0x4a817c800,
            max_priority_fee_per_gas: 0x3b9aca00,
            access_list: AccessList::default(),
        }),
    );

    let other_transaction = sign_transaction(
        &sender_secret_key,
        Transaction::Eip1559(TxEip1559 {
            chain_id: 5,
            nonce: 0,
            gas_limit: 21000,
            to: TransactionKind::Call(receiver_address),
            value: 1_000_000_u128.into(),
            input: Bytes::default(),
            max_fee_per_gas: 0x4a817c800,
            max_priority_fee_per_gas: 0x3b9aca00,
            access_list: AccessList::default(),
        }),
    );

    validation_request_body = add_transactions(
        validation_request_body,
        vec![spend_proposer_payment_tx, other_transaction],
        &provider_factory,
    );
    // Note that this reordering makes the payload verifiable by putting the proposer paymnent last
    validation_request_body.execution_payload.transactions = vec![
        validation_request_body.execution_payload.transactions[1].clone(),
        validation_request_body.execution_payload.transactions[2].clone(),
        validation_request_body.execution_payload.transactions[0].clone(),
    ];
    validation_request_body = seal_request_body(validation_request_body);

    let client = get_client(provider_factory).await;
    let result = ValidationApiClient::validate_builder_submission_v3(
        &client,
        validation_request_body.clone(),
    )
    .await;
    assert!(result.is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_insufficient_proposer_payment() {
    let provider_factory = get_provider_factory();
    let mut validation_request_body: ValidationRequestBody =
        generate_valid_request(&provider_factory, None);
    let original_proposer_payment = validation_request_body.message.value;
    let new_proposer_payment = original_proposer_payment + original_proposer_payment;
    validation_request_body.message.value = new_proposer_payment;
    let validation_request_body = seal_request_body(validation_request_body);

    let client = get_client(provider_factory).await;

    let result = ValidationApiClient::validate_builder_submission_v3(
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
    let provider_factory = get_provider_factory();
    let mut validation_request_body: ValidationRequestBody =
        generate_valid_request(&provider_factory, None);
    validation_request_body.execution_payload.timestamp += 1;

    let client = get_client(provider_factory).await;
    let result =
        ValidationApiClient::validate_builder_submission_v3(&client, validation_request_body).await;
    let error_message = get_call_error_message(result.unwrap_err()).unwrap();
    assert!(error_message.contains("block hash mismatch"));
}

async fn get_client(provider_factory: TestProviderFactory) -> HttpClient {
    let server_addr = start_server(provider_factory).await;
    let uri = format!("http://{}", server_addr);
    HttpClientBuilder::default().build(uri).unwrap()
}

async fn start_server(provider_factory: TestProviderFactory) -> std::net::SocketAddr {
    let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    let provider =
        BlockchainProvider::new(provider_factory, NoopBlockchainTree::default()).unwrap();
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

fn add_block(
    provider_factory: &TestProviderFactory,
    gas_limit: u64,
    base_fee_per_gas: u64,
) -> Block {
    let block = generate_block(gas_limit, base_fee_per_gas);
    let block_hash = block.header.hash_slow();
    add_block_with_hash(provider_factory, block_hash, block.clone());
    block
}

fn generate_valid_request(
    provider_factory: &TestProviderFactory,
    fee_recipient: Option<Address>,
) -> ValidationRequestBody {
    let base_fee_per_gas = 875000000;
    let start = SystemTime::now();
    let timestamp = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    let gas_limit = 1_000_000;
    let parent_block = add_block(provider_factory, gas_limit, base_fee_per_gas);

    let fee_recipient = fee_recipient.unwrap_or(Address::random());

    let proposer_payment = 10_u128.pow(18);

    let (sender_secret_key, sender_address) = generate_random_key();
    add_account(
        provider_factory,
        sender_address,
        Account {
            nonce: 0,
            balance: U256::MAX,
            bytecode_hash: None,
        },
    );

    let proposer_payment_transaction = sign_transaction(
        &sender_secret_key,
        Transaction::Eip1559(TxEip1559 {
            chain_id: 5,
            nonce: 0,
            gas_limit: 21000,
            to: TransactionKind::Call(fee_recipient),
            value: proposer_payment.into(),
            input: Bytes::default(),
            max_fee_per_gas: 0x4a817c800,
            max_priority_fee_per_gas: 0x3b9aca00,
            access_list: AccessList::default(),
        }),
    );

    generate_validation_request_body(
        parent_block,
        fee_recipient,
        timestamp + 10,
        765625000,
        proposer_payment,
        provider_factory,
        vec![proposer_payment_transaction],
    )
}

fn generate_block(gas_limit: u64, base_fee_per_gas: u64) -> Block {
    let payload = reth_payload_validator::rpc::ExecutionPayloadValidation {
        gas_limit,
        base_fee_per_gas: U256::from(base_fee_per_gas),
        block_number: 19447300,
        ..Default::default()
    };
    try_into_block(payload.clone().into(), Some(B256::with_last_byte(0x69)))
        .expect("failed to create block")
}

fn generate_validation_request_body(
    parent_block: Block,
    fee_recipient: Address,
    timestamp: u64,
    base_fee_per_gas: u64,
    proposer_fee: u128,
    provider_factory: &TestProviderFactory,
    transactions: Vec<TransactionSigned>,
) -> ValidationRequestBody {
    let parent_block_hash = parent_block.hash_slow();
    let mut validation_request_body = ValidationRequestBody::default();
    validation_request_body.execution_payload.base_fee_per_gas = U256::from(base_fee_per_gas);
    validation_request_body.execution_payload.timestamp = timestamp;
    validation_request_body.execution_payload.parent_hash = parent_block_hash;
    validation_request_body.execution_payload.block_number = parent_block.header.number + 1;
    validation_request_body.execution_payload.gas_limit = parent_block.gas_limit;
    validation_request_body.message.gas_limit = parent_block.gas_limit;
    validation_request_body.message.parent_hash = parent_block_hash;
    validation_request_body.message.value = U256::from(proposer_fee);
    validation_request_body.message.proposer_fee_recipient = fee_recipient;
    validation_request_body.registered_gas_limit = 1_000_000;
    validation_request_body.parent_beacon_block_root = Some(B256::with_last_byte(0x69));

    seal_request_body(add_transactions(
        validation_request_body,
        transactions,
        provider_factory,
    ))
}

fn add_transactions(
    mut validation_request_body: ValidationRequestBody,
    transactions: Vec<TransactionSigned>,
    provider_factory: &TestProviderFactory,
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
        Some(B256::with_last_byte(0x69)),
    )
    .expect("failed to create block");
    let (receipts_root, cumulative_gas_used, state_root) =
        calculate_receipts_root(&block, provider_factory);
    validation_request_body.execution_payload.gas_used = cumulative_gas_used;
    validation_request_body.message.gas_used = cumulative_gas_used;
    validation_request_body.execution_payload.receipts_root = receipts_root;
    validation_request_body.execution_payload.state_root = state_root;
    validation_request_body
}

fn seal_request_body(mut validation_request_body: ValidationRequestBody) -> ValidationRequestBody {
    let block = try_into_block(
        validation_request_body.execution_payload.clone().into(),
        Some(B256::with_last_byte(0x69)),
    )
    .expect("failed to create block");
    let sealed_block = block.seal_slow();
    validation_request_body.execution_payload.block_hash = sealed_block.hash();
    validation_request_body.message.block_hash = sealed_block.hash();
    validation_request_body
}
fn calculate_receipts_root(
    block: &Block,
    provider_factory: &TestProviderFactory,
) -> (B256, u64, B256) {
    let chain_spec = GOERLI.clone();
    let state_provider_db = StateProviderDatabase::new(provider_factory.latest().unwrap());

    let mut executor = EVMProcessor::new_with_db(chain_spec.clone(), state_provider_db);
    let block_with_senders = block
        .clone()
        .with_recovered_senders()
        .expect("failed to recover senders");
    let (receipts, cumulative_gas_used) = executor
        .execute_transactions(&block_with_senders, U256::MAX)
        .unwrap();
    let receipts_with_bloom = receipts
        .iter()
        .map(|r| r.clone().into())
        .collect::<Vec<ReceiptWithBloom>>();
    let receipts_root = reth::primitives::proofs::calculate_receipt_root(&receipts_with_bloom);

    let new_block = Block {
        header: Header {
            gas_used: cumulative_gas_used,
            receipts_root,
            ..block.header.clone()
        },
        ..block.clone()
    }
    .with_recovered_senders()
    .expect("failed to recover senders");

    let state_provider_db = StateProviderDatabase::new(provider_factory.latest().unwrap());
    let mut block_executor = EVMProcessor::new_with_db(chain_spec.clone(), state_provider_db);
    block_executor
        .execute_and_verify_receipt(&new_block, U256::MAX)
        .unwrap();
    let state = block_executor.take_output_state();

    let state_root = provider_factory
        .latest()
        .unwrap()
        .state_root(&state)
        .expect("failed to get state root");
    (receipts_root, cumulative_gas_used, state_root)
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

fn get_provider_factory() -> TestProviderFactory {
    let db = create_test_rw_db();
    ProviderFactory::new(db, GOERLI.clone())
}

fn add_account(provider_factory: &TestProviderFactory, address: Address, account: Account) {
    let hashed_address = keccak256(address);
    let provider = provider_factory.provider_rw().unwrap();
    let tx = provider.into_tx();
    tx.put::<tables::HashedAccount>(hashed_address, account)
        .unwrap();
    tx.commit().unwrap();

    let provider = provider_factory.provider_rw().unwrap();
    let tx = provider.into_tx();
    tx.put::<tables::PlainAccountState>(address, account)
        .unwrap();
    tx.commit().unwrap();
}

fn add_block_with_hash(provider_factory: &TestProviderFactory, hash: B256, block: Block) {
    let header = block.header.clone();
    let provider = provider_factory.provider_rw().unwrap();
    let tx = provider.into_tx();
    tx.put::<tables::Headers>(header.number, header.clone())
        .unwrap();
    tx.put::<tables::CanonicalHeaders>(header.clone().number, hash)
        .unwrap();
    tx.put::<tables::HeaderTD>(header.number, U256::MAX.into())
        .unwrap();
    tx.put::<tables::HeaderNumbers>(hash, header.number)
        .unwrap();
    tx.put::<tables::SyncStage>(
        StageId::Finish.to_string(),
        StageCheckpoint {
            block_number: header.number,
            stage_checkpoint: None,
        },
    )
    .unwrap();
    tx.commit().unwrap();
}
