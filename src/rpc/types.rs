use derivative::Derivative;
use reth::primitives::{Address, Bloom, Bytes, H256, U256};
use reth::rpc::types::{ExecutionPayload, ExecutionPayloadV1, ExecutionPayloadV2, Withdrawal};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct ValidationRequestBody {
    pub execution_payload: ExecutionPayloadValidation,
    pub message: BidTrace,
    pub signature: Bytes,
    pub registered_gas_limit: String
}

#[serde_as]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct BidTrace {
    #[serde_as(as = "DisplayFromStr")]
    pub slot: u64,
    pub parent_hash: H256,
    pub block_hash: H256,
    pub builder_pubkey: Bytes,
    pub proposer_pubkey: Bytes,
    pub proposer_fee_recipient: Bytes,
    #[serde_as(as = "DisplayFromStr")]
    pub gas_limit: u64,
    #[serde_as(as = "DisplayFromStr")]
    pub gas_used: u64,
    #[serde_as(as = "DisplayFromStr")]
    pub value: U256,
}

/// Structure to deserialize execution payloads sent according to the builder api spec
/// Numeric fields deserialized as decimals (unlike crate::eth::engine::ExecutionPayload)
#[derive(Derivative)]
#[derivative(Debug)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
#[serde_as]
pub struct ExecutionPayloadValidation {
    pub parent_hash: H256,
    pub fee_recipient: Address,
    pub state_root: H256,
    pub receipts_root: H256,
    pub logs_bloom: Bloom,
    pub prev_randao: H256,
    #[serde_as(as = "DisplayFromStr")]
    pub block_number: u64,
    #[serde_as(as = "DisplayFromStr")]
    pub gas_limit: u64,
    #[serde_as(as = "DisplayFromStr")]
    pub gas_used: u64,
    #[serde_as(as = "DisplayFromStr")]
    pub timestamp: u64,
    pub extra_data: Bytes,
    pub base_fee_per_gas: U256,
    pub block_hash: H256,
    #[derivative(Debug = "ignore")]
    pub transactions: Vec<Bytes>,
    pub withdrawals: Vec<WithdrawalValidation>,
}

/// Withdrawal object with numbers deserialized as decimals
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde_as]
pub struct WithdrawalValidation {
    /// Monotonically increasing identifier issued by consensus layer.
    #[serde_as(as = "DisplayFromStr")]
    pub index: u64,
    /// Index of validator associated with withdrawal.
    #[serde_as(as = "DisplayFromStr")]
    pub validator_index: u64,
    /// Target address for withdrawn ether.
    pub address: Address,
    /// Value of the withdrawal in gwei.
    #[serde_as(as = "DisplayFromStr")]
    pub amount: u64,
}

impl From<ExecutionPayloadValidation> for ExecutionPayload {
    fn from(val: ExecutionPayloadValidation) -> Self {
        ExecutionPayload::V2(ExecutionPayloadV2 {
            payload_inner: ExecutionPayloadV1 {
                parent_hash: val.parent_hash,
                fee_recipient: val.fee_recipient,
                state_root: val.state_root,
                receipts_root: val.receipts_root,
                logs_bloom: val.logs_bloom,
                prev_randao: val.prev_randao,
                block_number: val.block_number.into(),
                gas_limit: val.gas_limit.into(),
                gas_used: val.gas_used.into(),
                timestamp: val.timestamp.into(),
                extra_data: val.extra_data,
                base_fee_per_gas: val.base_fee_per_gas,
                block_hash: val.block_hash,
                transactions: val.transactions,
            },
            withdrawals: val.withdrawals.into_iter().map(|w| w.into()).collect(),
        })
    }
}

impl From<WithdrawalValidation> for Withdrawal {
    fn from(val: WithdrawalValidation) -> Self {
        Withdrawal {
            index: val.index,
            validator_index: val.validator_index,
            address: val.address,
            amount: val.amount,
        }
    }
}
