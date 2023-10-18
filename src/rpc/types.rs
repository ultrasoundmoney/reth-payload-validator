use derivative::Derivative;
use reth::primitives::{Address, Bloom, Bytes, B256, U256, U64};
use reth::rpc::types::{ExecutionPayload, ExecutionPayloadV1, ExecutionPayloadV2, Withdrawal};
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_u64;

/// Structure to deserialize execution payloads sent according to the builder api spec
/// Numeric fields deserialized as decimals (unlike crate::eth::engine::ExecutionPayload)
#[derive(Derivative)]
#[derivative(Debug)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct ExecutionPayloadValidation {
    pub parent_hash: B256,
    pub fee_recipient: Address,
    pub state_root: B256,
    pub receipts_root: B256,
    pub logs_bloom: Bloom,
    pub prev_randao: B256,
    pub block_number: U64,
    pub gas_limit: U64,
    pub gas_used: U64,
    pub timestamp: U64,
    pub extra_data: Bytes,
    pub base_fee_per_gas: U256,
    pub block_hash: B256,
    #[derivative(Debug = "ignore")]
    pub transactions: Vec<Bytes>,
    pub withdrawals: Vec<WithdrawalValidation>,
}

/// Withdrawal object with numbers deserialized as decimals
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalValidation {
    /// Monotonically increasing identifier issued by consensus layer.
    #[serde(deserialize_with = "as_u64")]
    pub index: u64,
    /// Index of validator associated with withdrawal.
    #[serde(deserialize_with = "as_u64")]
    pub validator_index: u64,
    /// Target address for withdrawn ether.
    pub address: Address,
    /// Value of the withdrawal in gwei.
    #[serde(deserialize_with = "as_u64")]
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
                block_number: val.block_number,
                gas_limit: val.gas_limit,
                gas_used: val.gas_used,
                timestamp: val.timestamp,
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
