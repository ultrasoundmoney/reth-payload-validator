use crate::rpc::result::internal_rpc_err;
use jsonrpsee::core::RpcResult;
use std::cmp::Ordering;
use reth_tracing::tracing;

pub fn compare_values<T: std::cmp::PartialEq + std::fmt::Display>(
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

// TODO: Can we avoid hard coding this here and read it from reth config instead ?
// Values as specified in: https://eips.ethereum.org/EIPS/eip-1559#specification
const GAS_LIMIT_BOUND_DIVISOR: u64 = 1024;
const MIN_GAS_LIMIT: u64 = 5000;

// Compute the gas limit of the next block after parent. It aims
// to keep the baseline gas close to the provided target, and increase it towards
// the target if the baseline gas is lower.
// Ported from: https://github.com/flashbots/builder/blob/03ee71cf0a344397204f65ff6d3a917ee8e06724/core/utils/gas_limit.go#L8
// Reference implementation: https://eips.ethereum.org/EIPS/eip-1559#specification
pub fn calc_gas_limit(parent_gas_limit: u64, desired_limit: u64) -> u64 {
    // TODO: Understand why 1 is subtracted here
    let delta = parent_gas_limit / GAS_LIMIT_BOUND_DIVISOR - 1;
    let desired_or_min_limit = std::cmp::max(desired_limit, MIN_GAS_LIMIT);
    match parent_gas_limit.cmp(&desired_or_min_limit) {
        Ordering::Less => {
            let max_acceptable_limit = parent_gas_limit + delta;
            tracing::debug!(
                parent_gas_limit,
                delta,
                desired_limit,
                desired_or_min_limit,
                max_acceptable_limit,
                "Parent gas limit is less than desired/min limit"
            );
            std::cmp::min(max_acceptable_limit, desired_or_min_limit)
        }
        Ordering::Greater => {
            let min_acceptable_limit = parent_gas_limit - delta;
            tracing::debug!(
                parent_gas_limit,
                delta,
                desired_limit,
                desired_or_min_limit,
                min_acceptable_limit,
                "Parent gas limit is greater than desired/min limit"
            );
            std::cmp::max(min_acceptable_limit, desired_or_min_limit)
        }
        Ordering::Equal => {
            tracing::debug!(
                parent_gas_limit,
                delta,
                desired_limit,
                desired_or_min_limit,
                "Parent gas limit is equal to desired/min limit"
            );
            parent_gas_limit
        }
    }
}
