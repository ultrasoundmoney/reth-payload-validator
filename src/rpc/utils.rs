use crate::rpc::result::internal_rpc_err;
use jsonrpsee::core::RpcResult;

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
pub fn calc_gas_limit(parent_gas_limit: u64, mut desired_limit: u64) -> u64 {
    // TODO: Understand why 1 is subtracted here
    let delta = parent_gas_limit / GAS_LIMIT_BOUND_DIVISOR - 1;
    let mut limit = parent_gas_limit;

    if desired_limit < MIN_GAS_LIMIT {
        desired_limit = MIN_GAS_LIMIT;
    }

    // If we're outside our allowed gas range, we try to hone towards them
    if limit < desired_limit {
        limit = parent_gas_limit + delta;
        if limit > desired_limit {
            limit = desired_limit;
        }
    } else if limit > desired_limit {
        limit = parent_gas_limit - delta;
        if limit < desired_limit {
            limit = desired_limit;
        }
    }

    limit
}
