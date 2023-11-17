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
const GAS_LIMIT_BOUND_DIVISOR: u64 = 1024;
const MIN_GAS_LIMIT: u64 = 5000;

// Compute the gas limit of the next block after parent. It aims
// to keep the baseline gas close to the provided target, and increase it towards
// the target if the baseline gas is lower.
// Reference: https://github.com/flashbots/builder/blob/03ee71cf0a344397204f65ff6d3a917ee8e06724/core/utils/gas_limit.go#L8
pub fn calc_gas_limit(parent_gas_limit: u64, desired_limit: u64) -> u64 {
    let delta = parent_gas_limit / GAS_LIMIT_BOUND_DIVISOR - 1;
    let mut limit = parent_gas_limit;
    let desired_limit = std::cmp::max(desired_limit, MIN_GAS_LIMIT);
    if limit < desired_limit {
        limit = parent_gas_limit + delta;
        if limit > desired_limit {
            limit = desired_limit;
        }
        return limit;
    }
    if limit > desired_limit {
        limit = parent_gas_limit - delta;
        if limit < desired_limit {
            limit = desired_limit;
        }
    }
    limit
}
