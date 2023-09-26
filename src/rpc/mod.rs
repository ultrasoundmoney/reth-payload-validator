use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth::transaction_pool::TransactionPool;
use crate::TxpoolExt;

/// trait interface for a custom rpc namespace: `txpool`
///
/// This defines an additional namespace where all methods are configured as trait functions.
#[rpc(server, namespace = "txpoolExt")]
pub trait TxpoolExtApi {
    /// Returns the number of transactions in the pool.
    #[method(name = "transactionCount")]
    fn transaction_count(&self) -> RpcResult<usize>;
}


impl<Pool> TxpoolExtApiServer for TxpoolExt<Pool>
where
    Pool: TransactionPool + Clone + 'static,
{
    fn transaction_count(&self) -> RpcResult<usize> {
        Ok(self.pool.pool_size().total)
    }
}

