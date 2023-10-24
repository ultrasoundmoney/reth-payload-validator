use std::sync::Arc;

pub mod cli_ext;
pub use cli_ext::ValidationCliExt;

pub mod rpc;
use rpc::ValidationApiInner;

/// The type that implements the `validation` rpc namespace trait
pub struct ValidationApi<Provider> {
    inner: Arc<ValidationApiInner<Provider>>,
}
