use reth::providers::test_utils::NoopProvider;
use reth_block_validator::ValidationApi;
use jsonrpsee::server::ServerBuilder;
use reth_block_validator::rpc::ValidationApiServer;





#[tokio::test(flavor = "multi_thread")]
async fn test_call_admin_functions_ws() {
    start_server().await;
}

async fn start_server() -> std::net::SocketAddr {
    let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
	let addr = server.local_addr().unwrap();
    let provider = NoopProvider::default();
    let api = ValidationApi::new(provider);
	let server_handle = server.start(api.into_rpc());

	tokio::spawn(server_handle.stopped());

    addr
}

// /// Returns an [RpcModuleBuilder] with testing components.
// pub fn test_rpc_builder() -> RpcModuleBuilder<
//     NoopProvider,
//     TestPool,
//     NoopNetwork,
//     TokioTaskExecutor,
//     TestCanonStateSubscriptions,
// > {
//     RpcModuleBuilder::default()
//         .with_provider(NoopProvider::default())
//         .with_pool(testing_pool())
//         .with_network(NoopNetwork::default())
//         .with_executor(TokioTaskExecutor::default())
//         .with_events(TestCanonStateSubscriptions::default())
// }

// /// Launches a new server with http only with the given modules
// pub async fn launch_http(modules: impl Into<RpcModuleSelection>) -> RpcServerHandle {
//     let builder = test_rpc_builder();
//     let server = builder.build(TransportRpcModuleConfig::set_http(modules));
//     server
//         .start_server(RpcServerConfig::http(Default::default()).with_http_address(test_address()))
//         .await
//         .unwrap()
// }


