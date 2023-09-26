# Reth based Block Validator Api
Reth rpc extension to add an endpoint for validation of builder submissions as received by a relay.

## Get Started
Run extended reth full node with the added rpc endpoint with:
`RUST_LOG=info cargo run -- node --full --metrics 127.0.0.1:9001 --http --enable-ext`

## Test it
While there are no automated tests yet you can execute a manual test using the provided testdata:
`curl --location 'localhost:8545/' --header 'Content-Type: application/json' --data @test/data/rpc_payload.json`

## Further Reading
- [Guide to custom api development based on reth](https://www.libevm.com/2023/09/01/reth-custom-api/)
- [Official example for adding rpc namespace](https://github.com/paradigmxyz/reth/blob/main/examples/additional-rpc-namespace-in-cli/src/main.rs)

## Disclaimer
This code is being provided as is. No guarantee, representation or warranty is being made, express or implied, as to the safety or correctness of the code. It has not been audited and as such there can be no assurance it will work as intended, and users may experience delays, failures, errors, omissions or loss of transmitted information.





