echo '{
        "jsonrpc":"2.0",
        "method":"validation_validateBuilderSubmissionV1",
        "params":[],
        "id":1
}' |\
jq --slurpfile payload crates/rpc/rpc-types/test_data/validation/execution_payload.json '.params += $payload'

