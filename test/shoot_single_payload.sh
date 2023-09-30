#!/bin/bash

# The URL to send the POST requests to
url="http://$1"

# The path to the ndjson file
file_path="$2"

echo '{
        "jsonrpc":"2.0",
        "method":"flashbots_validateBuilderSubmissionV2",
        "params":[],
        "id":1
    }' |\
jq --slurpfile payload ${file_path} '.params += $payload' |\
curl -X POST -H "Content-Type: application/json" -d @- "${url}"
