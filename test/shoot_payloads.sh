#!/bin/bash

# The URL to send the POST requests to
url="http://$1"

# The path to the ndjson file
file_path="$2"

# Read the ndjson file line by line
while read -r line
do
    request="{
        "jsonrpc":"2.0",
        "method":"flashbots_validateBuilderSubmissionV2",
        "params":[${line}],
        "id":1
    }";
    curl -X POST -H "Content-Type: application/json" -d "${request}" ${url}
done < ${file_path}
