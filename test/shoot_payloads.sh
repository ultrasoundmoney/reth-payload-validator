#!/bin/bash

# The URL to send the POST requests to
url="http://$1"

# The path to the ndjson file
file_path="$2"

# Read the ndjson file line by line
while read -r line
do
    curl -s -X POST -H "Content-Type: application/json" -d "${line}" ${url}
done < ${file_path}
