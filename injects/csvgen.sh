#!/bin/bash

# Check if at least two arguments are given (1 password + at least 1 hostname)
if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <password> <hostname1> [hostname2] ..."
    exit 1
fi

password="$1"
shift

usernames=("user1" "user2" "user3")

output_file="host_credentials.csv"

for hostname in "$@"; do
    for username in "${usernames[@]}"; do
        echo "${hostname}-ssh2,$username,$password" >> "$output_file"
    done
done

echo "CSV file generated: $output_file"