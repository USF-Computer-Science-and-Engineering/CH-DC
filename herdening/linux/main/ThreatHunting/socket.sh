#!/bin/bash

# Temporary file to track seen connections
SEEN_CONN_FILE="/tmp/seen_connections.log"
> "$SEEN_CONN_FILE" # Clear file contents at start

while true; do
    ss -ntupe | grep ESTAB | while read line; do
        localAddr=$(echo $line | awk '{print $5}')
        remoteAddr=$(echo $line | awk '{print $6}')
        pid=$(echo $line | sed -n 's/.*pid=\([0-9]*\),.*/\1/p')
        path=$(readlink -f /proc/$pid/exe)

        ppid=$(awk '/^PPid:/ { print $2 }' /proc/$pid/status)

        pcmd=$(cat /proc/$ppid/cmdline | tr '\0' ' ' | sed 's/ $//')

        connId="$pid-$localAddr-$remoteAddr"
        
        if ! grep -q $connId "$SEEN_CONN_FILE"; then
            echo "PID: $pid - Path: $path - PPID: $ppid - PCMD: \"$pcmd\" - Local: $localAddr - Remote: $remoteAddr"
            echo $connId >> "$SEEN_CONN_FILE"
        fi
    done
    sleep 1 
done
