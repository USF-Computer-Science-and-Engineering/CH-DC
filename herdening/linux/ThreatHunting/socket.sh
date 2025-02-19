#!/bin/bash

SEEN_CONN_FILE="/tmp/seen_connections.log"
rm -f "$SEEN_CONN_FILE"
touch "$SEEN_CONN_FILE"
chmod 666 "$SEEN_CONN_FILE"

# Open a file descriptor for appending
exec 3>>"$SEEN_CONN_FILE"

while true; do
    ss -ntupe | grep ESTAB | while read -r line; do
        localAddr=$(echo "$line" | awk '{print $5}')
        remoteAddr=$(echo "$line" | awk '{print $6}')
        pid=$(echo "$line" | sed -n 's/.*pid=\([0-9]*\),.*/\1/p')

        if [ ! -d "/proc/$pid" ]; then
            continue
        fi

        path=$(readlink -f /proc/"$pid"/exe 2>/dev/null)
        ppid=$(awk '/^PPid:/ { print $2 }' /proc/"$pid"/status 2>/dev/null)
        pcmd=$(cat /proc/"$ppid"/cmdline 2>/dev/null | tr '\0' ' ' | sed 's/ $//')

        connId="$pid-$localAddr-$remoteAddr"
        
        if ! grep -q "$connId" "$SEEN_CONN_FILE"; then
            echo "PID: $pid - Path: $path - PPID: $ppid - PCMD: \"$pcmd\" - Local: $localAddr - Remote: $remoteAddr"
            echo "$connId" >&3
        fi
    done
    sleep 1 
done
