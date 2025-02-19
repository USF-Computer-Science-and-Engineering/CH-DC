#!/bin/bash
# Enhanced SUID Binary Auditor and Remover

# Color definitions
RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
CYAN="\033[1;36m"
RESET="\033[0m"

# File names for current and previous scan outputs
OUTPUT_FILE="suid_binaries.txt"
PREV_FILE="suid_binaries_prev.txt"

# List of dangerous/exploitable binary names
dict=(aria2c arp ash base32 base64 basenc bash busybox capsh cat chmod chown chroot column comm cp csh csplit curl cut dash date dd dialog diff dmsetup docker emacs env eqn expand expect find flock fmt fold gdb gimp grep gtester hd head hexdump highlight iconv install ionice ip jjs join jq jrunscript ksh ks ld.so less logsave look lwp-download lwp-request make more mv nano nice nl node nohup od openssl paste perl pg php pico pr python readelf restic rev rlwrap rpm rpmquery rsync run-parts rview rvim sed setarch shuf soelim sort ss ssh-keyscan start-stop-daemon stdbuf strace strings sysctl systemctl tac tail taskset tbl tclsh tee tftp time timeout troff ul unexpand uniq unshare update-alternatives uudecode uuencode view vim watch wget xargs xmodmap xxd xz zsh zsoelim)

echo "==================================="
echo -e "${CYAN} SUIDER - SUID Exploit Finder Tool ${RESET}"
echo "==================================="

while true; do
    echo "[+] Scanning for SUID binaries..."
    # Find SUID binaries (suppressing error messages)
    found_suid=$(find / -perm -u=s -type f 2>/dev/null)
    
    # Write the current scan to the output file
    > "$OUTPUT_FILE"
    for file in $found_suid; do
        # Check if file exists (it might have disappeared)
        if [ -f "$file" ]; then
            hash=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
            echo "$file $hash" >> "$OUTPUT_FILE"
        fi
    done

    # On the first run (no previous scan), display all results.
    if [[ ! -f "$PREV_FILE" ]]; then
        echo -e "${YELLOW}[*] First run: Listing all detected SUID binaries:${RESET}"
        cat "$OUTPUT_FILE"
    fi

    echo '---------------------------------'
    echo " REMOVING SUID BIT FROM DANGEROUS BINARIES"
    echo '---------------------------------'

    # Loop through each found SUID file and remove SUID from dangerous ones.
    for file in $found_suid; do
        bin_name=$(basename "$file")
        if [[ " ${dict[@]} " =~ " ${bin_name} " ]]; then
            echo -e "${RED}[-] Removing SUID from: $file${RESET}"
            sudo chmod -s "$file"
        else
            echo -e "${GREEN}[+] Keeping SUID binary: $file${RESET}"
        fi
    done

    # If a previous scan exists, compare with the current scan
    if [[ -f "$PREV_FILE" ]]; then
        diff_output=$(diff "$PREV_FILE" "$OUTPUT_FILE")
        if [[ -n "$diff_output" ]]; then
            echo -e "${CYAN}[+] Changes detected in SUID binaries:${RESET}"
            echo "$diff_output"
            echo "$diff_output" > suid_changes.txt
        fi
    fi

    # Update the previous scan file with the current scan
    mv "$OUTPUT_FILE" "$PREV_FILE"
    
    echo "[+] Scan complete. Waiting 30 seconds before next scan..."
    sleep 30
done
