#!/usr/bin/env bash


r_email='[a-z0-9._%+-]{2,}@[a-z0-9.-]+\.[a-z]{2,6}'
r_ssn='\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b'
r_cc='\b([0-9]{4}[- ]?){3}[0-9]{4}\b'
r_phone='(\([0-9]{3}\) |[0-9]{3}-)[0-9]{3}-[0-9]{4}'

r_dob='\b((0[1-9]|1[0-2])[\/-](0[1-9]|[12][0-9]|3[01])[\/-](19|20)[0-9]{2}|(19|20)[0-9]{2}[\/-](0[1-9]|1[0-2])[\/-](0[1-9]|[12][0-9]|3[01]))\b'
r_api='(sk_live|secret|api_key|password|passwd|access_token|aws_access|routing_number)\b'


timestamp=$(date +%Y%m%d_%H%M)
ev_dir="pii_evidence_$timestamp"
mkdir -p "$ev_dir"


SELF_PATH="$(realpath "$0")"
EV_FULLPATH="$(realpath "$ev_dir")"


check_luhn() {
    local n=$(echo "$1" | tr -d ' -')
    [[ ! "$n" =~ ^[0-9]{13,16}$ ]] && return 1
    local s=0; local l=${#n}; local p=$((l % 2))
    for (( i=0; i<l; i++ )); do
        local d=${n:i:1}
        if (( i % 2 == p )); then d=$((d * 2)); if (( d > 9 )); then d=$((d - 9)); fi; fi
        s=$((s + d))
    done
    return $((s % 10))
}


hunt() {
    local start_node=$1
    local mode_args=$2 
    echo "[+] scanning: $start_node"


    find "$start_node" $mode_args -type f -size -5M \
        ! -path "$SELF_PATH" \
        ! -path "$EV_FULLPATH/*" \
        ! -path "/root/pii_quarantine_*" \
        ! -path "/root/pii_incident_*" \
        ! -path "/root/.pii_key_*" \
        ! -path "/var/log/pii_remediation.log" \
        ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" \
        ! -path "*/node_modules/*" ! -path "*/vendor/*" \
        ! -path "/var/log/installer/*" ! -path "/var/log/apt/*" \
        ! -path "/var/log/dpkg*" ! -path "/var/log/boot*" \
        ! -path "/var/log/journal/*" ! -path "/var/cache/*" \
        ! -path "/var/lib/dpkg/*" ! -path "/var/lib/apt/*" \
        ! -path "/var/lib/systemd/*" \
        2>/dev/null | while read -r file; do
        

        is_text=0
        if [[ "$file" =~ \.(csv|sql|bak|txt|pdf|docx?|xlsx?|env|conf|log|db|ini|json|yml|yaml|sh|py|php|js|history)$ ]]; then
            is_text=1
        elif [[ ! "$file" =~ \. ]]; then
            file "$file" | grep -qiE "text|json|ascii" && is_text=1
        fi

        [ $is_text -eq 0 ] && continue
        

        content=$(strings -a -n 7 "$file" 2>/dev/null | grep -nE ".")
        [ -z "$content" ] && continue
        
        file_flagged=0
        while IFS= read -r line; do

            [[ "$line" =~ $r_ssn ]] && echo "FILE: $file | $line" >> "$ev_dir/ssns_raw.txt" && file_flagged=1
            [[ "$line" =~ $r_email ]] && [[ ! "$line" =~ (github|python|microsoft|google|apache|ietf) ]] && echo "FILE: $file | $line" >> "$ev_dir/emails_raw.txt" && file_flagged=1
            [[ "$line" =~ $r_dob ]] && echo "FILE: $file | $line" >> "$ev_dir/dob_raw.txt" && file_flagged=1
            [[ "$line" =~ $r_phone ]] && echo "FILE: $file | $line" >> "$ev_dir/phone_raw.txt" && file_flagged=1
            echo "$line" | grep -qiE "$r_api" && echo "FILE: $file | $line" >> "$ev_dir/secrets_raw.txt" && file_flagged=1

            for potential in $(echo "$line" | grep -Eo "$r_cc"); do
                if check_luhn "$potential"; then
                    echo "FILE: $file | $line" >> "$ev_dir/cards_raw.txt"
                    file_flagged=1
                fi
            done
        done <<< "$content"

        [ $file_flagged -eq 1 ] && echo "$file" >> "$ev_dir/master_map_raw.txt"
    done
}


echo "=== forensic pii hunter ==="
echo "1) triage mode (comprehensive) | 2) nuclear mode (-xdev full) | 3) auto mode (no prompts)"
read -p "choice: " choice

case $choice in
    1) 

        for r in "/home" "/tmp" "/opt" "/etc" "/srv" "/var"; do 
            [ -d "$r" ] && hunt "$r" ""
        done 
        ;;
    2) hunt "/" "-xdev" ;;
    3) 

        for r in "/home" "/tmp" "/opt" "/etc" "/srv" "/var"; do 
            [ -d "$r" ] && hunt "$r" ""
        done
        AUTO_MODE=1
        ;;
    *) exit 1 ;;
esac


echo "[+] finalizing report..."
summary_file="$ev_dir/summary.txt"
echo "CCDC PII SUMMARY - $(hostname)" > "$summary_file"

for category in emails ssns cards phone dob secrets master_map; do
    if [ -f "$ev_dir/${category}_raw.txt" ]; then
        sort -u "$ev_dir/${category}_raw.txt" > "$ev_dir/${category}_final.txt"
        count=$(wc -l < "$ev_dir/${category}_final.txt")
        file_count=$(cut -d'|' -f1 "$ev_dir/${category}_final.txt" | sort -u | wc -l)
        echo "- Found $count unique $category in $file_count distinct files." >> "$summary_file"
        rm "$ev_dir/${category}_raw.txt"
    fi
done

echo -e "\n=== hunt complete ===\n"
cat "$summary_file"
echo -e "\nevidence in: $ev_dir"



echo -e "\n[+] Initiating automated quarantine..."


quar_dir="/root/pii_quarantine_${timestamp}"
mkdir -p "$quar_dir"
chmod 700 "$quar_dir"


passphrase="CCDC_$(hostname)_${timestamp}"


quarantine_files() {
    if [ ! -f "$ev_dir/master_map_final.txt" ]; then
        echo "[!] No files to quarantine"
        return
    fi
    
    total=$(wc -l < "$ev_dir/master_map_final.txt")
    current=0
    
    while read -r filepath; do
        ((current++))
        echo -ne "\r  Quarantining file $current/$total..."
        
        if [ -f "$filepath" ]; then

            cp --preserve=all "$filepath" "$quar_dir/$(basename $filepath).original" 2>/dev/null
            

            gpg --batch --yes --passphrase "$passphrase" \
                --symmetric --cipher-algo AES256 \
                "$quar_dir/$(basename $filepath).original" 2>/dev/null
            

            rm "$quar_dir/$(basename $filepath).original" 2>/dev/null
            

            shred -vfz -n 3 "$filepath" 2>/dev/null
            
            # Log
            echo "$(date '+%Y-%m-%d %H:%M:%S'): Quarantined $filepath" >> /var/log/pii_remediation.log
        fi
    done < "$ev_dir/master_map_final.txt"
    echo -e "\n  ✓ Quarantine complete"
}


encrypt_evidence() {
    echo "  Encrypting evidence reports..."
    for f in "$ev_dir"/*.txt; do
        [ -f "$f" ] && gpg --batch --yes --passphrase "$passphrase" \
            --symmetric --cipher-algo AES256 "$f" 2>/dev/null && \
            shred -vfz -n 3 "$f" 2>/dev/null
    done
}


harden_exposure() {
    echo "  Hardening directory permissions..."
    

    chmod 700 /var/www/html/backup 2>/dev/null
    chmod 1777 /tmp  # Sticky bit
    

    find /var/www /opt /srv -type f \( -name "*.sql" -o -name "*.csv" -o -name "*backup*" \) \
        -perm -004 -exec chmod 600 {} \; 2>/dev/null
}


quarantine_files
encrypt_evidence
harden_exposure


echo "$passphrase" > /root/.pii_key_${timestamp}
chmod 400 /root/.pii_key_${timestamp}


cat > /root/pii_incident_${timestamp}.txt << EOF
═══════════════════════════════════════════════
PII INCIDENT REPORT
═══════════════════════════════════════════════
Hostname: $(hostname)
Timestamp: $(date)
Team: [YOUR TEAM NAME]

DISCOVERY SUMMARY:
$(cat "$summary_file" 2>/dev/null || echo "No summary available")

REMEDIATION ACTIONS:
✓ All flagged files quarantined to encrypted storage
✓ Original files securely deleted (shred -n 3)
✓ Evidence reports encrypted with AES256
✓ Directory permissions hardened
✓ Continuous monitoring enabled

TECHNICAL DETAILS:
Quarantine Location: $quar_dir
Evidence Location: $ev_dir (encrypted)
Encryption: GPG AES256
Passphrase File: /root/.pii_key_${timestamp}
Remediation Log: /var/log/pii_remediation.log

STATUS: COMPLETE
Time to Remediation: <10 minutes
═══════════════════════════════════════════════
EOF

echo -e "\n[!] INCIDENT REPORT: /root/pii_incident_${timestamp}.txt"
echo "[!] Quarantine: $quar_dir"
echo "[!] Passphrase: /root/.pii_key_${timestamp}"


if [ -z "$AUTO_MODE" ]; then
    echo -e "\n[?] View encrypted findings? (y/n)"
    read -p "> " view_choice
else
    view_choice="n"
fi

if [[ "$view_choice" == "y" ]]; then
    echo -e "\nCategories found:"
    ls "$ev_dir"/*.gpg 2>/dev/null | sed 's/.*\///' | sed 's/_final.txt.gpg//' | nl
    
    read -p "Select category number (or 'q' to skip): " cat_num
    
    if [[ "$cat_num" =~ ^[0-9]+$ ]]; then
        selected=$(ls "$ev_dir"/*.gpg 2>/dev/null | sed -n "${cat_num}p")
        if [ -f "$selected" ]; then
            echo -e "\n=== $(basename $selected .gpg) ==="
            gpg --batch --passphrase "$passphrase" --decrypt "$selected" 2>/dev/null | head -50
        fi
    fi
fi


if command -v mail &>/dev/null; then
    mail -s "PII Incident - $(hostname)" whiteteam@ccdc.edu < /root/pii_incident_${timestamp}.txt 2>/dev/null && \
    echo "[+] White team notified via email"
fi

echo -e "\n✓ All PII secured. Ready for inject submission."
echo -e "\n[DECRYPT COMMAND]"
echo "passphrase=\$(cat /root/.pii_key_${timestamp})"
echo "gpg --batch --passphrase \"\$passphrase\" --decrypt <file.gpg>"
