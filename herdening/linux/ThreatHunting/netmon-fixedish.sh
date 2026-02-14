#!/usr/bin/env bash

set -o pipefail

# ============================================================================
# SECURE TEMP DIRECTORY - prevent symlink attacks
# ============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURE_TMP_DIR="/tmp/.netmon_${UID}_$$"
mkdir -p "$SECURE_TMP_DIR" 2>/dev/null
chmod 700 "$SECURE_TMP_DIR"

# Verify the directory is actually owned by us and not a symlink
if [[ -L "$SECURE_TMP_DIR" ]] || [[ "$(stat -c '%u' "$SECURE_TMP_DIR" 2>/dev/null)" != "$UID" ]]; then
    echo "SECURITY: tmp directory compromised, aborting."
    exit 1
fi

# --- Config ---
LOG_FILE="${SCRIPT_DIR}/network_complete.log"
BASELINE_FILE="${SCRIPT_DIR}/network_baseline.dat"
BUFFER_FILE="${SECURE_TMP_DIR}/buffer.tmp"
LOCK_FILE="${HOME}/.netmon.lock"
CACHE_FILE="${SECURE_TMP_DIR}/cache.tmp"
EXCLUDE_FILE="${SECURE_TMP_DIR}/exclude.txt"
CONFIG_FILE="${HOME}/.netmon_config"
ALERT_FILE="${SCRIPT_DIR}/security_alerts.log"
SS_CACHE_FILE="${SECURE_TMP_DIR}/ss_cache.tmp"
PRIV_CACHE_FILE="${SECURE_TMP_DIR}/priv_cache.tmp"
RAW_EVENTS_FILE="${SECURE_TMP_DIR}/raw_events.tmp"

# PIDs of background processes we start (for targeted cleanup)
TCPDUMP_PID=""
BASELINE_PID=""
CACHE_BUILDER_PID=""
PROC_MONITOR_PID=""
BUFFER_TRIM_PID=""
SS_REFRESH_PID=""
PRIV_CACHE_PID=""
AGG_PID=""

# ============================================================================
# SAFE CONFIG LOADING - no arbitrary code execution
# ============================================================================
COLOR_ENABLED=1
if [[ -f "$CONFIG_FILE" ]]; then
    # Parse config safely - only accept known key=value pairs
    while IFS='=' read -r key value; do
        key=$(echo "$key" | tr -d '[:space:]')
        value=$(echo "$value" | tr -d '[:space:]')
        case "$key" in
            COLOR_ENABLED)
                if [[ "$value" =~ ^[01]$ ]]; then
                    COLOR_ENABLED="$value"
                fi
                ;;
            # Add other safe config keys here
        esac
    done < "$CONFIG_FILE"
else
    echo "COLOR_ENABLED=1" > "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"
fi

# ============================================================================
# COLOR SETUP (as function so toggle works)
# ============================================================================
set_colors() {
    if [[ "$COLOR_ENABLED" -eq 1 ]]; then
        RED='\033[0;31m'
        YELLOW='\033[1;33m'
        NC='\033[0m'
        BLUE='\033[0;34m'
        GREEN='\033[0;32m'
        CYAN='\033[0;36m'
        MAGENTA='\033[0;35m'
        BOLD='\033[1m'
    else
        RED='' YELLOW='' NC='' BLUE='' GREEN='' CYAN='' MAGENTA='' BOLD=''
    fi
}
set_colors

# ============================================================================
# EARLY FLAG HANDLING - before lock so these work while netmon is running
# ============================================================================
if [[ "${1:-}" == "--save-hashes" ]]; then
    HASH_FILE="${HOME}/.netmon_hashes"
    CRITICAL_BINS=(tcpdump ss awk grep sudo)
    echo "# netmon binary hashes - generated $(date)" > "$HASH_FILE"
    for b in "${CRITICAL_BINS[@]}"; do
        bpath=$(command -v "$b" 2>/dev/null)
        if [[ -n "$bpath" && -f "$bpath" ]]; then
            sha256sum "$bpath" >> "$HASH_FILE"
        fi
    done
    chmod 600 "$HASH_FILE"
    echo "Saved hashes for ${#CRITICAL_BINS[@]} binaries to $HASH_FILE"
    exit 0
fi

# ============================================================================
# SINGLETON CHECK - use flock for race-free locking
# ============================================================================
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    echo "Already running (locked)."
    exit 1
fi
# Lock is held by fd 9 until process exits

# ============================================================================
# THREAT DETECTION - defined early so all subshells inherit it
# ============================================================================
detect_threats() {
    local bin="$1"
    local cmd="$2"
    local dst="$3"
    local proto="$4"
    local user="$5"

    local threat=""
    local severity=""

    # PANIX backdoor detection
    if [[ "$bin" =~ panix|rebound ]] || [[ "$cmd" =~ panix|rebound ]]; then
        threat="PANIX_BACKDOOR"
        severity="CRITICAL"
    fi

    # Sliver C2 detection (also catch renamed binaries with sliver-like behavior)
    if [[ "$bin" =~ sliver ]] || [[ "$cmd" =~ sliver.*implant|sliver.*beacon ]]; then
        threat="SLIVER_C2"
        severity="CRITICAL"
    fi

    # Reverse shell patterns - expanded coverage
    if [[ "$cmd" =~ bash.*-i|sh.*-i|nc.*-e|ncat.*-e|/dev/tcp|/dev/udp ]]; then
        threat="REVERSE_SHELL"
        severity="CRITICAL"
    elif [[ "$cmd" =~ python.*socket.*connect|python.*pty\.spawn|perl.*socket|ruby.*TCPSocket ]]; then
        threat="REVERSE_SHELL"
        severity="CRITICAL"
    elif [[ "$cmd" =~ socat.*exec|socat.*pty|socat.*TCP ]]; then
        threat="REVERSE_SHELL"
        severity="CRITICAL"
    fi

    # Suspicious encodings / obfuscation
    if [[ "$cmd" =~ base64.*-d|echo.*\|.*bash|eval.*\$|python.*-c.*exec|perl.*-e ]]; then
        threat="ENCODED_EXECUTION"
        severity="HIGH"
    fi

    # ICMP tunneling detection - check the ACTUAL process command, not system-wide pgrep
    if [[ "$proto" == "ICMP" ]]; then
        # -p flag = custom payload pattern (data exfil), -s 500+ = oversized payload
        if [[ "$cmd" =~ ping.*-p[[:space:]] ]] || [[ "$cmd" =~ ping.*-s[[:space:]]+([5-9][0-9][0-9]|[0-9]{4,}) ]]; then
            threat="ICMP_TUNNEL"
            severity="HIGH"
        elif [[ "$bin" =~ ^(hping|hping3)$ ]]; then
            threat="ICMP_TUNNEL"
            severity="HIGH"
        fi
    fi

    # DNS tunneling - very long hex subdomains over UDP/53
    if [[ "$dst" =~ [0-9a-f]{30,} ]] && [[ "$proto" == "UDP" ]]; then
        threat="DNS_TUNNEL"
        severity="HIGH"
    fi

    # Port scanning tools
    if [[ "$bin" =~ nmap|masscan|zmap|rustscan ]]; then
        threat="PORT_SCAN"
        severity="MEDIUM"
    fi

    # Data exfiltration indicators
    if [[ "$cmd" =~ curl.*-T|curl.*--upload|wget.*--post|scp.*@ ]]; then
        threat="DATA_EXFIL"
        severity="HIGH"
    fi

    # Tor/VPN detection
    if [[ "$bin" =~ ^tor$|^openvpn$|^wireguard$ ]]; then
        threat="ANONYMIZATION"
        severity="LOW"
    fi

    # Cryptominer indicators
    if [[ "$cmd" =~ stratum|xmrig|minerd|cryptonight ]]; then
        threat="CRYPTOMINER"
        severity="HIGH"
    fi

    # SSH tunneling
    if [[ "$cmd" =~ ssh.*-L|ssh.*-R|ssh.*-D|ssh.*-w ]]; then
        threat="SSH_TUNNEL"
        severity="MEDIUM"
    fi

    echo "$threat|$severity"
}

# ============================================================================
# CLEANUP - targeted, safe shutdown
# ============================================================================
cleanup() {
    echo -e "\n${YELLOW}Shutting down...${NC}"

    # Remove audit rules if we added them
    if command -v auditctl &>/dev/null; then
        sudo auditctl -d exit,always -F arch=b64 -S execve -F exe=/usr/bin/curl -k curl_exec 2>/dev/null
        sudo auditctl -d exit,always -F arch=b64 -S execve -F exe=/usr/bin/wget -k wget_exec 2>/dev/null
        sudo auditctl -d exit,always -F arch=b64 -S execve -F exe=/usr/bin/ping -k ping_exec 2>/dev/null
    fi

    # Kill only OUR background processes by stored PID
    for bg_pid in "$TCPDUMP_PID" "$BASELINE_PID" "$CACHE_BUILDER_PID" "$PROC_MONITOR_PID" "$BUFFER_TRIM_PID" "$SS_REFRESH_PID" "$PRIV_CACHE_PID" "$AGG_PID"; do
        if [[ -n "$bg_pid" ]] && kill -0 "$bg_pid" 2>/dev/null; then
            kill "$bg_pid" 2>/dev/null
            wait "$bg_pid" 2>/dev/null
        fi
    done

    # Kill our specific tcpdump (find it as child of our subshell)
    if [[ -n "$TCPDUMP_PID" ]]; then
        for cpid in $(pgrep -P "$TCPDUMP_PID" 2>/dev/null); do
            sudo kill "$cpid" 2>/dev/null
        done
    fi

    # Kill remaining children
    pkill -P $$ 2>/dev/null
    sleep 1

    # Clean up temp directory
    rm -rf "$SECURE_TMP_DIR" 2>/dev/null
    rm -f "$LOCK_FILE" 2>/dev/null

    # Restore terminal
    stty echo 2>/dev/null
    tput cnorm 2>/dev/null

    echo -e "${GREEN}Shutdown complete. Logs: $LOG_FILE${NC}"
    echo -e "${GREEN}Alerts: $ALERT_FILE${NC}"
    exit 0
}

trap cleanup INT TERM EXIT

# ============================================================================
# DEPENDENCY CHECK
# ============================================================================
for dep in lsof ps grep awk tail sudo ss; do
    if ! command -v "$dep" &>/dev/null; then
        echo "Missing: $dep"
        exit 1
    fi
done

# Install tcpdump if missing
if ! command -v tcpdump &>/dev/null; then
    echo "Installing tcpdump..."
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq && sudo apt-get install -y -qq tcpdump
    elif command -v yum &>/dev/null; then
        sudo yum install -y -q tcpdump
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y -q tcpdump
    fi
    if ! command -v tcpdump &>/dev/null; then
        echo "FATAL: Could not install tcpdump"
        exit 1
    fi
fi

# ============================================================================
# BINARY INTEGRITY CHECK - detect trojanized tools
# ============================================================================
HASH_FILE="${HOME}/.netmon_hashes"
CRITICAL_BINS=(tcpdump ss awk grep sudo)

save_binary_hashes() {
    echo "# netmon binary hashes - generated $(date)" > "$HASH_FILE"
    for b in "${CRITICAL_BINS[@]}"; do
        local bpath
        bpath=$(command -v "$b" 2>/dev/null)
        if [[ -n "$bpath" && -f "$bpath" ]]; then
            sha256sum "$bpath" >> "$HASH_FILE"
        fi
    done
    chmod 600 "$HASH_FILE"
    echo -e "${GREEN}Saved hashes for ${#CRITICAL_BINS[@]} binaries to $HASH_FILE${NC}"
}

verify_binary_hashes() {
    if [[ ! -f "$HASH_FILE" ]]; then
        echo -e "${YELLOW}  [WARN] No baseline hashes found. Saving current hashes.${NC}"
        echo -e "${YELLOW}         Run on a KNOWN CLEAN system for this to be useful.${NC}"
        save_binary_hashes
        return 0
    fi

    local tampered=0
    for b in "${CRITICAL_BINS[@]}"; do
        local bpath
        bpath=$(command -v "$b" 2>/dev/null)
        if [[ -n "$bpath" && -f "$bpath" ]]; then
            local current_hash saved_hash
            current_hash=$(sha256sum "$bpath" 2>/dev/null | awk '{print $1}')
            saved_hash=$(grep "$bpath" "$HASH_FILE" 2>/dev/null | awk '{print $1}')
            if [[ -n "$saved_hash" && "$current_hash" != "$saved_hash" ]]; then
                echo -e "  ${RED}[TAMPERED] $bpath hash mismatch!${NC}"
                echo -e "  ${RED}  Expected: ${saved_hash:0:16}...${NC}"
                echo -e "  ${RED}  Current:  ${current_hash:0:16}...${NC}"
                tampered=$((tampered + 1))
            fi
        fi
    done

    if [[ "$tampered" -gt 0 ]]; then
        echo -e "  ${RED}${BOLD}WARNING: $tampered critical binary(ies) have been modified!${NC}"
        echo -e "  ${RED}Red team may have replaced tools to hide activity.${NC}"
        echo -e "  ${YELLOW}Verify with: rpm -V coreutils iproute2  or  dpkg --verify${NC}"
        echo
        read -p "  Continue anyway? (y/N) " confirm
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            echo "Aborting."
            exit 1
        fi
    else
        echo -e "${GREEN}  [OK] All critical binaries match saved hashes${NC}"
    fi
}

verify_binary_hashes

# ============================================================================
# PREFLIGHT: Verify sudo, tcpdump, and capture capability
# ============================================================================
TCPDUMP_ERR_LOG="${SECURE_TMP_DIR}/tcpdump_errors.log"
touch "$TCPDUMP_ERR_LOG"

echo -e "${YELLOW}Running preflight checks...${NC}"

# 1. Verify sudo access
if ! sudo -n true 2>/dev/null; then
    echo -e "${YELLOW}Sudo requires a password. Enter it now to cache credentials:${NC}"
    if ! sudo true; then
        echo -e "${RED}FATAL: Cannot obtain sudo access. Run with sudo or fix sudoers.${NC}"
        exit 1
    fi
fi
echo -e "${GREEN}  [OK] sudo access${NC}"

# 2. Detect best capture interface
# Older tcpdump on CentOS/RHEL may not support '-i any'
CAPTURE_IFACE="any"
if ! sudo timeout 2 tcpdump -i any -nn -c 1 -w /dev/null 2>/dev/null; then
    # Fallback: find the default interface
    CAPTURE_IFACE=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
    if [[ -z "$CAPTURE_IFACE" ]]; then
        CAPTURE_IFACE=$(route -n 2>/dev/null | awk '/^0\.0\.0\.0/{print $NF; exit}')
    fi
    if [[ -z "$CAPTURE_IFACE" ]]; then
        echo -e "${RED}FATAL: Cannot determine network interface${NC}"
        exit 1
    fi
    echo -e "${YELLOW}  [WARN] tcpdump -i any not supported, using interface: $CAPTURE_IFACE${NC}"
else
    echo -e "${GREEN}  [OK] tcpdump capture (interface: any)${NC}"
fi

# 3. Quick capture test - verify we actually get packets
echo -n "  Testing live capture..."
test_output=$(sudo timeout 3 tcpdump -i "$CAPTURE_IFACE" -nn -c 1 -l 2>"$TCPDUMP_ERR_LOG")
if [[ $? -ne 0 ]] && [[ -z "$test_output" ]]; then
    echo -e " ${YELLOW}[WARN] No packets captured in 3s test${NC}"
    if [[ -s "$TCPDUMP_ERR_LOG" ]]; then
        echo -e "  ${RED}tcpdump errors:${NC}"
        head -3 "$TCPDUMP_ERR_LOG" | sed 's/^/    /'
    fi
    # Check common CentOS issues
    if command -v getenforce &>/dev/null && [[ "$(getenforce 2>/dev/null)" == "Enforcing" ]]; then
        echo -e "  ${YELLOW}SELinux is Enforcing - this may block tcpdump${NC}"
        echo -e "  ${YELLOW}Try: sudo setenforce 0  (temporary) or add a tcpdump SELinux policy${NC}"
    fi
    if ! sudo getcap "$(command -v tcpdump)" 2>/dev/null | grep -q cap_net_raw; then
        echo -e "  ${YELLOW}tcpdump may lack cap_net_raw capability${NC}"
        echo -e "  ${YELLOW}Try: sudo setcap cap_net_raw+eip $(command -v tcpdump)${NC}"
    fi
    echo -e "  ${YELLOW}Continuing anyway - capture may work for outbound traffic...${NC}"
else
    echo -e " ${GREEN}[OK]${NC}"
fi

# 4. Check if stdbuf is available (helps with pipe buffering on CentOS)
USE_STDBUF=0
if command -v stdbuf &>/dev/null; then
    USE_STDBUF=1
    echo -e "${GREEN}  [OK] stdbuf available (improved buffering)${NC}"
else
    echo -e "${YELLOW}  [INFO] stdbuf not found - install coreutils for better buffering${NC}"
fi

echo -e "${GREEN}Preflight complete.${NC}"

# ============================================================================
# EXCLUSION MENU
# ============================================================================
exclusion_menu() {
    while true; do
        clear
        echo -e "${BLUE}=== EXCLUSION FILTERS ===${NC}\n"
        echo -e "${YELLOW}Note: Exclusions only hide from display - all traffic still logged${NC}\n"

        if [[ -s "$EXCLUDE_FILE" ]]; then
            echo -e "${GREEN}Current exclusions:${NC}"
            grep -v '^#' "$EXCLUDE_FILE" 2>/dev/null | grep -v '^$' | cat -n
            echo
        else
            echo -e "${YELLOW}No exclusions set${NC}\n"
        fi

        echo "[1] Exclude by process name"
        echo "[2] Exclude by destination IP/domain"
        echo "[3] Exclude by user"
        echo "[4] Exclude by port"
        echo "[5] Exclude by protocol"
        echo "[6] Remove specific exclusion"
        echo "[7] Clear all exclusions"
        echo "[8] Back to main menu"
        echo
        read -p ">> " choice

        case "$choice" in
            1)
                read -p "Process name to exclude: " proc
                [[ -n "$proc" ]] && echo "$proc" >> "$EXCLUDE_FILE" && echo "Excluded: $proc" && sleep 1
                ;;
            2)
                read -p "IP/domain to exclude: " ip
                [[ -n "$ip" ]] && echo "$ip" >> "$EXCLUDE_FILE" && echo "Excluded: $ip" && sleep 1
                ;;
            3)
                read -p "User to exclude: " user_excl
                [[ -n "$user_excl" ]] && echo "$user_excl" >> "$EXCLUDE_FILE" && echo "Excluded: $user_excl" && sleep 1
                ;;
            4)
                read -p "Port to exclude: " port
                [[ -n "$port" ]] && echo ":$port" >> "$EXCLUDE_FILE" && echo "Excluded: port $port" && sleep 1
                ;;
            5)
                read -p "Protocol (TCP/UDP/ICMP): " proto
                [[ -n "$proto" ]] && echo "$proto" >> "$EXCLUDE_FILE" && echo "Excluded: $proto" && sleep 1
                ;;
            6)
                read -p "Line number to remove: " lineno
                if [[ "$lineno" =~ ^[0-9]+$ ]] && [[ -s "$EXCLUDE_FILE" ]]; then
                    sed -i "${lineno}d" "$EXCLUDE_FILE" 2>/dev/null && echo "Removed line $lineno" && sleep 1
                fi
                ;;
            7)
                > "$EXCLUDE_FILE"
                echo "All exclusions cleared"
                sleep 1
                ;;
            8)
                break
                ;;
        esac
    done
}

# ============================================================================
# CONFIG MENU - color toggle now properly restores colors
# ============================================================================
config_menu() {
    clear
    echo -e "${BLUE}=== CONFIG ===${NC}\n"
    echo "Color coding: $([[ $COLOR_ENABLED -eq 1 ]] && echo -e "${GREEN}ON${NC}" || echo "OFF")"
    echo
    echo "[1] Toggle colors"
    echo "[2] View full log"
    echo "[3] View alerts"
    echo "[4] Clear logs"
    echo "[5] Rotate logs (archive + truncate)"
    echo "[6] View tcpdump errors (debug)"
    echo "[7] Back"
    read -p ">> " choice

    case "$choice" in
        1)
            COLOR_ENABLED=$((1 - COLOR_ENABLED))
            echo "COLOR_ENABLED=$COLOR_ENABLED" > "$CONFIG_FILE"
            chmod 600 "$CONFIG_FILE"
            set_colors  # Properly restores colors in both directions
            ;;
        2)
            less "$LOG_FILE" 2>/dev/null
            ;;
        3)
            less "$ALERT_FILE" 2>/dev/null
            ;;
        4)
            > "$LOG_FILE"
            > "$ALERT_FILE"
            > "$BUFFER_FILE"
            echo "Logs cleared"
            sleep 1
            ;;
        5)
            local ts
            ts=$(date +%Y%m%d_%H%M%S)
            cp "$LOG_FILE" "${LOG_FILE%.log}_${ts}.log" 2>/dev/null
            cp "$ALERT_FILE" "${ALERT_FILE%.log}_${ts}.log" 2>/dev/null
            > "$LOG_FILE"
            > "$ALERT_FILE"
            echo "Logs archived and rotated."
            sleep 1
            ;;
        6)
            echo -e "\n${BLUE}=== TCPDUMP DEBUG LOG ===${NC}\n"
            if [[ -s "$TCPDUMP_ERR_LOG" ]]; then
                cat "$TCPDUMP_ERR_LOG"
            else
                echo "(empty - no errors)"
            fi
            echo
            echo -e "${CYAN}Capture interface: ${CAPTURE_IFACE}${NC}"
            echo -e "${CYAN}Capture PID (subshell): ${TCPDUMP_PID:-none}${NC}"
            echo -e "${CYAN}Capture PID (tcpdump):  ${TCPDUMP_REAL_PID:-none}${NC}"
            if [[ -n "$TCPDUMP_PID" ]] && kill -0 "$TCPDUMP_PID" 2>/dev/null; then
                echo -e "${GREEN}Status: RUNNING${NC}"
            else
                echo -e "${RED}Status: NOT RUNNING${NC}"
            fi
            echo
            read -p "Press enter to continue..."
            ;;
    esac
}

# ============================================================================
# STATISTICS MENU
# ============================================================================
# Log format (for reference):
# $1              $2       $3  $4    $5     $6    $7     $8              $9 $10             ...
# 2025-02-13      10:30:45 DIR PROTO PROC   [USR] PRIV   PID:123        SRC:PORT -> DST:PORT SIZE:NB ...
# Field positions: date=$1, time=$2, dir=$3, proto=$4, proc=$5, user=$6 (bracketed), priv=$7
#                  pid_field=$8, src=$9, arrow=$10, dst=$11, size=$12

statistics_menu() {
    while true; do
        clear
        echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${BLUE}                    NETWORK STATISTICS                          ${NC}"
        echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}\n"

        if [[ ! -s "$LOG_FILE" ]]; then
            echo -e "${YELLOW}No data collected yet${NC}\n"
            echo "[1] Back"
            read -p ">> " choice
            [[ "$choice" == "1" ]] && break
            continue
        fi

        echo -e "${GREEN}[1] Connections by IP (All Protocols)${NC}"
        echo -e "${GREEN}[2] TCP Connections by IP:Port${NC}"
        echo -e "${GREEN}[3] UDP Connections by IP:Port${NC}"
        echo -e "${GREEN}[4] ICMP Connections by IP${NC}"
        echo -e "${GREEN}[5] Top Talkers (by packet count)${NC}"
        echo -e "${GREEN}[6] Top Data Transfer (by size)${NC}"
        echo -e "${GREEN}[7] Unique IPs Contacted${NC}"
        echo -e "${RED}[8] BEACONING DETECTION (C2 Analysis)${NC}"
        echo -e "${GREEN}[9] Export Statistics${NC}"
        echo -e "${CYAN}[0] Back${NC}"
        echo
        read -p ">> " choice

        case "$choice" in
            1)
                clear
                echo -e "${BLUE}=== ALL CONNECTIONS BY IP ===${NC}\n"
                echo -e "${CYAN}Count  Destination IP${NC}"
                echo "────────────────────────────────"
                # Match the -> DST:PORT field in our log format
                awk '{
                    for(i=1;i<=NF;i++){
                        if($i=="->") {
                            split($(i+1),a,":")
                            print a[1]
                        }
                    }
                }' "$LOG_FILE" | sort | uniq -c | sort -rn | head -20 | \
                    awk '{printf "%-6s %s\n", $1, $2}'
                echo
                read -p "Press enter to continue..."
                ;;
            2)
                clear
                echo -e "${BLUE}=== TCP CONNECTIONS BY IP:PORT ===${NC}\n"
                echo -e "${CYAN}Count  Destination IP:Port${NC}"
                echo "──────────────────────────────────────"
                grep " TCP " "$LOG_FILE" | awk '{
                    for(i=1;i<=NF;i++){
                        if($i=="->") { print $(i+1) }
                    }
                }' | sort | uniq -c | sort -rn | head -30 | \
                    awk '{printf "%-6s %s\n", $1, $2}'
                echo
                read -p "Press enter to continue..."
                ;;
            3)
                clear
                echo -e "${BLUE}=== UDP CONNECTIONS BY IP:PORT ===${NC}\n"
                echo -e "${CYAN}Count  Destination IP:Port${NC}"
                echo "──────────────────────────────────────"
                grep " UDP " "$LOG_FILE" | awk '{
                    for(i=1;i<=NF;i++){
                        if($i=="->") { print $(i+1) }
                    }
                }' | sort | uniq -c | sort -rn | head -30 | \
                    awk '{printf "%-6s %s\n", $1, $2}'
                echo
                read -p "Press enter to continue..."
                ;;
            4)
                clear
                echo -e "${BLUE}=== ICMP CONNECTIONS BY IP ===${NC}\n"
                echo -e "${CYAN}Count  Destination IP${NC}"
                echo "──────────────────────────────────────"
                grep " ICMP " "$LOG_FILE" | awk '{
                    for(i=1;i<=NF;i++){
                        if($i=="->") {
                            split($(i+1),a,":")
                            print a[1]
                        }
                    }
                }' | sort | uniq -c | sort -rn | head -20 | \
                    awk '{printf "%-6s %s\n", $1, $2}'
                echo
                read -p "Press enter to continue..."
                ;;
            5)
                clear
                echo -e "${BLUE}=== TOP TALKERS (Packet Count) ===${NC}\n"
                echo -e "${CYAN}Pkts   Process    User      Destination${NC}"
                echo "──────────────────────────────────────────────"
                # Parse: ... PROTO PROC [USER] PRIV PID:N SRC -> DST ...
                awk '{
                    proc=$5
                    user=$6; gsub(/[\[\]]/,"",user)
                    for(i=1;i<=NF;i++){
                        if($i=="->") { dest=$(i+1) }
                    }
                    if(proc!="" && user!="" && dest!="") {
                        key=proc"|"user"|"dest
                        count[key]++
                    }
                }
                END {
                    for(k in count) {
                        split(k,parts,"|")
                        printf "%d|%s|%s|%s\n", count[k], parts[1], parts[2], parts[3]
                    }
                }' "$LOG_FILE" | sort -t'|' -k1 -rn | head -20 | \
                awk -F'|' '{printf "%-6s %-10s %-10s %s\n", $1, substr($2,1,10), substr($3,1,10), $4}'
                echo
                read -p "Press enter to continue..."
                ;;
            6)
                clear
                echo -e "${BLUE}=== TOP DATA TRANSFER (by size) ===${NC}\n"
                echo -e "${CYAN}Size     Process    User      Destination${NC}"
                echo "──────────────────────────────────────────────"
                awk '{
                    proc=$5
                    user=$6; gsub(/[\[\]]/,"",user)
                    for(i=1;i<=NF;i++){
                        if($i=="->") { dest=$(i+1) }
                        if($i~/^SIZE:[0-9]+B$/){
                            gsub(/SIZE:/,"",$i)
                            gsub(/B/,"",$i)
                            bytes=$i
                        }
                    }
                    if(proc!="" && user!="" && dest!="" && bytes+0>0) {
                        key=proc"|"user"|"dest
                        total[key]+=bytes
                    }
                }
                END {
                    for(k in total) {
                        split(k,parts,"|")
                        size=total[k]
                        if(size>=1048576) sizestr=sprintf("%.1fMB", size/1048576)
                        else if(size>=1024) sizestr=sprintf("%.1fKB", size/1024)
                        else sizestr=sprintf("%dB", size)
                        printf "%s|%s|%s|%s|%d\n", sizestr, parts[1], parts[2], parts[3], size
                    }
                }' "$LOG_FILE" | sort -t'|' -k5 -rn | head -20 | \
                awk -F'|' '{printf "%-8s %-10s %-10s %s\n", $1, substr($2,1,10), substr($3,1,10), $4}'
                echo
                read -p "Press enter to continue..."
                ;;
            7)
                clear
                echo -e "${BLUE}=== UNIQUE DESTINATION IPs ===${NC}\n"
                unique_count=$(awk '{for(i=1;i<=NF;i++){if($i=="->"){split($(i+1),a,":"); print a[1]}}}' "$LOG_FILE" | sort -u | wc -l)
                echo -e "${GREEN}Total Unique IPs Contacted: $unique_count${NC}\n"
                echo -e "${CYAN}Destination IP         Protocol  Count${NC}"
                echo "──────────────────────────────────────"
                awk '{
                    proto=$4
                    for(i=1;i<=NF;i++){
                        if($i=="->"){
                            split($(i+1),a,":")
                            ip=a[1]
                            print ip"|"proto
                        }
                    }
                }' "$LOG_FILE" | sort | uniq -c | sort -rn | head -30 | \
                awk '{
                    split($2,parts,"|")
                    printf "%-22s %-8s %s\n", parts[1], parts[2], $1
                }'
                echo
                read -p "Press enter to continue..."
                ;;
            8)
                clear
                echo -e "${RED}╔═══════════════════════════════════════════════════════════════════════════╗${NC}"
                echo -e "${RED}║              BEACONING DETECTION - C2 ANALYSIS                          ║${NC}"
                echo -e "${RED}╚═══════════════════════════════════════════════════════════════════════════╝${NC}\n"

                echo -e "${YELLOW}Analyzing packet timing patterns for C2 beaconing...${NC}\n"

                local temp_beacon="${SECURE_TMP_DIR}/beacon_analysis.tmp"

                # FIX: search for "->" which is in every log line, not "PACKET" which never appeared
                awk '{
                    ts=$1" "$2
                    proc=$5
                    user=$6; gsub(/[\[\]]/,"",user)
                    for(i=1;i<=NF;i++){
                        if($i=="->") { dest=$(i+1); break }
                    }
                    if(dest!="" && proc!="") print ts"|"proc"|"user"|"dest
                }' "$LOG_FILE" | sort > "$temp_beacon"

                echo -e "${CYAN}Pkts   Avg Interval  Deviation  Process    User      Destination:Port      ${RED}RISK${NC}"
                echo "─────────────────────────────────────────────────────────────────────────────────────────────"

                awk -F'|' '
                function sqrt(x) { return x^0.5 }
                # Pure AWK timestamp to seconds - no shell-out, no injection risk
                # Input: "YYYY-MM-DD HH:MM:SS.mmm" -> seconds since midnight
                # (We only need relative intervals, not absolute epoch)
                function ts_to_secs(ts,    parts,dparts,tparts) {
                    split(ts, parts, " ")
                    split(parts[2], tparts, ":")
                    # seconds since midnight + fractional
                    return tparts[1]*3600 + tparts[2]*60 + tparts[3]
                }
                {
                    key=$2"|"$3"|"$4
                    secs = ts_to_secs($1)
                    if(secs==0) next

                    # Handle midnight wraparound (if time goes from 23:59 to 00:00)
                    if(last_time[key]!="" && secs < last_time[key] && (last_time[key] - secs) > 43200) {
                        secs += 86400
                    }

                    if(last_time[key]!="") {
                        interval=secs-last_time[key]
                        if(interval>0.1 && interval<300) {
                            intervals[key]=intervals[key]" "interval
                            count[key]++
                        }
                    }
                    last_time[key]=secs
                    proc[key]=$2
                    user[key]=$3
                    dest[key]=$4
                    total[key]++
                }
                END {
                    for(k in intervals) {
                        if(total[k]<5) continue

                        n=split(intervals[k],arr," ")
                        if(n<2) continue
                        sum=0
                        for(i=1;i<=n;i++) sum+=arr[i]
                        avg=sum/n

                        variance=0
                        for(i=1;i<=n;i++) variance+=(arr[i]-avg)^2
                        stddev=sqrt(variance/n)
                        cv=(avg>0) ? stddev/avg : 999

                        risk="    "
                        if(total[k]>=10 && cv<0.15 && avg>0.5) risk="CRIT"
                        else if(total[k]>=15 && cv<0.25) risk="HIGH"
                        else if(total[k]>=25 && cv<0.35) risk="MED "
                        else if(total[k]>=50) risk=" LOW"

                        printf "%d|%.2fs|%.1f%%|%s|%s|%s|%s\n",
                            total[k], avg, cv*100, proc[k], user[k], dest[k], risk
                    }
                }' "$temp_beacon" | sort -t'|' -k1 -rn | head -30 | \
                awk -F'|' '{
                    printf "%-6s %-12s %-10s %-10s %-9s %-25s %s\n",
                    $1, $2, $3, substr($4,1,10), substr($5,1,9), substr($6,1,25), $7
                }'

                rm -f "$temp_beacon"

                echo
                echo -e "${YELLOW}Risk Assessment:${NC}"
                echo -e "  ${RED}CRIT${NC}  - Highly regular intervals (<15% deviation), 10+ packets - ${RED}INVESTIGATE NOW${NC}"
                echo -e "  ${YELLOW}HIGH${NC}  - Regular intervals (<25% deviation), 15+ packets - ${YELLOW}Likely automated${NC}"
                echo -e "  ${CYAN}MED${NC}   - Moderate regularity (<35% deviation), 25+ packets"
                echo -e "  ${NC}LOW${NC}   - High packet count (50+) but irregular timing"
                echo
                echo -e "${GREEN}Avg Interval:${NC} Average time between packets (e.g., 5.2s = beacon every 5.2 seconds)"
                echo -e "${GREEN}Deviation:${NC}   Timing consistency (lower % = more regular = more suspicious)"
                echo
                read -p "Press enter to continue..."
                ;;
            9)
                clear
                local stats_file="${SCRIPT_DIR}/network_stats_$(date +%Y%m%d_%H%M%S).txt"
                echo "Generating statistics report..."
                {
                    echo "NETWORK STATISTICS REPORT"
                    echo "Generated: $(date)"
                    echo "========================================"
                    echo ""
                    echo "TOP 20 DESTINATION IPs:"
                    echo "----------------------------------------"
                    awk '{for(i=1;i<=NF;i++){if($i=="->"){split($(i+1),a,":"); print a[1]}}}' "$LOG_FILE" | \
                        sort | uniq -c | sort -rn | head -20
                    echo ""
                    echo "CONNECTIONS BY PROTOCOL:"
                    echo "----------------------------------------"
                    echo -n "TCP: "; grep -c " TCP " "$LOG_FILE" 2>/dev/null || echo 0
                    echo -n "UDP: "; grep -c " UDP " "$LOG_FILE" 2>/dev/null || echo 0
                    echo -n "ICMP: "; grep -c " ICMP " "$LOG_FILE" 2>/dev/null || echo 0
                    echo ""
                    echo "SECURITY ALERTS:"
                    echo "----------------------------------------"
                    if [[ -s "$ALERT_FILE" ]]; then
                        cat "$ALERT_FILE"
                    else
                        echo "None"
                    fi
                } > "$stats_file"
                echo -e "${GREEN}Statistics saved to: $stats_file${NC}"
                sleep 2
                ;;
            0)
                break
                ;;
        esac
    done
}

# ============================================================================
# INITIALIZE FILES
# ============================================================================
> "$BUFFER_FILE"
> "$BASELINE_FILE"
> "$RAW_EVENTS_FILE"
touch "$EXCLUDE_FILE"
touch "$LOG_FILE"
touch "$ALERT_FILE"
touch "$SS_CACHE_FILE"
touch "$PRIV_CACHE_FILE"

# Secure permissions - no world access
chmod 600 "$BUFFER_FILE" "$LOG_FILE" "$ALERT_FILE" "$BASELINE_FILE" "$SS_CACHE_FILE" "$PRIV_CACHE_FILE" "$RAW_EVENTS_FILE" 2>/dev/null

echo -e "${YELLOW}Starting comprehensive network monitor...${NC}"
echo -e "${GREEN}Monitoring: All TCP/UDP/ICMP traffic, syscalls, and process spawns${NC}"
sleep 1

# ============================================================================
# BACKGROUND: SS CACHE REFRESHER (every 1s instead of per-packet)
# ============================================================================
(
    while true; do
        sudo ss -tunap 2>/dev/null > "${SS_CACHE_FILE}.new" 2>/dev/null
        mv "${SS_CACHE_FILE}.new" "$SS_CACHE_FILE" 2>/dev/null
        sleep 1
    done
) &
SS_REFRESH_PID=$!

# ============================================================================
# BACKGROUND: PRIVILEGE CACHE REFRESHER (every 10s)
# ============================================================================
(
    while true; do
        {
            # Build user -> privilege mapping
            while IFS=: read -r uname _ uid _ _ _ _; do
                [[ "$uid" == "0" ]] && echo "${uname}=ROOT" && continue
                if groups "$uname" 2>/dev/null | grep -qE "\b(sudo|wheel|admin)\b"; then
                    echo "${uname}=PRIV"
                else
                    echo "${uname}=USER"
                fi
            done < /etc/passwd
        } > "${PRIV_CACHE_FILE}.new" 2>/dev/null
        mv "${PRIV_CACHE_FILE}.new" "$PRIV_CACHE_FILE" 2>/dev/null
        sleep 10
    done
) &
PRIV_CACHE_PID=$!

# ============================================================================
# BACKGROUND: BASELINE BUILDER
# ============================================================================
(
    while true; do
        sleep 60

        if [[ -s "$LOG_FILE" ]]; then
            cutoff=$(date -d '5 minutes ago' '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -v-5M '+%Y-%m-%d %H:%M:%S' 2>/dev/null)

            awk -v cutoff="$cutoff" '
            $1" "$2 >= cutoff {
                for(i=1;i<=NF;i++) {
                    if($i=="->") dst=$(i+1)
                }
                user=$6; gsub(/[\[\]]/,"",user)
                pattern = dst"|"user
                count[pattern]++
            }
            END {
                for(p in count) {
                    if(count[p] >= 10) {
                        print p
                    }
                }
            }' "$LOG_FILE" > "$BASELINE_FILE.tmp" 2>/dev/null

            mv "$BASELINE_FILE.tmp" "$BASELINE_FILE" 2>/dev/null
        fi
    done
) &
BASELINE_PID=$!

# ============================================================================
# BACKGROUND: PROCESS CACHE BUILDER
# ============================================================================
(
    while true; do
        > "${CACHE_FILE}.tmp" 2>/dev/null

        # Method 1: ss with process info (use the cached ss output)
        if [[ -s "$SS_CACHE_FILE" ]]; then
            # Portable AWK: avoid gawk-specific match(s,r,arr) syntax
            awk 'NR>1 && /pid=/ {
                # Extract pid with sub/gsub instead of match array capture
                s=$0
                sub(/.*pid=/,"",s)
                sub(/[^0-9].*/,"",s)
                pid=s
                if(pid!="" && pid+0>0) {
                    split($5,c,":")
                    port=c[length(c)]
                    print port"|"pid
                }
            }' "$SS_CACHE_FILE" 2>/dev/null | while IFS='|' read -r port pid; do
                if [[ -n "$pid" && "$pid" != "-" ]]; then
                    user=$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')
                    bin=$(ps -o comm= -p "$pid" 2>/dev/null | tr -d ' ')
                    cmd=$(ps -o args= -p "$pid" 2>/dev/null)
                    [[ -n "$user" ]] && echo "$port|$pid|$user|$bin|$cmd" >> "${CACHE_FILE}.tmp"
                fi
            done
        fi

        # Method 2: /proc scan - but limit to reduce CPU
        for pid_dir in /proc/[0-9]*; do
            pid_num=$(basename "$pid_dir" 2>/dev/null) || continue
            [[ ! -d "/proc/$pid_num/fd" ]] && continue

            # Quick check: does this pid have network sockets?
            if find "/proc/$pid_num/fd" -maxdepth 1 -lname 'socket:*' -print -quit 2>/dev/null | grep -q .; then
                user=$(ps -o user= -p "$pid_num" 2>/dev/null | tr -d ' ')
                bin=$(ps -o comm= -p "$pid_num" 2>/dev/null | tr -d ' ')
                cmd=$(ps -o args= -p "$pid_num" 2>/dev/null)
                [[ -n "$user" && -n "$bin" ]] && echo "0|$pid_num|$user|$bin|$cmd" >> "${CACHE_FILE}.tmp"
            fi
        done 2>/dev/null

        mv "${CACHE_FILE}.tmp" "$CACHE_FILE" 2>/dev/null
        sleep 2
    done
) &
CACHE_BUILDER_PID=$!

# ============================================================================
# BACKGROUND: TCPDUMP PACKET CAPTURE - main detection engine
# Includes auto-restart: if tcpdump dies, restarts after 3s
# ============================================================================
(
    # Helper: look up privilege from cache instead of calling groups per-packet
    get_priv() {
        local u="$1"
        [[ "$u" == "root" ]] && echo "ROOT" && return
        local cached
        cached=$(grep "^${u}=" "$PRIV_CACHE_FILE" 2>/dev/null | head -1 | cut -d= -f2)
        echo "${cached:-USER}"
    }

    # Build the tcpdump command with proper buffering
    # CRITICAL: Use -nn (double n) to force numeric IP AND port output
    TCPDUMP_CMD="sudo tcpdump -i ${CAPTURE_IFACE} -nn -l --immediate-mode"

    # Test if --immediate-mode is supported (newer tcpdump)
    if ! sudo timeout 2 tcpdump --immediate-mode -i "$CAPTURE_IFACE" -c 1 -w /dev/null 2>/dev/null; then
        TCPDUMP_CMD="sudo tcpdump -i ${CAPTURE_IFACE} -nn -l"
    fi

    # Wrap with stdbuf INSIDE sudo so it applies to tcpdump, not to sudo
    # "stdbuf -oL sudo ..." is wrong: sudo resets LD_PRELOAD, so stdbuf never reaches tcpdump
    # "sudo stdbuf -oL tcpdump ..." is correct: stdbuf runs as root and controls tcpdump's buffering
    if [[ "$USE_STDBUF" -eq 1 ]]; then
        STDBUF_PATH=$(command -v stdbuf)
        TCPDUMP_CMD="${TCPDUMP_CMD/sudo /sudo ${STDBUF_PATH} -oL }"
    fi

    # Auto-restart loop
    while true; do
        echo "[$(date)] tcpdump starting: ${TCPDUMP_CMD} 'tcp or udp or icmp'" >> "$TCPDUMP_ERR_LOG"

        # Run tcpdump with stderr captured (not silenced!)
        ${TCPDUMP_CMD} 'tcp or udp or icmp' 2>>"$TCPDUMP_ERR_LOG" | \
        while IFS= read -r line; do
            timestamp=$(date '+%H:%M:%S')

            # Parse IP addresses and ports
            if [[ "$line" =~ IP[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\.([0-9]+)[[:space:]]*\>[[:space:]]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\.([0-9]+) ]]; then
                src_ip="${BASH_REMATCH[1]}"
                src_port="${BASH_REMATCH[2]}"
                dst_ip="${BASH_REMATCH[3]}"
                dst_port="${BASH_REMATCH[4]}"
            # Fallback: handle named ports (e.g., .https, .http, .domain, .ssh)
            elif [[ "$line" =~ IP[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\.([a-zA-Z0-9-]+)[[:space:]]*\>[[:space:]]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\.([a-zA-Z0-9-]+): ]]; then
                src_ip="${BASH_REMATCH[1]}"
                src_port="${BASH_REMATCH[2]}"
                dst_ip="${BASH_REMATCH[3]}"
                dst_port="${BASH_REMATCH[4]}"
            # ICMP: IP 10.0.0.1 > 192.0.2.101: ICMP echo request, ...
            elif [[ "$line" =~ IP[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)[[:space:]]*\>[[:space:]]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*ICMP ]]; then
                src_ip="${BASH_REMATCH[1]}"
                src_port="ICMP"
                dst_ip="${BASH_REMATCH[2]}"
                dst_port="ICMP"
            # IPv6 basic support
            elif [[ "$line" =~ IP6[[:space:]]+([0-9a-f:]+)\.([0-9]+)[[:space:]]*\>[[:space:]]*([0-9a-f:]+)\.([0-9]+) ]]; then
                src_ip="${BASH_REMATCH[1]}"
                src_port="${BASH_REMATCH[2]}"
                dst_ip="${BASH_REMATCH[3]}"
                dst_port="${BASH_REMATCH[4]}"
            else
                continue
            fi

            # Extract packet size
            packet_bytes=0
            if [[ "$line" =~ length[[:space:]]+([0-9]+) ]]; then
                packet_bytes="${BASH_REMATCH[1]}"
            fi

            # Determine protocol
            if [[ "$line" == *"ICMP"* ]]; then
                proto="ICMP"
                port="ICMP"
            elif [[ "$line" == *" UDP "* ]] || [[ "$line" == *".domain:"* ]] || [[ "$line" == *".53:"* ]]; then
                proto="UDP"
                port="$dst_port"
            else
                proto="TCP"
                port="$dst_port"
            fi

            # Process lookup from CACHED ss data (not per-packet ss call)
            pid=""
            user=""
            bin=""
            cmd=""

            if [[ "$proto" != "ICMP" ]] && [[ -s "$SS_CACHE_FILE" ]]; then
                ss_match=$(grep "$src_ip:$src_port" "$SS_CACHE_FILE" 2>/dev/null | head -n1)
                if [[ -n "$ss_match" ]] && [[ "$ss_match" =~ pid=([0-9]+) ]]; then
                    pid="${BASH_REMATCH[1]}"
                fi

                # Fallback: try destination port match in cache file
                if [[ -z "$pid" ]] && [[ -s "$CACHE_FILE" ]]; then
                    cache_match=$(grep "^${src_port}|" "$CACHE_FILE" 2>/dev/null | head -n1)
                    if [[ -n "$cache_match" ]]; then
                        IFS='|' read -r _ pid user bin cmd <<< "$cache_match"
                    fi
                fi

                # Fallback 2: try destination port in ss cache (for inbound)
                if [[ -z "$pid" ]] && [[ -s "$SS_CACHE_FILE" ]]; then
                    ss_match2=$(grep ":${dst_port}" "$SS_CACHE_FILE" 2>/dev/null | head -n1)
                    if [[ -n "$ss_match2" ]] && [[ "$ss_match2" =~ pid=([0-9]+) ]]; then
                        pid="${BASH_REMATCH[1]}"
                    fi
                fi

                # Fallback 3: search process cache by PID for any matching network process
                if [[ -z "$pid" ]] && [[ -s "$CACHE_FILE" ]]; then
                    cache_match2=$(grep "|${dst_port}\b" "$CACHE_FILE" 2>/dev/null | head -n1)
                    if [[ -n "$cache_match2" ]]; then
                        IFS='|' read -r _ pid user bin cmd <<< "$cache_match2"
                    fi
                fi
            elif [[ "$proto" == "ICMP" ]]; then
                pid=$(pgrep -x "ping" 2>/dev/null | head -1)
                [[ -z "$pid" ]] && pid=$(pgrep -x "hping3" 2>/dev/null | head -1)
                [[ -z "$pid" ]] && pid=$(pgrep -x "hping" 2>/dev/null | head -1)
            fi

            # Resolve PID to process info if we have pid but not bin
            if [[ -n "$pid" ]] && [[ -z "$bin" ]]; then
                user=$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')
                bin=$(ps -o comm= -p "$pid" 2>/dev/null | tr -d ' ')
                cmd=$(ps -o args= -p "$pid" 2>/dev/null)
            fi

            # Fallback: kernel/system
            if [[ -z "$pid" ]] || [[ -z "$bin" ]]; then
                pid="0"
                user="system"
                bin="kernel"
                cmd="kernel_net"
            fi

            # Detect threats
            threat_info=$(detect_threats "$bin" "$cmd" "$dst_ip" "$proto" "$user")
            IFS='|' read -r threat severity <<< "$threat_info"

            # Get privilege from cache
            priv=$(get_priv "$user")

            # Color based on privilege
            color="$NC"
            if [[ "$priv" == "ROOT" ]]; then
                color="$RED"
            elif [[ "$priv" == "PRIV" ]]; then
                color="$YELLOW"
            fi

            # Override color for critical threats
            if [[ "$severity" == "CRITICAL" ]]; then
                color="$RED$BOLD"
                threat="CRIT:$threat"
            elif [[ "$severity" == "HIGH" ]]; then
                threat="HIGH:$threat"
            elif [[ "$severity" == "MEDIUM" ]]; then
                threat="MED:$threat"
            fi

            # Check baseline for anomalies
            anom=""
            if [[ -s "$BASELINE_FILE" ]]; then
                pattern="$dst_ip|$user"
                if ! grep -qF "$pattern" "$BASELINE_FILE" 2>/dev/null; then
                    anom="NEW"
                fi
            fi

            # Direction
            if [[ "$src_ip" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.) ]]; then
                dir="OUT"
            else
                dir="IN"
            fi

            size_str="${packet_bytes}B"
            cmd_display="${cmd:0:50}"
            # Sanitize pipe chars from cmd so they don't break the aggregator's delimiter
            cmd_display="${cmd_display//|/ }"

            # Write raw event for the aggregator (pipe-delimited, no ANSI codes)
            echo "${timestamp}|${dir}|${proto}|${bin}|${user}|${priv}|${pid}|${dst_ip}|${dst_port}|${packet_bytes}|${cmd_display}|${threat}|${severity}" >> "$RAW_EVENTS_FILE"

            # Log with full details (per-packet)
            echo "$(date '+%Y-%m-%d %H:%M:%S.%3N') $dir $proto $bin [$user] $priv PID:$pid $src_ip:$src_port -> $dst_ip:$dst_port SIZE:${packet_bytes}B | CMD: $cmd | THREAT: $threat" >> "$LOG_FILE"

            # Log threats separately
            if [[ -n "$threat" && "$threat" != "|" && -n "$severity" ]]; then
                echo "$(date '+%Y-%m-%d %H:%M:%S') [$severity] $threat - $bin ($user) PID:$pid -> $dst_ip:$dst_port SIZE:$size_str | CMD: $cmd" >> "$ALERT_FILE"
            fi
        done

        # If we get here, tcpdump exited — log and restart
        echo "[$(date)] tcpdump exited (status $?), restarting in 3s..." >> "$TCPDUMP_ERR_LOG"
        sleep 3
    done
) &
TCPDUMP_PID=$!

# ============================================================================
# BACKGROUND: 5-SECOND EVENT AGGREGATOR
# Groups packets by (dir|proto|process|user|priv|dst_ip:dst_port) over 5s windows
# Writes collapsed summary lines to BUFFER_FILE for display
# ============================================================================
(
    while true; do
        sleep 5

        # Atomically swap the raw events file so tcpdump can keep writing
        if [[ -s "$RAW_EVENTS_FILE" ]]; then
            mv "$RAW_EVENTS_FILE" "${RAW_EVENTS_FILE}.processing" 2>/dev/null
            touch "$RAW_EVENTS_FILE"
            chmod 600 "$RAW_EVENTS_FILE" 2>/dev/null

            # Aggregate with AWK: group by dir|proto|bin|user|priv|dst_ip:dst_port
            # Output: grouped summary lines (no ANSI - color applied in bash)
            awk -F'|' '
            {
                # Fields: 1=time 2=dir 3=proto 4=bin 5=user 6=priv 7=pid 8=dst_ip 9=dst_port
                #         10=bytes 11=cmd 12=threat 13=severity
                key = $2 "|" $3 "|" $4 "|" $5 "|" $6 "|" $8 ":" $9

                count[key]++
                bytes[key] += $10

                # Keep last timestamp
                last_ts[key] = $1

                # Keep first pid, cmd
                if (!(key in pid_val)) {
                    pid_val[key] = $7
                    cmd_val[key] = $11
                }

                # Track worst threat severity
                sev = $13
                if (sev == "CRITICAL") s = 4
                else if (sev == "HIGH") s = 3
                else if (sev == "MEDIUM") s = 2
                else if (sev == "LOW") s = 1
                else s = 0

                if (s > best_sev[key]) {
                    best_sev[key] = s
                    threat_val[key] = $12
                    severity_val[key] = $13
                }

                # Store parts for output
                dir_val[key] = $2
                proto_val[key] = $3
                bin_val[key] = $4
                user_val[key] = $5
                priv_val[key] = $6
                dst_val[key] = $8 ":" $9
            }
            END {
                for (k in count) {
                    b = bytes[k]
                    if (b >= 1048576) size = sprintf("%.1fMB", b/1048576)
                    else if (b >= 1024) size = sprintf("%.1fKB", b/1024)
                    else size = sprintf("%dB", b)

                    c = count[k]
                    if (c > 1) pkts = sprintf("[%dx]", c)
                    else pkts = ""

                    printf "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n", \
                        last_ts[k], dir_val[k], proto_val[k], \
                        substr(bin_val[k],1,12), substr(user_val[k],1,8), \
                        priv_val[k], pid_val[k], dst_val[k], \
                        size, pkts, substr(cmd_val[k],1,40), severity_val[k]
                }
            }
            ' "${RAW_EVENTS_FILE}.processing" | sort -t'|' -k1,1 | \
            while IFS='|' read -r ts dir proto bin user priv pid dst size pkts cmd worst_sev; do
                # Determine color from privilege and threat severity
                color="$NC"
                if [[ "$worst_sev" == "CRITICAL" ]]; then
                    color="$RED$BOLD"
                elif [[ "$priv" == "ROOT" ]]; then
                    color="$RED"
                elif [[ "$worst_sev" == "HIGH" ]]; then
                    color="$YELLOW"
                elif [[ "$priv" == "PRIV" ]]; then
                    color="$YELLOW"
                fi

                output=$(printf "%-8s %-3s %-5s %-12s %-8s %-6s %-6s %-22s %-8s %-6s %s" \
                    "$ts" "$dir" "$proto" "$bin" "$user" "$priv" "$pid" \
                    "$dst" "$size" "$pkts" "$cmd")

                echo -e "${color}${output}${NC}" >> "$BUFFER_FILE"
            done

            rm -f "${RAW_EVENTS_FILE}.processing" 2>/dev/null
        fi
    done
) &
AGG_PID=$!

# ============================================================================
# BACKGROUND: SHORT-LIVED PROCESS MONITOR
# ============================================================================
(
    # Set up audit rules if available
    if command -v auditctl &>/dev/null; then
        sudo auditctl -a exit,always -F arch=b64 -S execve -F exe=/usr/bin/curl -k curl_exec 2>/dev/null
        sudo auditctl -a exit,always -F arch=b64 -S execve -F exe=/usr/bin/wget -k wget_exec 2>/dev/null
        sudo auditctl -a exit,always -F arch=b64 -S execve -F exe=/usr/bin/ping -k ping_exec 2>/dev/null
    fi

    # ps-based monitoring
    while true; do
        ps aux 2>/dev/null | grep -E '[c]url|[w]get|[p]ing|[n]cat|[n]c |[s]ocat' | while read -r psline; do
            p_user=$(echo "$psline" | awk '{print $1}')
            p_pid=$(echo "$psline" | awk '{print $2}')
            p_cmd=$(echo "$psline" | awk '{for(i=11;i<=NF;i++) printf $i" "; print ""}')
            p_bin=$(echo "$p_cmd" | awk '{print $1}')
            p_bin=$(basename "$p_bin" 2>/dev/null)

            # Avoid duplicate entries
            if ! grep -q "|${p_pid}|" "$CACHE_FILE" 2>/dev/null; then
                echo "0|${p_pid}|${p_user}|${p_bin}|${p_cmd}" >> "$CACHE_FILE"
            fi
        done
        sleep 1
    done
) &
PROC_MONITOR_PID=$!

# ============================================================================
# BACKGROUND: LOG ROTATION & BUFFER TRIM
# ============================================================================
(
    while true; do
        sleep 10

        # Trim buffer
        if [[ -f "$BUFFER_FILE" ]]; then
            tail -n 2000 "$BUFFER_FILE" > "$BUFFER_FILE.tmp" 2>/dev/null && mv "$BUFFER_FILE.tmp" "$BUFFER_FILE" 2>/dev/null
        fi

        # Auto-rotate logs if they get too large (>50MB)
        for f in "$LOG_FILE" "$ALERT_FILE"; do
            if [[ -f "$f" ]]; then
                fsize=$(stat -c%s "$f" 2>/dev/null || echo 0)
                if [[ "$fsize" -gt 52428800 ]]; then
                    mv "$f" "${f}.$(date +%H%M%S).bak" 2>/dev/null
                    touch "$f"
                    chmod 600 "$f" 2>/dev/null
                fi
            fi
        done
    done
) &
BUFFER_TRIM_PID=$!

# ============================================================================
# DASHBOARD - main display loop
# ============================================================================
clear
stty -echo 2>/dev/null
tput civis 2>/dev/null

while true; do
    clear
    echo -e "${BLUE}╔═════════════════════════════════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC} ${GREEN}NETWORK SECURITY MONITOR v8${NC} ${CYAN}[m]${NC}Menu ${RED}[5s AGGREGATED]${NC}                                    ${BLUE}║${NC}"
    echo -e "${BLUE}╚═════════════════════════════════════════════════════════════════════════════════════════════════════════╝${NC}"
    printf "%-8s %-3s %-5s %-12s %-8s %-6s %-6s %-22s %-8s %-6s %s\n" \
           "TIME" "DIR" "PROTO" "PROCESS" "USER" "PRIV" "PID" "DEST:PORT" "SIZE" "PKTS" "COMMAND"
    echo "─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────"

    if [[ ! -s "$BUFFER_FILE" ]]; then
        echo -e "\n      ${YELLOW}Waiting for traffic... (events appear in 5s batches)${NC}"
        echo -e "      ${CYAN}Interface: ${CAPTURE_IFACE} | Try: curl google.com, ping 8.8.8.8${NC}"
        echo -e "      ${CYAN}Press [m] > Config > tcpdump errors if no events appear${NC}"
    else
        # Apply exclusions when displaying
        if [[ -s "$EXCLUDE_FILE" ]]; then
            exclude_pattern=$(grep -v '^#' "$EXCLUDE_FILE" 2>/dev/null | grep -v '^$' | tr '\n' '|' | sed 's/|$//')
            if [[ -n "$exclude_pattern" ]]; then
                tail -n 30 "$BUFFER_FILE" 2>/dev/null | grep -vE "$exclude_pattern" | while IFS= read -r line; do
                    echo -e "$line"
                done
            else
                tail -n 30 "$BUFFER_FILE" 2>/dev/null | while IFS= read -r line; do
                    echo -e "$line"
                done
            fi
        else
            tail -n 30 "$BUFFER_FILE" 2>/dev/null | while IFS= read -r line; do
                echo -e "$line"
            done
        fi
    fi

    # Show stats
    total=$(wc -l < "$LOG_FILE" 2>/dev/null || echo 0)
    alerts=$(wc -l < "$ALERT_FILE" 2>/dev/null || echo 0)
    echo -e "\n${GREEN}Total Events:${NC} $total  ${RED}Security Alerts:${NC} $alerts"

    # Show active exclusions
    if [[ -s "$EXCLUDE_FILE" ]]; then
        active=$(grep -v '^#' "$EXCLUDE_FILE" 2>/dev/null | grep -v '^$' | tr '\n' ', ' | sed 's/,$//')
        [[ -n "$active" ]] && echo -e "${YELLOW}Filtered:${NC} $active"
    fi

    # Self-protection: verify tcpdump is still running (subshell auto-restarts it)
    if [[ -n "$TCPDUMP_PID" ]] && ! kill -0 "$TCPDUMP_PID" 2>/dev/null; then
        echo -e "${RED}WARNING: Capture subshell died! Manual restart needed.${NC}"
        if [[ -s "$TCPDUMP_ERR_LOG" ]]; then
            echo -e "${RED}  Last error: $(tail -1 "$TCPDUMP_ERR_LOG")${NC}"
        fi
    elif [[ -s "$TCPDUMP_ERR_LOG" ]] && grep -q "restarting" "$TCPDUMP_ERR_LOG" 2>/dev/null; then
        restarts=$(grep -c "restarting" "$TCPDUMP_ERR_LOG" 2>/dev/null)
        [[ "$restarts" -gt 0 ]] && echo -e "${YELLOW}NOTE: tcpdump has auto-restarted ${restarts} time(s)${NC}"
    fi

    if read -t 0.5 -n 1 key 2>/dev/null; then
        if [[ "$key" == "m" ]]; then
            stty echo 2>/dev/null
            tput cnorm 2>/dev/null
            clear
            echo -e "${BLUE}╔══════════════╗${NC}"
            echo -e "${BLUE}║${NC} ${GREEN}MAIN MENU${NC}  ${BLUE}║${NC}"
            echo -e "${BLUE}╚══════════════╝${NC}\n"
            echo "[1] Config & Logs"
            echo "[2] Exclusions (filter display)"
            echo "[3] Statistics"
            echo "[4] Exit"
            read -p ">> " choice

            case "$choice" in
                1) config_menu ;;
                2) exclusion_menu ;;
                3) statistics_menu ;;
                4) exit 0 ;;
            esac

            stty -echo 2>/dev/null
            tput civis 2>/dev/null
        fi
    fi
done
