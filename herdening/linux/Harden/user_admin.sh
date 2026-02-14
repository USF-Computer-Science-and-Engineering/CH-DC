#!/bin/sh
# ── Integrity Check (do not move — must run before anything else) ────────────
# Verifies this script hasn't been tampered with by comparing against a
# pre-generated .sha256 hash file. Run generate_hashes.sh to create/update it.
_integrity_check() {
    _self=$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || echo "$0")
    _hash_file="${_self}.sha256"
    if [ -f "$_hash_file" ]; then
        _expected=$(awk '{print $1}' "$_hash_file")
        if command -v sha256sum >/dev/null 2>&1; then
            _actual=$(sha256sum "$_self" | awk '{print $1}')
        elif command -v shasum >/dev/null 2>&1; then
            _actual=$(shasum -a 256 "$_self" | awk '{print $1}')
        else
            printf '\033[1;33m[!] INTEGRITY CHECK SKIPPED: no sha256sum or shasum available\033[0m\n'
            return
        fi
        if [ "$_expected" != "$_actual" ]; then
            printf '\033[1;31m╔══════════════════════════════════════════════════════════════╗\033[0m\n'
            printf '\033[1;31m║  INTEGRITY CHECK FAILED — POSSIBLE TAMPERING DETECTED!      ║\033[0m\n'
            printf '\033[1;31m╚══════════════════════════════════════════════════════════════╝\033[0m\n'
            printf '\033[1;31m  Expected: %s\033[0m\n' "$_expected"
            printf '\033[1;31m  Got:      %s\033[0m\n' "$_actual"
            printf '\033[1;33m  ⚠ This script may have been modified by Red Team!\033[0m\n'
            printf '\033[1;33m  ⚠ Re-download scripts from your team repo and run generate_hashes.sh\033[0m\n'
            exit 78
        fi
    else
        printf '\033[1;33m[!] WARNING: No hash file found — integrity cannot be verified\033[0m\n'
        printf '\033[1;33m    Run generate_hashes.sh to create hash files\033[0m\n'
    fi
}
_integrity_check
unset -f _integrity_check 2>/dev/null
# ─────────────────────────────────────────────────────────────────────────────
# ============================================================================
# user_admin.sh — CCDC Comprehensive User Management & Audit
# ============================================================================
# Manages authorized user lists, detects unauthorized users, rotates passwords,
# audits SSH keys / bashrc / home directories, and tracks changes between runs.
#
# Usage:
#   sudo sh user_admin.sh                          # Full interactive mode
#   sudo sh user_admin.sh --audit-only             # Read-only audit (no changes)
#   sudo sh user_admin.sh --passwords-only         # Skip audit, just rotate passwords
#
# Requires: admins.txt and users.txt in the SAME directory as this script.
#   Optional: domain_users.txt
#
# On re-run: compares against previous snapshot to show what changed.
# POSIX sh — works on dash/ash/bash across all distros.
# ============================================================================

# ── Modes ───────────────────────────────────────────────────────────────────
AUDIT_ONLY=false; PASSWORDS_ONLY=false
for arg in "$@"; do
    case "$arg" in
        --audit-only) AUDIT_ONLY=true ;;
        --passwords-only) PASSWORDS_ONLY=true ;;
    esac
done

# ── Globals ─────────────────────────────────────────────────────────────────
HOSTNAME=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo "unknown")
TIMESTAMP=$(date +%Y%m%d_%H%M%S 2>/dev/null || echo "notime")
SCRIPT_DIR=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
STATE_DIR="$SCRIPT_DIR/.ccdc_state"
SNAPSHOT="$STATE_DIR/last_snapshot.txt"
FIRST_SNAPSHOT="$STATE_DIR/first_snapshot.txt"
REPORT_DIR="${SCRIPT_DIR}/ccdc_reports/users_${HOSTNAME}_${TIMESTAMP}"
BACKUP_DIR="$REPORT_DIR/backups"
LOG="$REPORT_DIR/report.log"
mkdir -p "$BACKUP_DIR" "$STATE_DIR" "$REPORT_DIR/ir_evidence"
chmod 700 "$REPORT_DIR" "$STATE_DIR" 2>/dev/null

# Save snapshot on exit (trap)
save_snapshot() {
    if [ -n "$CURRENT_SNAP" ]; then
        echo "$CURRENT_SNAP" > "$SNAPSHOT" 2>/dev/null
        chmod 600 "$SNAPSHOT" 2>/dev/null
        log "Snapshot saved on exit"
    fi
}
trap save_snapshot EXIT INT TERM

# ── Colors ──────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
    R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; B='\033[1m'; N='\033[0m'
else
    R=''; G=''; Y=''; C=''; B=''; N=''
fi

# ── Helpers ─────────────────────────────────────────────────────────────────
cmd_exists() { command -v "$1" > /dev/null 2>&1; }
log()    { printf "[%s] %s\n" "$(date +%H:%M:%S 2>/dev/null)" "$1" >> "$LOG"; }
banner() { printf "\n${C}${B}══════════════════════════════════════════════════════════════${N}\n"; }
header() { printf "\n${C}${B}[*] %s${N}\n" "$1"; printf '%60s\n' '' | tr ' ' '-'; }
ok()     { printf "${G}  [✓] %s${N}\n" "$1"; log "OK: $1"; }
warn_()  { printf "${Y}  [!] %s${N}\n" "$1"; log "WARN: $1"; WARNINGS=$((WARNINGS+1)); echo x >> "$_WARN_FILE"; }
crit()   { printf "${R}${B}  [!!!] %s${N}\n" "$1"; log "CRIT: $1"; CRITICALS=$((CRITICALS+1)); echo x >> "$_CRIT_FILE"; }
info()   { printf "  [-] %s\n" "$1"; }
skip()   { printf "${Y}  [—] SKIPPED: %s${N}\n" "$1"; log "SKIP: $1"; }
fix()    { printf "${C}      ↳ FIX: %s${N}\n" "$1"; }
indent() { sed 's/^/      /'; }

confirm() {
    if [ "$AUDIT_ONLY" = true ]; then return 1; fi
    printf "${Y}  [?] %s [y/N]: ${N}" "$1"
    read -r ans < /dev/tty
    # Default to No if empty or anything other than y/yes
    case "$ans" in y|Y|yes|YES) return 0;; *) return 1;; esac
}

choose() {
    # Interactive menu: returns the chosen letter
    if [ "$AUDIT_ONLY" = true ]; then echo "S"; return; fi
    printf "${Y}  [?] %s: ${N}" "$1"
    read -r ans
    echo "${ans:-$2}"
}

backup_file() {
    if [ -f "$1" ]; then
        # Unlock immutable files before backup (safe_chattr)
        safe_chattr -i "$1"
        dest="$BACKUP_DIR/$(echo "$1" | tr '/' '_')"
        cp -a "$1" "$dest" 2>/dev/null
        log "BACKUP: $1 -> $dest"
    fi
}

# Safe chattr — gracefully handles unsupported filesystems (XFS, BTRFS, ZFS)
safe_chattr() {
    flag="$1"  # +i or -i
    file="$2"
    
    if ! cmd_exists chattr; then
        return 1  # chattr not available
    fi
    
    if chattr "$flag" "$file" 2>/dev/null; then
        return 0  # Success
    else
        # Filesystem doesn't support chattr (XFS, BTRFS, ZFS, etc.)
        return 1
    fi
}

# chattr helpers — lock/unlock critical files
lock_file() {
    if safe_chattr +i "$1"; then
        log "LOCKED: $1 (chattr)"
        return 0
    else
        # Not an error - just unsupported filesystem
        return 1
    fi
}

unlock_file() {
    if safe_chattr -i "$1"; then
        log "UNLOCKED: $1 (chattr)"
        return 0
    else
        return 1
    fi
}

# Critical file wrapper - unlocks, performs operation, re-locks ONLY previously locked files
critical_operation() {
    CRITICAL_FILES="/etc/passwd /etc/shadow /etc/group /etc/gshadow"
    LOCKED_FILES=""
    
    # Unlock and track which were locked
    for f in $CRITICAL_FILES; do
        [ -f "$f" ] || continue
        
        # Check if file is currently locked (only if lsattr available)
        if cmd_exists lsattr; then
            if lsattr "$f" 2>/dev/null | awk '{print $1}' | grep -q 'i'; then
                LOCKED_FILES="$LOCKED_FILES $f"
                safe_chattr -i "$f"
            fi
        fi
    done
    
    # Execute the operation
    "$@"
    result=$?
    
    # Re-lock ONLY previously locked files
    for f in $LOCKED_FILES; do
        safe_chattr +i "$f"
    done
    
    return $result
}

# ── Root Check ──────────────────────────────────────────────────────────────
if [ "$(id -u)" != "0" ]; then
    printf "${R}${B}  [!] This script must be run as root!${N}\n"
    exit 1
fi

# ── Package Manager Detection ──────────────────────────────────────────────
PKG_MGR="unknown"
if cmd_exists apt-get; then PKG_MGR="apt"
elif cmd_exists dnf; then PKG_MGR="dnf"
elif cmd_exists yum; then PKG_MGR="yum"
elif cmd_exists pacman; then PKG_MGR="pacman"
elif cmd_exists apk; then PKG_MGR="apk"
elif cmd_exists zypper; then PKG_MGR="zypper"
fi

CRITICALS=0; WARNINGS=0; FIXED=0; SKIPPED=0

# File-based counters (survive subshells created by piped while-read loops)
_CNT_DIR=$(mktemp -d 2>/dev/null || echo "$STATE_DIR/counters_$$")
mkdir -p "$_CNT_DIR" 2>/dev/null
_CRIT_FILE="$_CNT_DIR/criticals"
_WARN_FILE="$_CNT_DIR/warnings"
_FIX_FILE="$_CNT_DIR/fixed"
_SKIP_FILE="$_CNT_DIR/skipped"
: > "$_CRIT_FILE"; : > "$_WARN_FILE"; : > "$_FIX_FILE"; : > "$_SKIP_FILE"
add_fixed()   { echo x >> "$_FIX_FILE"; }
add_skipped() { echo x >> "$_SKIP_FILE"; }

banner
printf "${C}${B}  USER MANAGEMENT — %s — %s${N}\n" "$HOSTNAME" "$(date 2>/dev/null)"
printf "${C}  Report:  %s${N}\n" "$REPORT_DIR"
if [ "$AUDIT_ONLY" = true ]; then printf "${G}${B}  MODE: AUDIT-ONLY (no changes)${N}\n"; fi
banner

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  0. GLOBAL EXCLUSIONS & CONFIG                                          ║
# ╚════════════════════════════════════════════════════════════════════════════╝
EXCLUDE_FILE="${SCRIPT_DIR}/global_exclude.txt"
EXCLUDED_USERS=""
EXCLUDED_PROCS=""
EXCLUDED_FILES=""

load_exclusions() {
    if [ -f "$EXCLUDE_FILE" ]; then
        info "Loading exclusions from $EXCLUDE_FILE..."
        # Read file, ignoring comments/empty lines
        EXCLUDED_USERS=$(grep "^USER:" "$EXCLUDE_FILE" 2>/dev/null | cut -d: -f2 | tr '\n' ' ' | sed 's/ $//')
        EXCLUDED_PROCS=$(grep "^PROC:" "$EXCLUDE_FILE" 2>/dev/null | cut -d: -f2 | tr '\n' ' ' | sed 's/ $//')
        EXCLUDED_FILES=$(grep "^FILE:" "$EXCLUDE_FILE" 2>/dev/null | cut -d: -f2 | tr '\n' ' ' | sed 's/ $//')
        
        [ -n "$EXCLUDED_USERS" ] && ok "Excluded Users: $EXCLUDED_USERS"
        [ -n "$EXCLUDED_PROCS" ] && ok "Excluded Procs: $EXCLUDED_PROCS"
    else
        if [ "$AUDIT_ONLY" = true ]; then
            info "No exclusion file found (skipping prompt in audit mode)"
        else
            echo ""
            printf "${Y}${B}  ╔══════════════════════════════════════════════════════════╗${N}\n"
            printf "${Y}${B}  ║  ⚠  CRITICAL: DO NOT BREAK SCORING / INFRASTRUCTURE    ║${N}\n"
            printf "${Y}${B}  ║                                                        ║${N}\n"
            printf "${Y}${B}  ║  Are there any users, processes, or files we must      ║${N}\n"
            printf "${Y}${B}  ║  ABSOLUTELY NOT TOUCH? (e.g. scoring agents, splunk)   ║${N}\n"
            printf "${Y}${B}  ╚══════════════════════════════════════════════════════════╝${N}\n"
            
            if confirm "Configure global exclusions now?"; then
                printf "${Y}  Enter USERS to exclude (space separated, e.g. splunk ccdc_score): ${N}"
                read -r ex_users
                printf "${Y}  Enter PROCESS names to exclude (space separated, e.g. python3 java): ${N}"
                read -r ex_procs
                
                # Save to file
                echo "# CCDC Global Exclusions" > "$EXCLUDE_FILE"
                echo "# Add items here to prevent scripts from touching them"
                for u in $ex_users; do echo "USER:$u" >> "$EXCLUDE_FILE"; done
                for p in $ex_procs; do echo "PROC:$p" >> "$EXCLUDE_FILE"; done
                
                EXCLUDED_USERS="$ex_users"
                EXCLUDED_PROCS="$ex_procs"
                ok "Exclusions saved to $EXCLUDE_FILE"
            fi
        fi
    fi
}

is_excluded_user() {
    # Returns 0 (true) if user is in exclusion list
    [ -z "$EXCLUDED_USERS" ] && return 1
    echo "$EXCLUDED_USERS" | grep -qwF "$1"
}

load_exclusions

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  1. LOAD AUTHORIZED LISTS                                               ║
# ╚════════════════════════════════════════════════════════════════════════════╝
header "LOADING AUTHORIZED LISTS"
info "Reads admins.txt, users.txt, and optional domain_users.txt."
info "Users listed here are AUTHORIZED — everyone else will be flagged."

# Clean a list file: strip whitespace, blank lines, comments, deduplicate, remove DOS returns
clean_list() {
    [ -f "$1" ] || return
    tr -d '\r' < "$1" 2>/dev/null | grep -v '^#\|^[[:space:]]*$' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sort -u
}

ADMINS_FILE="$SCRIPT_DIR/admins.txt"
USERS_FILE="$SCRIPT_DIR/users.txt"
DOMAIN_FILE="$SCRIPT_DIR/domain_users.txt"

# Validate that users in the list actually exist on this system
validate_users_exist() {
    list_name="$1"
    user_list="$2"
    [ -z "$user_list" ] && return
    
    _missing_names=""
    _missing_count=0
    while read -r u; do
        [ -z "$u" ] && continue
        if ! id "$u" >/dev/null 2>&1; then
            _missing_count=$((_missing_count+1))
            if [ -n "$_missing_names" ]; then
                _missing_names="${_missing_names}, $u"
            else
                _missing_names="$u"
            fi
            log "WARN: User '$u' in $list_name does not exist on this system"
        fi
    done <<EOF
$(echo "$user_list")
EOF
    if [ $_missing_count -gt 0 ]; then
        info "$_missing_count user(s) in $list_name not found on system (normal for domain users)"
        log "Missing from $list_name: $_missing_names"
    fi
}

# Load authorized admins
if [ -f "$ADMINS_FILE" ]; then
    ADMINS=$(clean_list "$ADMINS_FILE")
    count=0; [ -n "$ADMINS" ] && count=$(echo "$ADMINS" | wc -l | tr -d ' ')
    ok "Loaded admins.txt ($count admins)"
    validate_users_exist "admins.txt" "$ADMINS"
else
    warn_ "admins.txt not found at $ADMINS_FILE"
    info "Create it with one admin username per line"
    ADMINS=""
fi

# Load authorized users
if [ -f "$USERS_FILE" ]; then
    USERS=$(clean_list "$USERS_FILE")
    count=0; [ -n "$USERS" ] && count=$(echo "$USERS" | wc -l | tr -d ' ')
    ok "Loaded users.txt ($count users)"
    validate_users_exist "users.txt" "$USERS"
else
    warn_ "users.txt not found at $USERS_FILE"
    info "Create it with one username per line"
    USERS=""
fi

# Load domain users (optional)
DOMAIN_USERS=""
if [ -f "$DOMAIN_FILE" ]; then
    DOMAIN_USERS=$(clean_list "$DOMAIN_FILE")
    count=0; [ -n "$DOMAIN_USERS" ] && count=$(echo "$DOMAIN_USERS" | wc -l | tr -d ' ')
    ok "Loaded domain_users.txt ($count domain users)"
fi

# Combined authorized list (admin + users + root)
# Root is always authorized — never flag the account you're running from
ALL_AUTHORIZED=$(printf '%s\n%s\nroot\n' "$ADMINS" "$USERS" | grep -v '^$' | sort -u)

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  1. DETECT DOMAIN JOIN                                                  ║
# ╚════════════════════════════════════════════════════════════════════════════╝
header "DOMAIN JOIN DETECTION"
info "Checks realm/SSSD/Winbind to determine if host is domain-joined."
info "Domain users need password changes from AD — not locally."

IS_DOMAIN=false
DOMAIN_NAME=""
SAMBA_DC=false

if cmd_exists realm && realm list 2>/dev/null | grep -q 'domain-name'; then
    IS_DOMAIN=true
    DOMAIN_NAME=$(realm list 2>/dev/null | grep 'domain-name' | head -1 | awk '{print $2}')
    crit "Domain-joined via realmd: $DOMAIN_NAME"
    info "Domain user passwords must be changed from AD, not locally"
elif [ -f /etc/sssd/sssd.conf ]; then
    IS_DOMAIN=true
    DOMAIN_NAME=$(grep 'domains' /etc/sssd/sssd.conf 2>/dev/null | head -1 | sed 's/.*= *//')
    crit "SSSD configured — likely domain-joined: $DOMAIN_NAME"
elif cmd_exists wbinfo && wbinfo -t 2>/dev/null | grep -q 'succeeded'; then
    IS_DOMAIN=true
    DOMAIN_NAME=$(wbinfo --own-domain 2>/dev/null)
    crit "Winbind domain trust verified: $DOMAIN_NAME"
fi

# Check if this machine IS a Samba domain controller
if cmd_exists samba-tool; then
    SAMBA_DC=true
    warn_ "samba-tool detected — this machine may be a Samba AD DC"
    info "samba-tool: Changes AD user passwords when this host is the DC"
    info "Usage: samba-tool user setpassword <username> --newpassword=<pw>"
fi

if [ "$IS_DOMAIN" = false ]; then
    ok "Not domain-joined (standalone Linux)"
fi

# ── Domain/User Helper Functions ──────────────────────────────────────────
# Defined here (after domain detection) so they're available to ALL sections

# Helper to check if user is truly a domain user
is_domain_user() {
    target_user="$1"
    
    # Check if in domain_users.txt
    if [ -n "$DOMAIN_USERS" ] && echo "$DOMAIN_USERS" | grep -qx "$target_user"; then
        return 0
    fi
    
    # If domain-joined, check if user exists in local passwd but not in shadow
    if [ "$IS_DOMAIN" = true ]; then
        # User exists in passwd
        if grep -q "^${target_user}:" /etc/passwd 2>/dev/null; then
            # But no local shadow entry (or has ! which indicates domain-only)
            if ! grep -q "^${target_user}:[^\!]" /etc/shadow 2>/dev/null; then
                return 0
            fi
        fi
        
        # Cross-check: getent pulls from all sources (NSS), passwd is local only
        if cmd_exists getent; then
            getent_result=$(getent passwd "$target_user" 2>/dev/null)
            passwd_result=$(grep "^${target_user}:" /etc/passwd 2>/dev/null)
            # If getent finds it but passwd doesn't, it's from domain
            if [ -n "$getent_result" ] && [ -z "$passwd_result" ]; then
                return 0
            fi
        fi
    fi
    
    return 1
}

# Check if user is local (has /etc/passwd entry)
is_local_user() { grep -q "^${1}:" /etc/passwd 2>/dev/null; }

# Check if user account is locked
is_user_locked() {
    if cmd_exists passwd; then
        lock_field=$(passwd -S "$1" 2>/dev/null | awk '{print $2}')
        case "$lock_field" in L|LK|*L*) return 0;; esac
    fi
    # Fallback: check shadow for ! or * prefix
    if [ -r /etc/shadow ]; then
        hash_field=$(grep "^${1}:" /etc/shadow 2>/dev/null | cut -d: -f2)
        case "$hash_field" in
            '!'*|'*'*|'!!'*) return 0;;
        esac
    fi
    return 1
}

# Show enriched context for a user (source, lock status, services, ports, procs)
show_user_context() {
    _suc_user="$1"
    # Source detection
    if is_local_user "$_suc_user"; then _src="LOCAL"; else _src="DOMAIN"; fi
    # Lock status
    if is_user_locked "$_suc_user"; then _lock="LOCKED"; else _lock="ACTIVE"; fi
    # Shell (use getent to cover both local and domain)
    _shell=$(getent passwd "$_suc_user" 2>/dev/null | cut -d: -f7)
    [ -z "$_shell" ] && _shell=$(grep "^${_suc_user}:" /etc/passwd 2>/dev/null | cut -d: -f7)
    [ -z "$_shell" ] && _shell="(none)"
    _uid=$(id -u "$_suc_user" 2>/dev/null)

    printf "${R}      %-15s UID:%-6s Source:%-7s Status:%-8s Shell:%s${N}\n" \
        "$_suc_user" "$_uid" "$_src" "$_lock" "$_shell"

    # Processes
    _procs=$(ps -u "$_suc_user" -o comm= 2>/dev/null | sort -u | tr '\n' ', ' | sed 's/,$//')
    _pcount=$(ps -u "$_suc_user" -o pid= 2>/dev/null | wc -l | tr -d ' ')
    if [ "$_pcount" -gt 0 ] 2>/dev/null; then
        printf "      Processes (%s): %s\n" "$_pcount" "$_procs"
    fi

    # Systemd services owned/related to this user
    if cmd_exists systemctl; then
        _svcs=$(systemctl list-units --type=service --all --no-pager 2>/dev/null | grep -i "$_suc_user" | awk '{print $1}' | tr '\n' ', ' | sed 's/,$//')
        [ -n "$_svcs" ] && printf "${Y}      Services: %s${N}\n" "$_svcs"
    fi

    # Listening ports (cross-reference user's PIDs against ss/netstat output)
    _user_pids=$(ps -u "$_suc_user" -o pid= 2>/dev/null | tr -s ' \n' '|' | sed 's/^|//;s/|$//')
    if [ -n "$_user_pids" ]; then
        if cmd_exists ss; then
            _ports=$(ss -tlnp 2>/dev/null | grep -E "pid=($_user_pids)[^0-9]" | awk '{print $4}' | tr '\n' ', ' | sed 's/,$//')
            [ -n "$_ports" ] && printf "${Y}      Listening Ports: %s${N}\n" "$_ports"
        elif cmd_exists netstat; then
            _ports=$(netstat -tlnp 2>/dev/null | grep -E "($_user_pids)/" | awk '{print $4}' | tr '\n' ', ' | sed 's/,$//')
            [ -n "$_ports" ] && printf "${Y}      Listening Ports: %s${N}\n" "$_ports"
        fi

        # Active network connections
        if cmd_exists ss; then
            _conns=$(ss -tunp 2>/dev/null | grep -E "pid=($_user_pids)[^0-9]" | grep -c "ESTAB" 2>/dev/null)
            [ "$_conns" -gt 0 ] 2>/dev/null && printf "${Y}      Active Connections: %s${N}\n" "$_conns"
        fi
    fi
}

# Block a domain-sourced user from logging in (realm → SSSD → access.conf)
block_domain_user() {
    _bdu_target="$1"
    
    # Method 1: realm deny (cleanest, reversible)
    if cmd_exists realm; then
        if realm deny "$_bdu_target" 2>/dev/null; then
            ok "Blocked $_bdu_target via realm deny"
            log "DOMAIN-BLOCK: $_bdu_target (realm deny)"
            return 0
        fi
    fi
    
    # Method 2: SSSD simple_deny_users
    if [ -f /etc/sssd/sssd.conf ]; then
        backup_file /etc/sssd/sssd.conf
        _current_deny=$(grep 'simple_deny_users' /etc/sssd/sssd.conf 2>/dev/null | head -1 | sed 's/.*= *//')
        if [ -n "$_current_deny" ]; then
            sed -i "s/simple_deny_users.*/simple_deny_users = ${_current_deny}, ${_bdu_target}/" /etc/sssd/sssd.conf 2>/dev/null
        else
            sed -i "/^\[domain/a access_provider = simple" /etc/sssd/sssd.conf 2>/dev/null
            sed -i "/access_provider = simple/a simple_deny_users = ${_bdu_target}" /etc/sssd/sssd.conf 2>/dev/null
        fi
        systemctl restart sssd 2>/dev/null
        ok "Blocked $_bdu_target via SSSD deny list"
        log "DOMAIN-BLOCK: $_bdu_target (sssd.conf)"
        return 0
    fi
    
    # Method 3: /etc/security/access.conf (last resort)
    if [ -f /etc/security/access.conf ]; then
        backup_file /etc/security/access.conf
        echo "- : $_bdu_target : ALL" >> /etc/security/access.conf
        warn_ "Blocked $_bdu_target via access.conf (ensure pam_access.so is enabled in PAM)"
        log "DOMAIN-BLOCK: $_bdu_target (access.conf)"
        return 0
    fi
    
    warn_ "Could not block $_bdu_target — no realm, SSSD, or access.conf available"
    return 1
}

# Unblock/enable a domain-sourced user
unblock_domain_user() {
    _udu_target="$1"
    
    # Try realm permit
    if cmd_exists realm; then
        realm permit "$_udu_target" 2>/dev/null && {
            ok "Unblocked $_udu_target via realm permit"
            log "DOMAIN-UNBLOCK: $_udu_target (realm permit)"
            return 0
        }
    fi
    
    # Try removing from SSSD deny list
    if [ -f /etc/sssd/sssd.conf ] && grep -q "$_udu_target" /etc/sssd/sssd.conf 2>/dev/null; then
        backup_file /etc/sssd/sssd.conf
        sed -i "s/, *${_udu_target}//;s/${_udu_target}, *//" /etc/sssd/sssd.conf 2>/dev/null
        systemctl restart sssd 2>/dev/null
        ok "Removed $_udu_target from SSSD deny list"
        log "DOMAIN-UNBLOCK: $_udu_target (sssd.conf)"
        return 0
    fi
    
    # Try removing from access.conf
    if [ -f /etc/security/access.conf ] && grep -q "$_udu_target" /etc/security/access.conf 2>/dev/null; then
        backup_file /etc/security/access.conf
        sed -i "/^- : ${_udu_target} : ALL$/d" /etc/security/access.conf 2>/dev/null
        ok "Removed $_udu_target from access.conf"
        log "DOMAIN-UNBLOCK: $_udu_target (access.conf)"
        return 0
    fi
    
    warn_ "Could not find block entry for $_udu_target to remove"
    return 1
}

# ─────────────────────────────────────────────────────────────────────────────

# If passwords-only mode, skip directly to password rotation section
if [ "$PASSWORDS_ONLY" = true ]; then
    info "Skipping audit/snapshot steps (passwords-only mode)..."
else

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  2. SNAPSHOT & DIFF (re-run tracking)                                   ║
# ╚════════════════════════════════════════════════════════════════════════════╝
header "CHANGE TRACKING"
info "Compares current users against the last run to detect new/removed accounts."
info "If something changed: investigate immediately — Red Team may have added users."

# Current snapshot: username:uid:shell:groups
current_snap() {
    awk -F: '($3==0 || $3>=1000) && $1!="nobody" && $1!="nfsnobody" && $1!="nogroup" {
        printf "%s:%s:%s\n", $1, $3, $7
    }' /etc/passwd 2>/dev/null | sort
}

CURRENT_SNAP=$(current_snap)

# Save first snapshot if it doesn't exist
if [ ! -f "$FIRST_SNAPSHOT" ]; then
    echo "$CURRENT_SNAP" > "$FIRST_SNAPSHOT"
    chmod 600 "$FIRST_SNAPSHOT" 2>/dev/null
    info "First run — baseline snapshot created"
fi

if [ -f "$SNAPSHOT" ]; then
    info "Previous snapshot found: $SNAPSHOT"
    OLD_SNAP=$(cat "$SNAPSHOT")

    # New users since last run
    NEW_USERS=$(echo "$CURRENT_SNAP" | while read -r line; do
        u=$(echo "$line" | cut -d: -f1)
        echo "$OLD_SNAP" | grep -q "^${u}:" || echo "$u"
    done)

    # Removed users since last run
    GONE_USERS=$(echo "$OLD_SNAP" | while read -r line; do
        u=$(echo "$line" | cut -d: -f1)
        echo "$CURRENT_SNAP" | grep -q "^${u}:" || echo "$u"
    done)

    # Shell changes
    SHELL_CHANGES=$(echo "$CURRENT_SNAP" | while read -r line; do
        u=$(echo "$line" | cut -d: -f1)
        new_shell=$(echo "$line" | cut -d: -f3)
        old_line=$(echo "$OLD_SNAP" | grep "^${u}:")
        if [ -n "$old_line" ]; then
            old_shell=$(echo "$old_line" | cut -d: -f3)
            if [ "$old_shell" != "$new_shell" ]; then
                echo "$u: $old_shell → $new_shell"
            fi
        fi
    done)

    if [ -n "$NEW_USERS" ]; then
        crit "NEW users since last run:"
        echo "$NEW_USERS" | indent
    fi
    if [ -n "$GONE_USERS" ]; then
        warn_ "REMOVED users since last run:"
        echo "$GONE_USERS" | indent
    fi
    if [ -n "$SHELL_CHANGES" ]; then
        warn_ "SHELL CHANGES since last run:"
        echo "$SHELL_CHANGES" | indent
    fi
    if [ -z "$NEW_USERS" ] && [ -z "$GONE_USERS" ] && [ -z "$SHELL_CHANGES" ]; then
        ok "No user changes since last run"
    fi
    
    # Optionally compare against first snapshot
    if [ -f "$FIRST_SNAPSHOT" ]; then
        FIRST_SNAP=$(cat "$FIRST_SNAPSHOT")
        
        # New users since first run
        NEW_SINCE_FIRST=$(echo "$CURRENT_SNAP" | while read -r line; do
            u=$(echo "$line" | cut -d: -f1)
            echo "$FIRST_SNAP" | grep -q "^${u}:" || echo "$u"
        done)
        
        # Removed users since first run
        GONE_SINCE_FIRST=$(echo "$FIRST_SNAP" | while read -r line; do
            u=$(echo "$line" | cut -d: -f1)
            echo "$CURRENT_SNAP" | grep -q "^${u}:" || echo "$u"
        done)
        
        if [ -n "$NEW_SINCE_FIRST" ] || [ -n "$GONE_SINCE_FIRST" ]; then
            echo ""
            info "Changes since FIRST run (baseline):"
            if [ -n "$NEW_SINCE_FIRST" ]; then
                warn_ "NEW users since first run:"
                echo "$NEW_SINCE_FIRST" | indent
            fi
            if [ -n "$GONE_SINCE_FIRST" ]; then
                info "REMOVED users since first run:"
                echo "$GONE_SINCE_FIRST" | indent
            fi
        fi
    fi
else
    info "First run — no previous snapshot (will create one)"
fi

# ── kill_user_procs — Kill processes for a user with IR evidence capture ──
kill_user_procs() {
    target_user="$1"
    if is_excluded_user "$target_user"; then
        warn_ "Skipping process kill for $target_user (Excluded)"
        return
    fi
    
    # Check for excluded process names
    if [ -n "$EXCLUDED_PROCS" ]; then
        running_excluded=$(ps -u "$target_user" -o comm= 2>/dev/null | grep -E "$(echo $EXCLUDED_PROCS | tr ' ' '|')")
        if [ -n "$running_excluded" ]; then
            warn_ "User $target_user is running excluded processes: $running_excluded"
            if ! confirm "Kill anyway?"; then return; fi
        fi
    fi

    pcount=$(ps -u "$target_user" -o pid= 2>/dev/null | wc -l | tr -d ' ')
    
    if [ "$pcount" -gt 0 ] 2>/dev/null; then
        # IR: Capture Evidence
        evidence_file="$REPORT_DIR/ir_evidence/${target_user}_$(date +%H%M%S).txt"
        echo "Evidence for user $target_user captured at $(date)" > "$evidence_file"
        echo "------------------------------------------------" >> "$evidence_file"
        echo "PROCESSES:" >> "$evidence_file"
        ps -u "$target_user" -o pid,ppid,user,stat,start,time,cmd >> "$evidence_file" 2>/dev/null
        echo "" >> "$evidence_file"
        echo "NETWORK:" >> "$evidence_file"
        if cmd_exists ss; then ss -tunp | grep "$target_user" >> "$evidence_file" 2>/dev/null
        elif cmd_exists netstat; then netstat -tunp | grep "$target_user" >> "$evidence_file" 2>/dev/null; fi
        
        net_count=$(grep -c "ESTAB" "$evidence_file")
        
        if confirm "Found $pcount processes and $net_count active connections used by $target_user. Kill them?"; then
            info "Killing processes... (Evidence saved to $evidence_file)"

            # Try SIGTERM first
            pkill -TERM -u "$target_user" 2>/dev/null
            sleep 2
            
            # Then SIGKILL for survivors
            pkill -KILL -u "$target_user" 2>/dev/null
            sleep 1
            
            # Check for systemd services owned by this user
            if cmd_exists systemctl; then
                user_services=$(systemctl list-units --all --no-pager 2>/dev/null | grep -i "$target_user" | awk '{print $1}')
                if [ -n "$user_services" ]; then
                    warn_ "Found systemd services related to $target_user:"
                    echo "$user_services" | indent
                    if confirm "Stop and disable these services?"; then
                        echo "$user_services" | while read -r svc; do
                            systemctl stop "$svc" 2>/dev/null
                            systemctl disable "$svc" 2>/dev/null
                        done
                    fi
                fi
            fi
            
            # Final check
            remain=$(ps -u "$target_user" -o pid= 2>/dev/null | wc -l | tr -d ' ')
            if [ "$remain" -gt 0 ] 2>/dev/null; then
                warn_ "Still $remain process(es) running for $target_user"
                ps -u "$target_user" -o pid=,comm= 2>/dev/null | indent
                fix "kill -9 \$(ps -u $target_user -o pid=)"
            else
                ok "Killed all processes for $target_user"
            fi
        else
            warn_ "Skipped killing processes — $target_user may still have active sessions"
        fi
    fi
}

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  3. ENUMERATE & COMPARE                                                 ║
# ╚════════════════════════════════════════════════════════════════════════════╝
header "USER COMPARISON"
info "Cross-references system users against admins.txt + users.txt."
info "Unauthorized users should be locked/removed. Missing users may need creation."

# Get all real users (UID >= 1000 + root)
SYSTEM_USERS=$(awk -F: '($3==0 || $3>=1000) && $1!="nobody" && $1!="nfsnobody" && $1!="nogroup" {print $1}' /etc/passwd 2>/dev/null | sort)

if [ -z "$ALL_AUTHORIZED" ]; then
    warn_ "No authorized lists loaded — listing all users for manual review"
    echo "$SYSTEM_USERS" | indent
else
    # Expected & present
    PRESENT=$(echo "$ALL_AUTHORIZED" | while read -r u; do
        [ -z "$u" ] && continue
        echo "$SYSTEM_USERS" | grep -qx "$u" && echo "$u"
    done)

    # Missing (authorized but not on system)
    MISSING=$(echo "$ALL_AUTHORIZED" | while read -r u; do
        [ -z "$u" ] && continue
        echo "$SYSTEM_USERS" | grep -qx "$u" || echo "$u"
    done)

    # Unauthorized (on system but not in lists)
    UNAUTHORIZED=$(echo "$SYSTEM_USERS" | while read -r u; do
        [ -z "$u" ] && continue
        echo "$ALL_AUTHORIZED" | grep -qx "$u" || echo "$u"
    done)

    # Present users
    if [ -n "$PRESENT" ]; then
        _present_count=$(echo "$PRESENT" | wc -l | tr -d ' ')
        _present_names=$(echo "$PRESENT" | tr '\n' ', ' | sed 's/,$//')
        ok "$_present_count authorized user(s) present: $_present_names"
    fi

    # Missing users
    if [ -n "$MISSING" ]; then
        _missing_count=$(echo "$MISSING" | wc -l | tr -d ' ')
        _missing_names=$(echo "$MISSING" | tr '\n' ',' | sed 's/,/, /g;s/, $//')
        warn_ "$_missing_count authorized user(s) MISSING from system"
        info "Missing: $_missing_names"
        log "Missing users: $_missing_names"
        if [ "$AUDIT_ONLY" = false ]; then
            echo "$MISSING" | while read -r u; do
                [ -z "$u" ] && continue
                if confirm "Create missing user $u?"; then
                    critical_operation useradd -m -s /bin/bash "$u" 2>/dev/null
                    ok "Created $u"
                    add_fixed
                else skip "create $u"; fi
            done
        fi
    fi

    # Unauthorized users
    if [ -n "$UNAUTHORIZED" ]; then
        crit "UNAUTHORIZED users (not in admins.txt or users.txt):"
        echo "$UNAUTHORIZED" | while read -r u; do
            [ -z "$u" ] && continue
            
            if is_excluded_user "$u"; then
                printf "${C}      [SKIPPED] %s (Globally Excluded)${N}\n" "$u"
                continue
            fi
            
            # Enriched context display
            show_user_context "$u"

            if [ "$AUDIT_ONLY" = false ]; then
                # Different menu depending on user source
                if is_local_user "$u"; then
                    printf "${Y}  [?] [L]ock / [D]isable shell / [R]emove / [E]nable / [S]kip (%s): ${N}" "$u"
                    read -r action < /dev/tty
                    action=${action:-S}
                else
                    printf "${C}      ↳ Domain-sourced user — local usermod won't work${N}\n"
                    printf "${Y}  [?] [B]lock (realm/SSSD) / [K]ill processes / [E]nable (unblock) / [S]kip (%s): ${N}" "$u"
                    read -r action < /dev/tty
                    action=${action:-S}
                fi

                case "$action" in
                    # ── Local user actions ──
                    l|L)
                        if ! is_local_user "$u"; then
                            warn_ "Cannot lock $u with usermod — not a local user"
                            info "Use [B]lock instead to deny via realm/SSSD"
                        else
                            kill_user_procs "$u"
                            critical_operation usermod -L "$u" 2>/dev/null
                            ok "Locked $u"
                            log "LOCKED: $u"
                        fi
                        ;;
                    d|D)
                        if ! is_local_user "$u"; then
                            warn_ "Cannot change shell for $u — not a local user"
                        else
                            kill_user_procs "$u"
                            backup_file "/etc/passwd"
                            critical_operation usermod -s /usr/sbin/nologin "$u" 2>/dev/null
                            ok "Disabled shell for $u"
                        fi
                        ;;
                    r|R)
                        if ! is_local_user "$u"; then
                            warn_ "Cannot userdel $u — not a local user. Use [B]lock instead."
                        else
                            kill_user_procs "$u"
                            hd=$(getent passwd "$u" 2>/dev/null | cut -d: -f6)
                            if [ -d "$hd" ]; then
                                cp -a "$hd" "$BACKUP_DIR/home_${u}" 2>/dev/null
                                info "Home dir backed up to $BACKUP_DIR/home_${u}"
                            fi
                            critical_operation userdel "$u" 2>/dev/null
                            ok "Removed $u (home preserved in backup)"
                        fi
                        ;;
                    # ── Domain user actions ──
                    b|B)
                        kill_user_procs "$u"
                        block_domain_user "$u"
                        ;;
                    k|K)
                        kill_user_procs "$u"
                        ;;
                    # ── Enable/Unlock (works for both) ──
                    e|E)
                        if is_local_user "$u"; then
                            critical_operation usermod -U "$u" 2>/dev/null
                            ok "Unlocked local account $u"
                            # Check if shell needs fixing too
                            _curr_sh=$(grep "^${u}:" /etc/passwd 2>/dev/null | cut -d: -f7)
                            if echo "$_curr_sh" | grep -Eq 'nologin|false|^$'; then
                                if confirm "  Shell is $_curr_sh — set to /bin/bash?"; then
                                    critical_operation usermod -s /bin/bash "$u" 2>/dev/null
                                    ok "Shell restored for $u"
                                fi
                            fi
                        else
                            unblock_domain_user "$u"
                        fi
                        log "ENABLED: $u"
                        ;;
                    *)
                        skip "$u"
                        ;;
                esac
            else
                # Audit-only mode: show fix suggestions
                _pcount=$(ps -u "$u" -o pid= 2>/dev/null | wc -l | tr -d ' ')
                if [ "$_pcount" -gt 0 ] 2>/dev/null; then
                    if is_local_user "$u"; then
                        fix "usermod -L $u  OR  userdel $u"
                    else
                        fix "realm deny $u  OR  edit /etc/sssd/sssd.conf"
                    fi
                    fix "pkill -KILL -u $u"
                fi
            fi
        done
    else
        ok "No unauthorized users found"
    fi
fi

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  4. ADMIN GROUP AUDIT                                                   ║
# ╚════════════════════════════════════════════════════════════════════════════╝
header "ADMIN GROUP AUDIT"
info "Verifies sudo/wheel group matches admins.txt. Checks sudoers for NOPASSWD."
info "Also audits docker/lxd/lxc groups (root-equivalent access)."

# Detect sudo/wheel group
ADMIN_GROUP=""
if grep -q '^sudo:' /etc/group 2>/dev/null; then ADMIN_GROUP="sudo"
elif grep -q '^wheel:' /etc/group 2>/dev/null; then ADMIN_GROUP="wheel"
fi

if [ -n "$ADMIN_GROUP" ]; then
    ACTUAL_ADMINS=$(grep "^${ADMIN_GROUP}:" /etc/group 2>/dev/null | cut -d: -f4 | tr ',' '\n' | grep -v '^$' | sort)
    # Also check users with primary group = admin group
    admin_gid=$(grep "^${ADMIN_GROUP}:" /etc/group 2>/dev/null | cut -d: -f3)
    PRIMARY_ADMINS=$(awk -F: -v gid="$admin_gid" '$4==gid {print $1}' /etc/passwd 2>/dev/null)
    ACTUAL_ADMINS=$(printf '%s\n%s' "$ACTUAL_ADMINS" "$PRIMARY_ADMINS" | grep -v '^$' | sort -u)

    info "Users in $ADMIN_GROUP group: $(echo "$ACTUAL_ADMINS" | tr '\n' ' ')"

    if [ -n "$ADMINS" ]; then
        # Users in admin group but NOT in admins.txt
        echo "$ACTUAL_ADMINS" | while read -r u; do
            [ -z "$u" ] && continue
            if ! echo "$ADMINS" | grep -qx "$u"; then
                crit "$u is in $ADMIN_GROUP but NOT in admins.txt"
                if [ "$AUDIT_ONLY" = false ]; then
                    if confirm "Remove $u from $ADMIN_GROUP group?"; then
                        critical_operation gpasswd -d "$u" "$ADMIN_GROUP" 2>/dev/null || critical_operation deluser "$u" "$ADMIN_GROUP" 2>/dev/null
                        ok "Removed $u from $ADMIN_GROUP"
                        add_fixed
                    else skip "admin removal for $u"; add_skipped; fi
                fi
            fi
        done

        # Users in admins.txt but NOT in admin group
        echo "$ADMINS" | while read -r u; do
            [ -z "$u" ] && continue
            if ! echo "$ACTUAL_ADMINS" | grep -qx "$u"; then
                warn_ "$u is in admins.txt but NOT in $ADMIN_GROUP group"
                if [ "$AUDIT_ONLY" = false ]; then
                    if confirm "Add $u to $ADMIN_GROUP?"; then
                        critical_operation usermod -aG "$ADMIN_GROUP" "$u" 2>/dev/null
                        ok "Added $u to $ADMIN_GROUP"
                        add_fixed
                    else skip "admin add for $u"; add_skipped; fi
                fi
            fi
        done
    fi

    # Main /etc/sudoers check
    if [ -f /etc/sudoers ]; then
        if grep -q 'NOPASSWD\|!authenticate' /etc/sudoers 2>/dev/null; then
            crit "Dangerous entries in /etc/sudoers (main file):"
            grep -n 'NOPASSWD\|!authenticate' /etc/sudoers 2>/dev/null | grep -v '^[0-9]*:[[:space:]]*#' | indent
            if [ "$AUDIT_ONLY" = false ]; then
                if confirm "Remove NOPASSWD entries from /etc/sudoers?"; then
                    backup_file /etc/sudoers
                    safe_chattr -i /etc/sudoers
                    sed -i 's/NOPASSWD:/PASSWD:/g' /etc/sudoers 2>/dev/null
                    sed -i 's/!authenticate/authenticate/g' /etc/sudoers 2>/dev/null
                    ok "Removed NOPASSWD from /etc/sudoers"
                    safe_chattr +i /etc/sudoers
                    add_fixed
                fi
            fi
        fi
    fi

    # Sudoers.d check with remediation
    if [ -d /etc/sudoers.d ]; then
        for f in /etc/sudoers.d/*; do
            [ -f "$f" ] || continue
            if grep -q 'NOPASSWD\|!authenticate' "$f" 2>/dev/null; then
                crit "Dangerous sudoers file: $f"
                cat "$f" 2>/dev/null | indent
                if [ "$AUDIT_ONLY" = false ]; then
                    if confirm "Remove or disable NOPASSWD entries in $f?"; then
                        backup_file "$f"
                        safe_chattr -i "$f"
                        sed -i 's/NOPASSWD:/PASSWD:/g' "$f" 2>/dev/null
                        sed -i 's/!authenticate/authenticate/g' "$f" 2>/dev/null
                        ok "Removed NOPASSWD from $f"
                        safe_chattr +i "$f"
                        add_fixed
                    fi
                fi
            fi
        done
    fi
else
    warn_ "No sudo/wheel group found"
fi

# ── Docker / LXD Group Check (root-equivalent access) ──
for priv_group in docker lxd lxc; do
    if grep -q "^${priv_group}:" /etc/group 2>/dev/null; then
        priv_members=$(grep "^${priv_group}:" /etc/group 2>/dev/null | cut -d: -f4 | tr ',' '\n' | grep -v '^$')
        # Also check primary group membership
        priv_gid=$(grep "^${priv_group}:" /etc/group 2>/dev/null | cut -d: -f3)
        priv_primary=$(awk -F: -v gid="$priv_gid" '$4==gid {print $1}' /etc/passwd 2>/dev/null)
        priv_all=$(printf '%s\n%s' "$priv_members" "$priv_primary" | grep -v '^$' | sort -u)
        
        if [ -n "$priv_all" ]; then
            crit "Users in '$priv_group' group (ROOT-EQUIVALENT access):"
            echo "$priv_all" | while read -r pu; do
                [ -z "$pu" ] && continue
                _is_auth=""
                if [ -n "$ALL_AUTHORIZED" ]; then
                    echo "$ALL_AUTHORIZED" | grep -qx "$pu" || _is_auth=" [UNAUTHORIZED]"
                fi
                printf "      %s%s\n" "$pu" "$_is_auth"
            done
            if [ "$AUDIT_ONLY" = false ]; then
                echo "$priv_all" | while read -r pu; do
                    [ -z "$pu" ] && continue
                    if [ -n "$ADMINS" ] && echo "$ADMINS" | grep -qx "$pu"; then
                        continue  # Skip authorized admins
                    fi
                    if confirm "Remove $pu from $priv_group group?"; then
                        critical_operation gpasswd -d "$pu" "$priv_group" 2>/dev/null || critical_operation deluser "$pu" "$priv_group" 2>/dev/null
                        ok "Removed $pu from $priv_group"
                    fi
                done
            fi
        fi
    fi
done

# End audit/snapshot section
fi

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  5. PASSWORD ROTATION                                                   ║
# ╚════════════════════════════════════════════════════════════════════════════╝
header "PASSWORD ROTATION"
info "Rotates passwords for root, admins, and standard users separately."
info "Domain users are skipped — change those from the AD/DC."

rotate_passwords() {
    target_group="$1"
    prompt_msg="$2"
    user_list="$3" # Space-separated list of users to rotate

    if [ -z "$user_list" ]; then
        info "No users found for group: $target_group"
        return
    fi
    
    echo ""
    if confirm "Rotate passwords for $target_group?"; then
        # Ask for password twice to confirm
        while true; do
            printf "${Y}${B}  Enter NEW password for $target_group: ${N}"
            stty -echo 2>/dev/null
            read -r NEWPW
            stty echo 2>/dev/null
            echo ""
            
            if [ -z "$NEWPW" ]; then
                warn_ "Password cannot be empty!"
                continue
            fi
            
            printf "${Y}${B}  Confirm password for $target_group: ${N}"
            stty -echo 2>/dev/null
            read -r NEWPW_CONFIRM
            stty echo 2>/dev/null
            echo ""
            
            if [ "$NEWPW" = "$NEWPW_CONFIRM" ]; then
                ok "Passwords match"
                break
            else
                warn_ "Passwords do NOT match! Try again."
            fi
        done
        
        for user in $user_list; do
            # Skip domain/excluded checks
            if is_domain_user "$user"; then
                warn_ "SKIPPED $user — domain user (change from AD/DC)"
                continue
            fi
            
            if is_excluded_user "$user"; then
                warn_ "SKIPPING password rotation for $user (Globally Excluded)"
                continue
            fi

            # Save lock state before unlocking
            _was_locked=false
            is_user_locked "$user" && _was_locked=true

            # Unlock user before password change (in case locked)
            safe_chattr -i /etc/shadow
            usermod -U "$user" 2>/dev/null
            
            # Set password
            if echo "${user}:${NEWPW}" | chpasswd 2>/dev/null; then
                ok "Password set for $user"
            else
                warn_ "Failed to set password for $user"
            fi

            # Restore lock state if user was previously locked
            if [ "$_was_locked" = true ]; then
                usermod -L "$user" 2>/dev/null
                info "Re-locked $user (was locked before rotation)"
            fi
            
            # Re-lock shadow
            safe_chattr +i /etc/shadow
        done
    else
        skip "Rotation for $target_group"
    fi
}

if [ "$AUDIT_ONLY" = true ]; then
    info "Skipping password rotation (audit-only mode)"
else
    # ── 1. ROOT ROTATION ──
    rotate_passwords "ROOT" "root" "root"

    # ── 2. ADMINS ROTATION ──
    # Filter admins.txt to find local users who are NOT root
    if [ -n "$ADMINS" ]; then
        LOCAL_ADMINS=""
        for u in $ADMINS; do
            [ "$u" = "root" ] && continue
            if id "$u" >/dev/null 2>&1; then
                LOCAL_ADMINS="$LOCAL_ADMINS $u"
            fi
        done
        rotate_passwords "ADMINS (admins.txt)" "admins" "$LOCAL_ADMINS"
    fi

    # ── 3. STANDARD USERS ROTATION ──
    # Only rotate for users in users.txt who are NOT in admins.txt
    STANDARD_USERS=""
    if [ -n "$USERS" ]; then
        for u in $USERS; do
            # If user is in ADMINS, skip (already handled)
            echo "$ADMINS" | grep -qx "$u" && continue
            # Only include if user actually exists on the system
            id "$u" >/dev/null 2>&1 && STANDARD_USERS="$STANDARD_USERS $u"
        done
    fi
    rotate_passwords "STANDARD USERS" "users" "$STANDARD_USERS"

    # Samba DC password option
    if [ "$SAMBA_DC" = true ]; then
        echo ""
        warn_ "This host has samba-tool — domain password changes available"
        if [ -n "$DOMAIN_USERS" ]; then
            if confirm "Set domain user passwords via samba-tool?"; then
                 printf "${Y}${B}  Enter NEW domain password: ${N}"
                 stty -echo 2>/dev/null
                 read -r DOMAINPW
                 stty echo 2>/dev/null
                 echo ""
                 if [ -n "$DOMAINPW" ]; then
                     echo "$DOMAIN_USERS" | while read -r user; do
                         [ -z "$user" ] && continue
                         if samba-tool user setpassword "$user" --newpassword="$DOMAINPW" 2>/dev/null; then
                             ok "Domain password set: $user (via samba-tool)"
                         else
                             warn_ "Failed to set domain password for $user"
                         fi
                     done
                 fi
            else skip "samba-tool domain passwords"; fi
        else
            info "No domain_users.txt found — create it to use this feature"
        fi
    fi
    
    # ── SCORING ENGINE REMINDER ──
    echo ""
    printf "${R}${B}  ╔══════════════════════════════════════════════════════════╗${N}\n"
    printf "${R}${B}  ║  ⚠  SCORING ENGINE: UPDATE PASSWORD NOW!               ║${N}\n"
    printf "${R}${B}  ║  Update the scoring engine portal with the new         ║${N}\n"
    printf "${R}${B}  ║  passwords for any scored service accounts.            ║${N}\n"
    printf "${R}${B}  ║  DO NOT save them to a file on this machine.           ║${N}\n"
    printf "${R}${B}  ╚══════════════════════════════════════════════════════════╝${N}\n"
    echo ""
fi

# If running in --passwords-only mode, exit here
if [ "$PASSWORDS_ONLY" = true ]; then
    ok "Password rotation complete. Exiting."
    exit 0
fi

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  6. PER-USER SECURITY AUDIT                                             ║
# ╚════════════════════════════════════════════════════════════════════════════╝
header "PER-USER SECURITY AUDIT"
info "Checks SSH keys, bashrc backdoors, suspicious aliases, and .rhosts/.netrc."
info "If backdoors found: remove the lines, then investigate how they got there."

SUS_PATTERN='curl \|wget \|nc \|ncat \|socat \|python.*-c\|perl.*-e\|ruby.*-e\|bash.*-i\|/dev/tcp/\|mkfifo\|base64.*-d\|chmod.*+s\|/dev/shm/'

for hd in /root /home/*; do
    [ -d "$hd" ] || continue
    u=$(basename "$hd"); [ "$hd" = "/root" ] && u="root"

    # Audit all users — unauthorized users' home dirs may contain backdoors too

    # Collect all findings for this user first
    findings=""

    # 6a. SSH authorized_keys - enhanced validation
    ak="$hd/.ssh/authorized_keys"
    if [ -f "$ak" ] && [ -s "$ak" ]; then
        kc=$(wc -l < "$ak" 2>/dev/null | tr -d ' ')
        findings="${findings}KEY:${kc} SSH key(s)\n"
        
        # Check for restricted keys
        restricted=$(grep -E 'command=|from=|permitopen=|tunnel=' "$ak" 2>/dev/null)
        if [ -n "$restricted" ]; then
            findings="${findings}KEY-RESTRICT:Restricted key options found:\n$(echo "$restricted" | sed 's/^/      /')\n"
        fi
        
        keys=$(awk '{print "      " $1 " " $NF}' "$ak" 2>/dev/null)
        findings="${findings}${keys}\n"
    fi

    # 6b. Shell RC backdoors (only suspicious patterns, not general content)
    for rc in .bashrc .bash_profile .profile .zshrc .bash_login; do
        f="$hd/$rc"; [ -f "$f" ] || continue
        sus=$(grep -n "$SUS_PATTERN" "$f" 2>/dev/null | grep -v '^[0-9]*:[[:space:]]*#')
        if [ -n "$sus" ]; then
            findings="${findings}RC:Backdoor in $rc:\n$(echo "$sus" | sed 's/^/      /')\n"
        fi
    done



    # 6e. Alias backdoors - enhanced detection
    SUS_ALIAS='alias ls=\|alias sudo=\|alias su=\|alias ssh=\|alias passwd=\|alias cat=\|alias rm=\|alias id=\|alias ps=\|alias who=\|alias w=\|alias netstat=\|alias ss=\|alias iptables=\|alias curl=\|alias wget=\|alias cp=\|alias mv=\|alias kill=\|alias mount=\|alias chattr=\|alias chmod=\|alias chown=\|alias crontab=\|alias systemctl=\|alias service='
    for rc in .bashrc .bash_aliases .bash_profile .profile .zshrc; do
        f="$hd/$rc"; [ -f "$f" ] || continue
        
        # Check for system command overrides
        sus_aliases=$(grep -n "$SUS_ALIAS" "$f" 2>/dev/null | grep -v '^[0-9]*:[[:space:]]*#' | grep -v "alias ls='ls --color=auto'")
        if [ -n "$sus_aliases" ]; then
            findings="${findings}ALIAS:Suspicious aliases in $rc:\n$(echo "$sus_aliases" | sed 's/^/      /')\n"
        fi
        
        # Check for network/encoding in any alias
        net_aliases=$(grep -n 'alias.*=.*' "$f" 2>/dev/null | grep -v '^[0-9]*:[[:space:]]*#' | grep -E '/dev/tcp|curl |wget |nc |ncat |base64|python.*-c|perl.*-e|eval ')
        if [ -n "$net_aliases" ]; then
            findings="${findings}ALIAS:Backdoor aliases in $rc:\n$(echo "$net_aliases" | sed 's/^/      /')\n"
        fi
    done

    # 6f. Check for .rhosts and .netrc (dangerous legacy files)
    for dangerous_file in .rhosts .netrc; do
        df="$hd/$dangerous_file"
        if [ -f "$df" ]; then
            findings="${findings}DANGER:Legacy auth file found: $dangerous_file\n$(cat "$df" 2>/dev/null | sed 's/^/      /')\n"
        fi
    done

    # Print user summary
    if [ -n "$findings" ]; then
        # User has findings — show them
        crit "Issues for $u:"

        # Process findings and offer remediation
        echo "$findings" | while IFS= read -r line; do
            [ -z "$line" ] && continue
            case "$line" in
                KEY:*)
                    printf "${R}      %s${N}\n" "$(echo "$line" | sed 's/^KEY://')"
                    ;;
                KEY-RESTRICT:*)
                    printf "${Y}      %s${N}\n" "$(echo "$line" | sed 's/^KEY-RESTRICT://')"
                    ;;
                RC:*)
                    printf "${R}      %s${N}\n" "$(echo "$line" | sed 's/^RC://')"
                    ;;

                ALIAS:*)
                    printf "${R}      %s${N}\n" "$(echo "$line" | sed 's/^ALIAS://')"
                    ;;
                DANGER:*)
                    printf "${R}${B}      %s${N}\n" "$(echo "$line" | sed 's/^DANGER://')"
                    ;;
                *)
                    printf "%s\n" "$line"
                    ;;
            esac
        done

        # Remediation options
        if [ "$AUDIT_ONLY" = false ]; then
            # SSH keys
            if [ -f "$ak" ] && [ -s "$ak" ]; then
                if confirm "Remove ALL SSH keys for $u?"; then
                    backup_file "$ak"
                    : > "$ak"
                    ok "Cleared SSH keys for $u"
                    add_fixed
                else skip "SSH keys for $u"; fi
            fi

            # Bashrc backdoors
            for rc in .bashrc .bash_profile .profile .zshrc .bash_login; do
                f="$hd/$rc"; [ -f "$f" ] || continue
                sus=$(grep -n "$SUS_PATTERN" "$f" 2>/dev/null | grep -v '^[0-9]*:[[:space:]]*#')
                if [ -n "$sus" ]; then
                    if confirm "Remove backdoor lines from $u's $rc?"; then
                        backup_file "$f"
                        echo "$sus" | cut -d: -f1 | sort -rn | while read -r ln; do
                            sed -i "${ln}d" "$f" 2>/dev/null
                        done
                        ok "Cleaned $u's $rc"
                        add_fixed
                    fi
                fi
            done

            # Alias backdoor removal
            for rc in .bashrc .bash_aliases .bash_profile .profile .zshrc; do
                f="$hd/$rc"; [ -f "$f" ] || continue
                sus_aliases=$(grep -n "$SUS_ALIAS" "$f" 2>/dev/null | grep -v '^[0-9]*:[[:space:]]*#')
                net_aliases=$(grep -n 'alias.*=.*' "$f" 2>/dev/null | grep -v '^[0-9]*:[[:space:]]*#' | grep -E '/dev/tcp|curl |wget |nc |ncat |base64|python.*-c|perl.*-e|eval ')
                all_sus="${sus_aliases}${net_aliases}"
                if [ -n "$all_sus" ]; then
                    if confirm "Remove suspicious aliases from $u's $rc?"; then
                        backup_file "$f"
                        echo "$all_sus" | cut -d: -f1 | sort -rnu | while read -r ln; do
                            sed -i "${ln}d" "$f" 2>/dev/null
                        done
                        ok "Removed malicious aliases from $u's $rc"
                        add_fixed
                    fi
                fi
            done
            
            # Remove dangerous legacy files
            for dangerous_file in .rhosts .netrc; do
                df="$hd/$dangerous_file"
                if [ -f "$df" ]; then
                    if confirm "Remove dangerous $dangerous_file for $u?"; then
                        backup_file "$df"
                        rm -f "$df"
                        ok "Removed $dangerous_file for $u"
                        add_fixed
                    fi
                fi
            done
        fi
    else
        # Clean user
        printf "${G}  [✓] %-15s— clean${N}\n" "$u"
    fi
done

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  7. HIDDEN ROOT ACCOUNTS & EMPTY PASSWORDS                              ║
# ╚════════════════════════════════════════════════════════════════════════════╝
header "UID 0 & EMPTY PASSWORD CHECK"
info "Detects backdoor accounts with UID 0 (hidden root) and blank passwords."
info "UID 0 backdoors: userdel <user>. Empty passwords: passwd <user> or lock them."

# Check for hidden UID 0 accounts (backdoor root accounts)
uid0_users=$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd 2>/dev/null)
if [ -n "$uid0_users" ]; then
    echo "$uid0_users" | while read -r u; do
        crit "HIDDEN ROOT ACCOUNT (UID 0): $u"
        fix "userdel $u"
        if [ "$AUDIT_ONLY" = false ]; then
            if confirm "Lock hidden root account $u?"; then
                critical_operation usermod -L "$u" 2>/dev/null
                critical_operation usermod -s /usr/sbin/nologin "$u" 2>/dev/null
                ok "Locked and disabled shell for $u"
            fi
        fi
    done
else
    ok "No hidden UID 0 accounts"
fi

# Check for users with empty passwords in shadow
if [ -r /etc/shadow ]; then
    empty_pw=$(awk -F: '$2=="" && $1!="*" {print $1}' /etc/shadow 2>/dev/null)
    if [ -n "$empty_pw" ]; then
        echo "$empty_pw" | while read -r u; do
            # Only flag real users
            uid=$(id -u "$u" 2>/dev/null)
            case "$u" in nobody|nfsnobody|nogroup) continue;; esac
            if [ -n "$uid" ] && { [ "$uid" = "0" ] || [ "$uid" -ge 1000 ]; }; then
                crit "EMPTY PASSWORD: $u — anyone can log in as this user"
                fix "passwd $u"
                if [ "$AUDIT_ONLY" = false ]; then
                    if confirm "Lock $u until password is set?"; then
                        critical_operation usermod -L "$u" 2>/dev/null
                        ok "Locked $u"
                    fi
                fi
            fi
        done
    else
        ok "No users with empty passwords"
    fi
fi

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  8. SHELL CONFIGURATION AUDIT                                           ║
# ╚════════════════════════════════════════════════════════════════════════════╝
header "SHELL CONFIGURATION AUDIT"
info "Ensures authorized users have valid login shells (scoring may require this)."
info "Also disables shells on system accounts (UID < 1000) and checks hash strength."

# 8a. Ensure Authorized Users have VALID shells (Scoring Requirement)
if [ -n "$ALL_AUTHORIZED" ]; then
    _domain_noshell_list=""
    _domain_noshell_count=0
    _local_noshell_count=0

    echo "$ALL_AUTHORIZED" | while read -r u; do
        [ -z "$u" ] && continue
        
        # Skip users that don't exist on this system at all
        if ! id "$u" >/dev/null 2>&1; then
            continue
        fi
        
        # Check current shell (use getent for domain users too)
        curr_shell=$(getent passwd "$u" 2>/dev/null | cut -d: -f7)
        [ -z "$curr_shell" ] && curr_shell=$(grep "^${u}:" /etc/passwd 2>/dev/null | cut -d: -f7)
        
        # If shell is nologin/false/empty, it might break scoring
        if echo "$curr_shell" | grep -Eq 'nologin|false|^$'; then
            if is_local_user "$u"; then
                crit "LOCAL user $u has INVALID shell: ${curr_shell:-(empty)} — may break scoring!"
                fix "usermod -s /bin/bash $u"
                if [ "$AUDIT_ONLY" = false ]; then
                    if confirm "Set valid shell (/bin/bash) for $u?"; then
                        critical_operation usermod -s /bin/bash "$u" 2>/dev/null
                        ok "Shell updated for $u"
                        add_fixed
                    fi
                fi
            else
                # Batch domain users — just track them
                echo "$u" >> "$_CNT_DIR/domain_noshell"
                if [ "$AUDIT_ONLY" = false ]; then
                    if confirm "Apply local shell override (/bin/bash) for domain user $u?"; then
                        critical_operation usermod -s /bin/bash "$u" 2>/dev/null
                        if [ $? -eq 0 ]; then
                            ok "Shell overridden locally for $u"
                            add_fixed
                        else
                            warn_ "Local override failed — change shell from AD/DC"
                        fi
                    fi
                fi
            fi
        fi
    done

    # Summarize domain users with no local shell
    if [ -f "$_CNT_DIR/domain_noshell" ]; then
        _dn_count=$(wc -l < "$_CNT_DIR/domain_noshell" | tr -d ' ')
        _dn_names=$(tr '\n' ', ' < "$_CNT_DIR/domain_noshell" | sed 's/,$//')
        warn_ "$_dn_count domain user(s) have no local shell (expected if not yet logged in)"
        info "Set shells from AD, or locally: usermod -s /bin/bash <user>"
        log "Domain users with no shell: $_dn_names"
    fi
fi

# 8b. Disable System Account Shells (UID < 1000)
# Ignore: root, sync, shutdown, halt
sys_users_with_shells=$(awk -F: '$3 < 1000 && $3 > 0 && $7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1 ":" $7}' /etc/passwd 2>/dev/null)

if [ -n "$sys_users_with_shells" ]; then
    echo "$sys_users_with_shells" | while read -r line; do
        u=$(echo "$line" | cut -d: -f1)
        sh=$(echo "$line" | cut -d: -f2)
        
        warn_ "System Account $u (UID < 1000) has login shell: $sh"
        if [ "$AUDIT_ONLY" = false ]; then
            if confirm "Disable shell for system account $u?"; then
                critical_operation usermod -s /usr/sbin/nologin "$u" 2>/dev/null
                ok "Disabled shell for $u"
                FIXED=$((FIXED+1))
            else
                skip "shell disable for $u"
            fi
        fi
    done
else
    ok "System accounts (UID < 1000) are properly restricted"
fi


# Check for password hash algorithm strength
weak_hash=$(awk -F: '$2 ~ /^\$1\$/ {print $1" (MD5)"}; $2 ~ /^\$5\$/ {print $1" (SHA-256)"}' /etc/shadow 2>/dev/null)
if [ -n "$weak_hash" ]; then
    warn_ "Users with weak password hashes (should be SHA-512/yescrypt):"
    echo "$weak_hash" | indent
    fix "chpasswd rehashes automatically — just change their passwords"
fi

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  8. ACTIVE SESSIONS & LOGIN HISTORY                                     ║
# ╚════════════════════════════════════════════════════════════════════════════╝
header "ACTIVE SESSIONS & LOGIN HISTORY"
info "Shows who is currently logged in and recent login/failure history."
info "Unauthorized active sessions: pkill -KILL -u <user> to terminate."

# Active sessions with details (w shows what users are doing)
if cmd_exists w; then
    active=$(w -h 2>/dev/null)
    if [ -n "$active" ]; then
        warn_ "Active user sessions:"
        printf "      %-12s %-10s %-8s %s\n" "USER" "TTY" "IDLE" "COMMAND"
        printf "      %-12s %-10s %-8s %s\n" "----" "---" "----" "-------"
        echo "$active" | while read -r user tty from login idle jcpu pcpu what; do
            # Highlight if user is not in authorized lists
            is_auth=""
            if [ -n "$ALL_AUTHORIZED" ]; then
                echo "$ALL_AUTHORIZED" | grep -qx "$user" || is_auth=" [UNAUTHORIZED]"
            fi
            printf "      %-12s %-10s %-8s %s%s\n" "$user" "$tty" "$idle" "$what" "$is_auth"
        done

        # Offer to kill unauthorized sessions
        if [ "$AUDIT_ONLY" = false ] && [ -n "$ALL_AUTHORIZED" ]; then
            echo "$active" | while read -r user tty rest; do
                if ! echo "$ALL_AUTHORIZED" | grep -qx "$user"; then
                    if confirm "Kill all sessions for unauthorized user $user?"; then
                        pkill -KILL -u "$user" 2>/dev/null
                        ok "Killed all sessions for $user"
                    else
                        fix "pkill -KILL -u $user"
                    fi
                fi
            done
        fi
    else
        info "No active user sessions"
    fi
fi

# Currently logged-in users (simpler view)
if cmd_exists who; then
    logged_in=$(who 2>/dev/null)
    if [ -n "$logged_in" ]; then
        info "Logged-in users (who):"
        echo "$logged_in" | indent
    fi
fi

# Recent logins
if cmd_exists last; then
    info "Recent logins (last 10):"
    last -10 -w 2>/dev/null | grep -v '^$\|^reboot\|^wtmp' | indent
fi

# Users who never logged in
if cmd_exists lastlog; then
    never_list=$(lastlog 2>/dev/null | grep -i 'never' | awk '{print $1}' | while read -r u; do
        case "$u" in nobody|nfsnobody|nogroup) continue;; esac
        uid=$(id -u "$u" 2>/dev/null)
        if [ -n "$uid" ] && [ "$uid" -ge 1000 ]; then
            printf "%s\n" "$u"
        fi
    done)
    if [ -n "$never_list" ]; then
        _nl_count=$(echo "$never_list" | wc -l | tr -d ' ')
        _nl_names=$(echo "$never_list" | tr '\n' ', ' | sed 's/,$//')
        info "$_nl_count user(s) have NEVER logged in: $_nl_names"
    fi
fi

# Failed logins
if cmd_exists lastb; then
    failed=$(lastb -10 2>/dev/null | grep -v '^$\|^btmp')
    if [ -n "$failed" ]; then
        warn_ "Recent failed logins (last 10):"
        echo "$failed" | indent
        fix "Check if these are brute-force attempts from Red Team"
    fi
fi



# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  9. CHATTR FILE LOCKING                                                 ║
# ╚════════════════════════════════════════════════════════════════════════════╝
header "CRITICAL FILE LOCKING (chattr)"
info "Makes critical files immutable (chattr +i) to prevent Red Team tampering."
info "To edit a locked file: chattr -i <file>, edit, then chattr +i <file>."

# Install chattr if not present (it's in e2fsprogs)
if ! cmd_exists chattr; then
    info "chattr not found — attempting to install e2fsprogs..."
    case "$PKG_MGR" in
        apt)    apt-get install -y e2fsprogs > /dev/null 2>&1 ;;
        dnf)    dnf install -y e2fsprogs > /dev/null 2>&1 ;;
        yum)    yum install -y e2fsprogs > /dev/null 2>&1 ;;
        pacman) pacman -S --noconfirm e2fsprogs > /dev/null 2>&1 ;;
        apk)    apk add e2fsprogs > /dev/null 2>&1 ;;
        zypper) zypper install -y e2fsprogs > /dev/null 2>&1 ;;
        *)      warn_ "Unknown package manager — cannot install e2fsprogs" ;;
    esac
fi

if cmd_exists chattr; then
    LOCKABLE_FILES="/etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/ssh/sshd_config /etc/crontab /etc/cron.allow /etc/hosts"

    if [ "$AUDIT_ONLY" = true ]; then
        # Show compact lock status
        _locked=""; _unlocked=""
        for f in $LOCKABLE_FILES; do
            [ -f "$f" ] || continue
            _bn=$(basename "$f")
            if cmd_exists lsattr && lsattr "$f" 2>/dev/null | awk '{print $1}' | grep -q 'i'; then
                _locked="${_locked:+${_locked}, }$_bn"
            else
                _unlocked="${_unlocked:+${_unlocked}, }$_bn"
            fi
        done
        [ -n "$_locked" ]   && ok "Locked: $_locked"
        [ -n "$_unlocked" ] && warn_ "UNLOCKED: $_unlocked"
        [ -n "$_unlocked" ] && fix "Run without --audit-only to lock, or: chattr +i <file>"
    elif confirm "Lock critical files with chattr +i (prevents tampering)?"; then
        info "Files that will be made immutable:"
        for f in $LOCKABLE_FILES; do
            [ -f "$f" ] || continue
            printf "      %s\n" "$f"
        done
        echo ""
        info "To edit a locked file later, first unlock it:"
        printf "${C}      chattr -i /etc/passwd   # unlock${N}\n"
        printf "${C}      vim /etc/passwd          # edit${N}\n"
        printf "${C}      chattr +i /etc/passwd   # re-lock${N}\n"
        echo ""

        locked_count=0
        unsupported_count=0
        for f in $LOCKABLE_FILES; do
            [ -f "$f" ] || continue
            # Unlock first in case it's already locked
            safe_chattr -i "$f"
            # Try to lock
            if safe_chattr +i "$f"; then
                ok "Locked $f"
                locked_count=$((locked_count+1))
            else
                warn_ "Could not lock $f (filesystem doesn't support chattr - XFS/BTRFS/ZFS?)"
                unsupported_count=$((unsupported_count+1))
            fi
        done
        
        if [ $locked_count -gt 0 ]; then
            FIXED=$((FIXED+1))
            printf "\n${Y}${B}  ⚠ REMEMBER: To edit any locked file, run chattr -i <file> first!${N}\n"
            printf "${Y}${B}    After editing, re-lock with chattr +i <file>${N}\n"
            printf "${Y}${B}    Or use this script's critical_operation wrapper function${N}\n"
        fi
        
        if [ $unsupported_count -gt 0 ]; then
            printf "\n${Y}${B}  ℹ  NOTE: $unsupported_count files could not be locked (unsupported filesystem)${N}\n"
            printf "${Y}${B}    This is normal for XFS, BTRFS, and ZFS filesystems${N}\n"
        fi
    else
        skip "chattr file locking"
        add_skipped
    fi
else
    warn_ "chattr not available — cannot lock files"
    fix "apt install e2fsprogs  OR  yum install e2fsprogs"
fi

# Snapshot is saved automatically by EXIT trap (no manual save needed)

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  SUMMARY                                                                ║
# ╚════════════════════════════════════════════════════════════════════════════╝
banner
printf "${B}  USER MANAGEMENT COMPLETE — %s${N}\n" "$(date 2>/dev/null)"
banner
echo ""
# Read file-based counters (includes increments from subshells)
_TOTAL_CRIT=$(wc -l < "$_CRIT_FILE" 2>/dev/null | tr -d ' '); _TOTAL_CRIT=${_TOTAL_CRIT:-0}
_TOTAL_WARN=$(wc -l < "$_WARN_FILE" 2>/dev/null | tr -d ' '); _TOTAL_WARN=${_TOTAL_WARN:-0}
_TOTAL_FIX=$(wc -l < "$_FIX_FILE" 2>/dev/null | tr -d ' '); _TOTAL_FIX=${_TOTAL_FIX:-0}
_TOTAL_SKIP=$(wc -l < "$_SKIP_FILE" 2>/dev/null | tr -d ' '); _TOTAL_SKIP=${_TOTAL_SKIP:-0}

printf "${R}${B}  CRITICAL:  %s${N}\n" "$_TOTAL_CRIT"
printf "${Y}${B}  WARNINGS:  %s${N}\n" "$_TOTAL_WARN"
printf "${G}${B}  FIXED:     %s${N}\n" "$_TOTAL_FIX"
printf "${Y}${B}  SKIPPED:   %s${N}\n" "$_TOTAL_SKIP"

# Cleanup counter files
rm -rf "$_CNT_DIR" 2>/dev/null
echo ""
printf "  Report:     %s\n" "$REPORT_DIR"
printf "  Backups:    %s\n" "$BACKUP_DIR"
printf "  Log:        %s\n" "$LOG"
printf "  Snapshot:   %s (for next re-run diff)\n" "$SNAPSHOT"
printf "  Baseline:   %s (first run reference)\n" "$FIRST_SNAPSHOT"
echo ""
if [ "$AUDIT_ONLY" = true ]; then
    printf "${C}  Re-run without --audit-only to fix findings${N}\n"
fi
echo ""