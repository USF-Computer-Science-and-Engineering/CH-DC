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
    fi
}
_integrity_check
unset -f _integrity_check 2>/dev/null
# ─────────────────────────────────────────────────────────────────────────────
# ============================================================================
# user_watchdog.sh — Real-time User & Password Monitor (CCDC Edition)
# ============================================================================
# Runs in an infinite loop to detect changes to /etc/passwd, /etc/shadow,
# /etc/group, user home directories, and privilege escalations.
# Alerts on screen and logs to watchdog_log.txt.
#
# CCDC-SAFE: Compatible with user_admin.sh state files and chattr locks.
# Uses local directory for state (not /var/lib/), fixed subshell issues
#
# Usage: sudo ./user_watchdog.sh
# Press Ctrl+C to stop.
# ============================================================================

# ── Configuration ──
SCRIPT_DIR=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
HOSTNAME=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo "unknown")
LOG_FILE="$SCRIPT_DIR/watchdog_log.txt"
CHECK_INTERVAL=2
TEMP_DIR="/tmp/ccdc_watchdog_$$"
AUTO_LOCK=true  # Auto-lock unauthorized users (disable with --no-auto-lock)
STATE_DIR="$SCRIPT_DIR/.ccdc_state"  # LOCAL directory (shared with user_admin.sh)

# Cleanup on exit
_CLEANUP_DONE=false
_RUNNING=true
cleanup() {
    [ "$_CLEANUP_DONE" = true ] && return
    _CLEANUP_DONE=true
    rm -rf "$TEMP_DIR"
    echo ""
    printf "\033[1;33m╔══════════════════════════════════════════════════════════════╗\033[0m\n"
    printf "\033[1;33m║  WATCHDOG STOPPED — %s\033[0m\n" "$(date 2>/dev/null)"
    printf "\033[1;33m║  Uptime: %ds | Total Alerts: %d\033[0m\n" "$ELAPSED_TIME" "$ALERT_COUNT"
    printf "\033[1;33m╚══════════════════════════════════════════════════════════════╝\033[0m\n"
    printf "\033[0;36m  Log saved: %s\033[0m\n" "$LOG_FILE"
}
# INT/TERM: stop loop, cleanup, exit
trap '_RUNNING=false; cleanup; exit 0' INT TERM
# EXIT: catches normal exit
trap cleanup EXIT

# Root check
if [ "$(id -u)" != "0" ]; then
    printf "\033[1;31m[!] This script must be run as root!\033[0m\n"
    exit 1
fi

mkdir -p "$TEMP_DIR" "$STATE_DIR" 2>/dev/null
chmod 700 "$TEMP_DIR" "$STATE_DIR" 2>/dev/null

# ── Colors ──
R='\033[1;31m'
G='\033[1;32m'
Y='\033[1;33m'
C='\033[0;36m'
N='\033[0m'
BELL='\a'

# ── Helpers ──
LAST_BELL=0
ALERT_COUNT=0

log_alert() {
    timestamp=$(date +"%H:%M:%S" 2>/dev/null)
    
    # Bell rate-limiting (only if 5+ seconds since last bell)
    now=$(date +%s 2>/dev/null || echo 0)
    if [ "$now" -ge "$((LAST_BELL + 5))" ]; then
        printf "${BELL}${R}[!!!] [%s] %s${N}\n" "$timestamp" "$1"
        LAST_BELL=$now
    else
        printf "${R}[!!!] [%s] %s${N}\n" "$timestamp" "$1"
    fi
    
    echo "[$timestamp] ALARM: $1" >> "$LOG_FILE"
    ALERT_COUNT=$((ALERT_COUNT + 1))
}

log_warn() {
    timestamp=$(date +"%H:%M:%S" 2>/dev/null)
    printf "${Y}[!]  [%s] %s${N}\n" "$timestamp" "$1"
    echo "[$timestamp] WARN: $1" >> "$LOG_FILE"
}

log_change() {
    timestamp=$(date +"%H:%M:%S" 2>/dev/null)
    printf "${C}[~]  [%s] %s${N}\n" "$timestamp" "$1"
    echo "[$timestamp] CHANGE: $1" >> "$LOG_FILE"
}

log_info() {
    printf "${G}[*] %s${N}\n" "$1"
}

# Boxed critical alert for high-severity events
log_critical_box() {
    timestamp=$(date +"%H:%M:%S" 2>/dev/null)
    printf "${R}╔══════════════════════════════════════════════════════════════╗${N}\n"
    printf "${R}║  ⚠ %s${N}\n" "$1"
    if [ -n "$2" ]; then printf "${R}║    → %s${N}\n" "$2"; fi
    if [ -n "$3" ]; then printf "${R}║    → %s${N}\n" "$3"; fi
    printf "${R}╚══════════════════════════════════════════════════════════════╝${N}\n"
    echo "[$timestamp] CRITICAL: $1" >> "$LOG_FILE"
    ALERT_COUNT=$((ALERT_COUNT + 1))
}

# Check if user is authorized (root, admins.txt, users.txt, or global_exclude.txt)
is_authorized_user() {
    user="$1"
    
    # Root is always authorized
    [ "$user" = "root" ] && return 0
    
    # Check admins.txt
    if [ -f "$SCRIPT_DIR/admins.txt" ]; then
        if grep -qx "$user" "$SCRIPT_DIR/admins.txt" 2>/dev/null; then
            return 0
        fi
    fi
    
    # Check users.txt
    if [ -f "$SCRIPT_DIR/users.txt" ]; then
        if grep -qx "$user" "$SCRIPT_DIR/users.txt" 2>/dev/null; then
            return 0
        fi
    fi
    
    # Check global_exclude.txt (USER:username format)
    if [ -f "$SCRIPT_DIR/global_exclude.txt" ]; then
        if grep -qx "USER:$user" "$SCRIPT_DIR/global_exclude.txt" 2>/dev/null; then
            return 0
        fi
    fi
    
    return 1
}

# ── Initialization ──
clear 2>/dev/null
printf "${Y}╔══════════════════════════════════════════════════════════════╗${N}\n"
printf "${Y}║  CCDC USER WATCHDOG — %s${N}\n" "$HOSTNAME"
printf "${Y}║  Monitoring: /etc/{passwd,shadow,group}, homes, privileges  ║${N}\n"
if [ "$AUTO_LOCK" = true ]; then
    printf "${Y}║  AUTO-LOCK: ENABLED (unauthorized users locked instantly)   ║${N}\n"
else
    printf "${Y}║  AUTO-LOCK: DISABLED (alerts only)                         ║${N}\n"
fi
printf "${Y}║  Started: %s${N}\n" "$(date 2>/dev/null)"
printf "${Y}╚══════════════════════════════════════════════════════════════╝${N}\n"
log_info "Log: $LOG_FILE"
log_info "Check interval: ${CHECK_INTERVAL}s"

# Check for authorization files
if [ ! -f "$SCRIPT_DIR/users.txt" ] && [ ! -f "$SCRIPT_DIR/admins.txt" ]; then
    log_warn "WARNING: No users.txt or admins.txt found!"
    log_warn "Auto-lock will treat ALL users as unauthorized."
    log_warn "Run user_admin.sh first to establish baseline."
else
    if [ -f "$SCRIPT_DIR/users.txt" ]; then
        user_count=$(wc -l < "$SCRIPT_DIR/users.txt" 2>/dev/null | tr -d ' ')
        log_info "Loaded $user_count authorized users from users.txt"
    fi
    if [ -f "$SCRIPT_DIR/admins.txt" ]; then
        admin_count=$(wc -l < "$SCRIPT_DIR/admins.txt" 2>/dev/null | tr -d ' ')
        log_info "Loaded $admin_count authorized admins from admins.txt"
    fi
    if [ -f "$SCRIPT_DIR/global_exclude.txt" ]; then
        exclude_count=$(grep -c '^USER:' "$SCRIPT_DIR/global_exclude.txt" 2>/dev/null || echo 0)
        log_info "Loaded $exclude_count excluded users from global_exclude.txt"
    fi
fi

log_info "Press Ctrl+C to stop."
echo ""

# Unlock files temporarily to read (user_admin.sh may have locked them)
# NOTE: This works even if chattr is unavailable (just fails silently)
unlock_if_needed() {
    for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow; do
        [ -f "$f" ] && chattr -i "$f" 2>/dev/null
    done
}

# Create initial baselines
unlock_if_needed

cp /etc/passwd "$TEMP_DIR/passwd.base" 2>/dev/null
cp /etc/group "$TEMP_DIR/group.base" 2>/dev/null

# Shadow baseline - handle permission errors gracefully
if [ -r /etc/shadow ]; then
    cp /etc/shadow "$TEMP_DIR/shadow.base" 2>/dev/null
    awk -F: '{print $1":"$2}' /etc/shadow 2>/dev/null > "$TEMP_DIR/hashes.base"
    SHADOW_MONITORING=true
else
    log_warn "Cannot read /etc/shadow — password monitoring disabled"
    SHADOW_MONITORING=false
fi

# Detect admin group (sudo/wheel)
ADMIN_GROUP=""
if grep -q '^sudo:' /etc/group 2>/dev/null; then ADMIN_GROUP="sudo"
elif grep -q '^wheel:' /etc/group 2>/dev/null; then ADMIN_GROUP="wheel"
fi

# Track home directories (detect new user home dirs under /home)
ls -1d /home/*/ /root/ 2>/dev/null | sort > "$TEMP_DIR/homes.base"

# UID/GID tracking for privilege escalation
awk -F: '($3>=1000 || $3==0) && $1!="nobody" {print $1":"$3}' /etc/passwd 2>/dev/null | sort > "$TEMP_DIR/uids.base"

# Count baseline stats for heartbeat
_BASE_USERS=$(wc -l < /etc/passwd 2>/dev/null | tr -d ' ')
_BASE_UID0=$(awk -F: '$3==0' /etc/passwd 2>/dev/null | wc -l | tr -d ' ')

log_info "Baseline: $_BASE_USERS passwd entries, $_BASE_UID0 UID 0 account(s)"
echo ""

# ── Main Loop ──
ELAPSED_TIME=0

while [ "$_RUNNING" = true ]; do
    # Background sleep + wait: allows trap to fire during wait (sleep blocks signals in sh)
    sleep "$CHECK_INTERVAL" &
    wait $! 2>/dev/null
    [ "$_RUNNING" = true ] || break
    ELAPSED_TIME=$((ELAPSED_TIME + CHECK_INTERVAL))
    
    # Unlock files before checking
    unlock_if_needed

    # ════════════════════════════════════════════════════════════
    # 1. /etc/passwd — Detects new/deleted users, shell changes, UID tampering
    # ════════════════════════════════════════════════════════════
    if ! cmp -s "$TEMP_DIR/passwd.base" /etc/passwd 2>/dev/null; then
        diff_out=$(diff "$TEMP_DIR/passwd.base" /etc/passwd 2>/dev/null)
        
        # New users (FIXED: Using temp file to avoid subshell)
        echo "$diff_out" | grep "^> " | cut -c 3- > "$TEMP_DIR/added"
        while IFS=: read -r u _ uid _ _ _ shell; do
            [ -z "$u" ] && continue
            
            # Check if user is authorized
            if is_authorized_user "$u"; then
                log_change "NEW USER (authorized): $u (UID=$uid, Shell=$shell)"
            else
                log_alert "NEW UNAUTHORIZED USER: $u (UID=$uid, Shell=$shell)"
                
                # Auto-lock if enabled
                if [ "$AUTO_LOCK" = true ]; then
                    # CRITICAL: Never kill UID 0 (would kill root and ourselves!)
                    if [ "$uid" = "0" ]; then
                        log_critical_box \
                            "BACKDOOR UID 0 ACCOUNT: $u — same privileges as root!" \
                            "FIX: userdel $u  OR  edit /etc/passwd to fix UID" \
                            "DO NOT pkill — killing UID 0 kills your own session!"
                    else
                        # Lock the account
                        if usermod -L "$u" 2>/dev/null; then
                            log_alert "AUTO-LOCKED: $u (not in users.txt/admins.txt)"
                            
                            # Kill their processes (safe because UID != 0)
                            # Get actual current UID in case it changed
                            current_uid=$(id -u "$u" 2>/dev/null)
                            if [ -n "$current_uid" ] && [ "$current_uid" != "0" ]; then
                                if pkill -9 -u "$u" 2>/dev/null; then
                                    log_alert "Killed all processes for: $u (UID=$current_uid)"
                                fi
                            else
                                log_warn "Skipped killing processes for $u (UID is 0 or unavailable)"
                            fi
                        else
                            log_warn "Failed to lock: $u"
                        fi
                    fi
                fi
            fi
        done < "$TEMP_DIR/added"
        
        # Deleted users
        echo "$diff_out" | grep "^< " | cut -c 3- > "$TEMP_DIR/deleted"
        while IFS=: read -r u _; do
            [ -z "$u" ] && continue
            log_change "USER DELETED: $u"
        done < "$TEMP_DIR/deleted"
        
        # Modified users (shell/UID changes)
        while IFS=: read -r user _ uid _ _ _ shell; do
            old_line=$(grep "^${user}:" "$TEMP_DIR/passwd.base" 2>/dev/null)
            if [ -n "$old_line" ]; then
                old_uid=$(echo "$old_line" | cut -d: -f3)
                old_shell=$(echo "$old_line" | cut -d: -f7)
                
                if [ "$uid" != "$old_uid" ]; then
                    if [ "$uid" = "0" ]; then
                        log_critical_box \
                            "UID ESCALATION: $user changed from UID $old_uid → 0 (ROOT)!" \
                            "FIX: usermod -u $old_uid $user  (restore original UID)" \
                            "DO NOT pkill — UID 0 processes include YOUR session!"
                    else
                        log_alert "UID CHANGED: $user ($old_uid → $uid)"
                    fi
                fi
                
                if [ "$shell" != "$old_shell" ]; then
                    log_warn "Shell changed: $user ($old_shell → $shell)"
                fi
            fi
        done < /etc/passwd
        
        # Update baseline
        cp /etc/passwd "$TEMP_DIR/passwd.base" 2>/dev/null
    fi

    # ════════════════════════════════════════════════════════════
    # 2. /etc/shadow — Detects password changes, locks/unlocks, empty passwords
    # ════════════════════════════════════════════════════════════
    if [ "$SHADOW_MONITORING" = true ] && [ -r /etc/shadow ]; then
        if ! cmp -s "$TEMP_DIR/shadow.base" /etc/shadow 2>/dev/null; then
            # Generate current hash snapshot
            awk -F: '{print $1":"$2}' /etc/shadow 2>/dev/null > "$TEMP_DIR/hashes.new"
            
            # Compare
            shadow_diff=$(diff "$TEMP_DIR/hashes.base" "$TEMP_DIR/hashes.new" 2>/dev/null)
            
            # Changed passwords (FIXED: temp file to preserve ALERT_COUNT)
            echo "$shadow_diff" | grep "^> " | cut -c 3- > "$TEMP_DIR/shadow_changes"
            while IFS=: read -r user hash; do
                [ -z "$user" ] && continue
                
                old_hash=$(grep "^${user}:" "$TEMP_DIR/hashes.base" 2>/dev/null | cut -d: -f2)
                
                if [ -z "$old_hash" ]; then
                    # New user password set
                    if is_authorized_user "$user"; then
                        log_change "Password SET for new user: $user (authorized)"
                    else
                        log_alert "Password SET for UNAUTHORIZED user: $user"
                    fi
                elif [ "$hash" = "!" ] || [ "$hash" = "*" ] || [ "$hash" = "!!" ]; then
                    log_warn "Account LOCKED: $user"
                elif [ "$old_hash" = "!" ] || [ "$old_hash" = "*" ] || [ "$old_hash" = "!!" ]; then
                    log_change "Account UNLOCKED and password set: $user"
                else
                    # Regular password change - could be legitimate rotation or Red Team
                    if is_authorized_user "$user"; then
                        # Legitimate user - might be your team rotating passwords
                        log_change "Password changed: $user (authorized user - verify this was your team)"
                    else
                        # Unauthorized user password change = definitely Red Team
                        log_alert "PASSWORD CHANGED: $user (UNAUTHORIZED USER!)"
                    fi
                fi
            done < "$TEMP_DIR/shadow_changes"
            
            # Update baselines
            cp /etc/shadow "$TEMP_DIR/shadow.base" 2>/dev/null
            mv "$TEMP_DIR/hashes.new" "$TEMP_DIR/hashes.base" 2>/dev/null
        fi
    fi

    # ════════════════════════════════════════════════════════════
    # 3. /etc/group — Detects sudo/wheel additions (privilege escalation)
    # ════════════════════════════════════════════════════════════
    if ! cmp -s "$TEMP_DIR/group.base" /etc/group 2>/dev/null; then
        # Focus on admin group changes
        if [ -n "$ADMIN_GROUP" ]; then
            grep "^${ADMIN_GROUP}:" "$TEMP_DIR/group.base" 2>/dev/null | cut -d: -f4 | tr ',' '\n' | sort > "$TEMP_DIR/old_admins"
            grep "^${ADMIN_GROUP}:" /etc/group 2>/dev/null | cut -d: -f4 | tr ',' '\n' | sort > "$TEMP_DIR/new_admins"
            
            # Find additions
            while IFS= read -r u; do
                [ -z "$u" ] && continue
                if ! grep -qx "$u" "$TEMP_DIR/old_admins" 2>/dev/null; then
                    log_critical_box \
                        "PRIVILEGE ESCALATION: $u added to $ADMIN_GROUP group!" \
                        "FIX: gpasswd -d $u $ADMIN_GROUP" \
                        "Then investigate: who did this? Check auth.log"
                fi
            done < "$TEMP_DIR/new_admins"
            
            # Find removals
            while IFS= read -r u; do
                [ -z "$u" ] && continue
                if ! grep -qx "$u" "$TEMP_DIR/new_admins" 2>/dev/null; then
                    log_change "User removed from $ADMIN_GROUP: $u"
                fi
            done < "$TEMP_DIR/old_admins"
        fi
        
        # Update baseline
        cp /etc/group "$TEMP_DIR/group.base" 2>/dev/null
    fi

    # ════════════════════════════════════════════════════════════
    # 4. Home directories — Detects new home dirs (user creation side-effect)
    # ════════════════════════════════════════════════════════════
    ls -1d /home/*/ /root/ 2>/dev/null | sort > "$TEMP_DIR/homes.new"
    
    if [ -f "$TEMP_DIR/homes.base" ]; then
        home_diff=$(diff "$TEMP_DIR/homes.base" "$TEMP_DIR/homes.new" 2>/dev/null)
        
        # New homes
        echo "$home_diff" | grep "^> " | cut -c 3- > "$TEMP_DIR/new_homes"
        while IFS= read -r hd; do
            [ -z "$hd" ] && continue
            log_warn "New home directory: $hd"
        done < "$TEMP_DIR/new_homes"
        
        # Deleted homes
        echo "$home_diff" | grep "^< " | cut -c 3- > "$TEMP_DIR/del_homes"
        while IFS= read -r hd; do
            [ -z "$hd" ] && continue
            log_warn "Home directory deleted: $hd"
        done < "$TEMP_DIR/del_homes"
    fi
    
    mv "$TEMP_DIR/homes.new" "$TEMP_DIR/homes.base" 2>/dev/null

    # ════════════════════════════════════════════════════════════
    # 5. Heartbeat — Shows system health snapshot every 30s
    # ════════════════════════════════════════════════════════════
    if [ $((ELAPSED_TIME % 30)) -eq 0 ]; then
        _cur_users=$(wc -l < /etc/passwd 2>/dev/null | tr -d ' ')
        _cur_uid0=$(awk -F: '$3==0' /etc/passwd 2>/dev/null | wc -l | tr -d ' ')
        _cur_shadow=""
        if [ -r /etc/shadow ]; then
            _cur_empty=$(awk -F: '$2==""' /etc/shadow 2>/dev/null | wc -l | tr -d ' ')
            [ "$_cur_empty" -gt 0 ] 2>/dev/null && _cur_shadow=" | ${_cur_empty} EMPTY PW!"
        fi
        _cur_admin=""
        if [ -n "$ADMIN_GROUP" ]; then
            _cur_admin_count=$(grep "^${ADMIN_GROUP}:" /etc/group 2>/dev/null | cut -d: -f4 | tr ',' '\n' | grep -v '^$' | wc -l | tr -d ' ')
            _cur_admin=" | ${ADMIN_GROUP}:${_cur_admin_count}"
        fi
        
        # Color-code: green if stable, yellow if something changed
        if [ "$_cur_users" != "$_BASE_USERS" ] || [ "$_cur_uid0" != "$_BASE_UID0" ]; then
            printf "${Y}[⚡] %s | %ds | users:%s (was %s) | uid0:%s%s%s | alerts:%d${N}\n" \
                "$HOSTNAME" "$ELAPSED_TIME" "$_cur_users" "$_BASE_USERS" "$_cur_uid0" "$_cur_admin" "$_cur_shadow" "$ALERT_COUNT"
        else
            printf "${G}[✓]  %s | %ds | users:%s | uid0:%s%s%s | alerts:%d${N}\n" \
                "$HOSTNAME" "$ELAPSED_TIME" "$_cur_users" "$_cur_uid0" "$_cur_admin" "$_cur_shadow" "$ALERT_COUNT"
        fi
    fi
done
