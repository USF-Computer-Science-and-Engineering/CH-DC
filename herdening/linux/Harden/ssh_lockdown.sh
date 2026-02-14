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
# ssh_lockdown.sh — CCDC SSH Hardening & Security
# ============================================================================
# Hardens SSH configuration for CCDC competitions:
# - Disables public key authentication (removes Red Team backdoor keys)
# - Enables password authentication (allows your team to login)
# - Enables root login (controlled via strong passwords)
# - Removes all SSH keys from user home directories
# - Locks SSH config with chattr
#
# Usage: 
#   sudo ./ssh_lockdown.sh              # Harden SSH
#   sudo ./ssh_lockdown.sh --restore    # Restore from backup
# ============================================================================

# Root check
if [ "$(id -u)" != "0" ]; then
    echo "ERROR: This script must be run as root!"
    exit 1
fi

# ── Argument Parsing ──
RESTORE_MODE=false
if [ "$1" = "--restore-backup" ] || [ "$1" = "--restore" ]; then
    RESTORE_MODE=true
fi

# ── Configuration ──
SCRIPT_DIR=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
TIMESTAMP=$(date +%Y%m%d_%H%M%S 2>/dev/null || echo "notime")
ORIGINAL_BACKUP_DIR="$SCRIPT_DIR/ssh_original_backup"  # Permanent backup
BACKUP_DIR="$SCRIPT_DIR/ssh_backups_${TIMESTAMP}"       # Timestamped backup
SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_CONFIG_D="/etc/ssh/sshd_config.d"

mkdir -p "$BACKUP_DIR"

# ── Colors ──
if [ -t 1 ]; then
    R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; B='\033[1m'; N='\033[0m'
else
    R=''; G=''; Y=''; C=''; B=''; N=''
fi

# ── Helper Functions ──
header() { printf "${Y}${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}\n${Y}${B}%s${N}\n${Y}${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}\n" "$1"; }
ok()   { printf "${G}[✓] %s${N}\n" "$1"; }
warn() { printf "${Y}[!] %s${N}\n" "$1"; }
err()  { printf "${R}[✗] %s${N}\n" "$1"; }
info() { printf "${C}[*] %s${N}\n" "$1"; }

confirm() {
    printf "${Y}[?] %s [y/N]: ${N}" "$1"
    read -r resp
    [ "$resp" = "y" ] || [ "$resp" = "Y" ]
}

# ── Restore Function ──
restore_from_backup() {
    clear
    printf "${Y}╔══════════════════════════════════════════════════════════════╗${N}\n"
    printf "${Y}║  SSH RESTORE — Recovering Original Configuration           ║${N}\n"
    printf "${Y}╚══════════════════════════════════════════════════════════════╝${N}\n"
    echo ""
    
    if [ ! -d "$ORIGINAL_BACKUP_DIR" ]; then
        err "No original backup found at: $ORIGINAL_BACKUP_DIR"
        err "Run the script normally first to create a backup."
        exit 1
    fi
    
    warn "This will restore SSH configuration to its ORIGINAL state."
    warn "All hardening applied by this script will be REMOVED."
    echo ""
    
    if ! confirm "Are you sure you want to restore?"; then
        info "Restore cancelled."
        exit 0
    fi
    
    header "RESTORING SSH CONFIGURATION"
    
    # Unlock files first
    chattr -i "$SSHD_CONFIG" 2>/dev/null
    chattr -i "$SSHD_CONFIG_D" 2>/dev/null
    
    # Restore main config
    if [ -f "$ORIGINAL_BACKUP_DIR/sshd_config.original" ]; then
        cp "$ORIGINAL_BACKUP_DIR/sshd_config.original" "$SSHD_CONFIG"
        ok "Restored $SSHD_CONFIG"
    else
        err "Original sshd_config not found in backup!"
        exit 1
    fi
    
    # Restore sshd_config.d directory
    if [ -d "$ORIGINAL_BACKUP_DIR/sshd_config.d.original" ]; then
        rm -rf "$SSHD_CONFIG_D"
        cp -a "$ORIGINAL_BACKUP_DIR/sshd_config.d.original" "$SSHD_CONFIG_D"
        ok "Restored $SSHD_CONFIG_D"
    fi
    
    echo ""
    header "TESTING RESTORED CONFIGURATION"
    
    if command -v sshd >/dev/null 2>&1; then
        if sshd -t 2>/dev/null; then
            ok "SSH configuration is valid"
        else
            err "Restored config test FAILED!"
            sshd -t
            exit 1
        fi
    fi
    
    echo ""
    header "RESTARTING SSH SERVICE"
    
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null; then
            ok "SSH service restarted"
        fi
    elif command -v service >/dev/null 2>&1; then
        service sshd restart 2>/dev/null || service ssh restart 2>/dev/null
        ok "SSH service restarted"
    fi
    
    echo ""
    printf "${G}✓ SSH configuration restored to original state${N}\n"
    printf "${Y}⚠ SSH hardening has been REMOVED${N}\n"
    printf "${Y}⚠ Original backup preserved at: $ORIGINAL_BACKUP_DIR${N}\n"
    echo ""
    exit 0
}

# Check if restore mode
if [ "$RESTORE_MODE" = true ]; then
    restore_from_backup
fi

# ── Banner ──
clear
printf "${Y}╔══════════════════════════════════════════════════════════════╗${N}\n"
printf "${Y}║  SSH LOCKDOWN — CCDC SSH Hardening                          ║${N}\n"
printf "${Y}╚══════════════════════════════════════════════════════════════╝${N}\n"
echo ""

# ── Backup Current Config ──
header "BACKUP SSH CONFIGURATION"
info "Creates one-time original backup + timestamped backup for this run."
info "Restore anytime with: ./ssh_lockdown.sh --restore"

if [ ! -f "$SSHD_CONFIG" ]; then
    err "SSH config not found at $SSHD_CONFIG"
    exit 1
fi

# Create permanent original backup on first run
if [ ! -d "$ORIGINAL_BACKUP_DIR" ]; then
    mkdir -p "$ORIGINAL_BACKUP_DIR"
    cp -a "$SSHD_CONFIG" "$ORIGINAL_BACKUP_DIR/sshd_config.original"
    ok "Created ORIGINAL backup: $ORIGINAL_BACKUP_DIR/sshd_config.original"
    
    if [ -d "$SSHD_CONFIG_D" ]; then
        cp -a "$SSHD_CONFIG_D" "$ORIGINAL_BACKUP_DIR/sshd_config.d.original"
        ok "Backed up $SSHD_CONFIG_D (original)"
    fi
    
    info "Original backup will be preserved for --restore-backup"
else
    info "Original backup exists at: $ORIGINAL_BACKUP_DIR"
fi

# Also create timestamped backup for this run
mkdir -p "$BACKUP_DIR"
cp -a "$SSHD_CONFIG" "$BACKUP_DIR/sshd_config.bak"
ok "Created timestamped backup: $BACKUP_DIR/sshd_config.bak"

if [ -d "$SSHD_CONFIG_D" ]; then
    cp -a "$SSHD_CONFIG_D" "$BACKUP_DIR/sshd_config.d.bak"
    ok "Backed up $SSHD_CONFIG_D (timestamped)"
fi

echo ""

# ── Modify SSH Configuration ──
header "HARDENING SSH CONFIGURATION"
info "Disables pubkey auth to kill Red Team SSH keys, enables password auth."
info "Also disables X11 forwarding and sets session limits."

# Unlock config files temporarily (in case locked from previous run)
chattr -i "$SSHD_CONFIG" 2>/dev/null
if [ -d "$SSHD_CONFIG_D" ]; then
    chattr -i "$SSHD_CONFIG_D" 2>/dev/null
fi
info "Unlocked SSH config files for editing"

# Function to set SSH config value (handles existing, commented, and missing values)
set_ssh_config() {
    directive="$1"
    value="$2"
    config_file="$3"
    
    # Check if directive exists (uncommented)
    if grep -q "^${directive} " "$config_file" 2>/dev/null; then
        # Setting exists, replace it
        sed -i "s/^${directive} .*/${directive} ${value}/" "$config_file"
        ok "Set ${directive} ${value}"
    # Check if directive exists but is commented out
    elif grep -q "^#${directive} " "$config_file" 2>/dev/null; then
        # Uncomment and set
        sed -i "s/^#${directive} .*/${directive} ${value}/" "$config_file"
        ok "Uncommented and set ${directive} ${value}"
    else
        # Directive doesn't exist, add it
        echo "${directive} ${value}" >> "$config_file"
        ok "Added ${directive} ${value}"
    fi
}

# Unlock config file temporarily
chattr -i "$SSHD_CONFIG" 2>/dev/null

# Critical settings for CCDC
set_ssh_config "PasswordAuthentication" "yes" "$SSHD_CONFIG"
set_ssh_config "PubkeyAuthentication" "no" "$SSHD_CONFIG"
set_ssh_config "PermitRootLogin" "yes" "$SSHD_CONFIG"
set_ssh_config "ChallengeResponseAuthentication" "no" "$SSHD_CONFIG"
set_ssh_config "UsePAM" "yes" "$SSHD_CONFIG"

# Security hardening (still allow functionality)
set_ssh_config "PermitEmptyPasswords" "no" "$SSHD_CONFIG"
set_ssh_config "X11Forwarding" "no" "$SSHD_CONFIG"
set_ssh_config "MaxAuthTries" "5" "$SSHD_CONFIG"
set_ssh_config "MaxSessions" "10" "$SSHD_CONFIG"
set_ssh_config "ClientAliveInterval" "300" "$SSHD_CONFIG"
set_ssh_config "ClientAliveCountMax" "2" "$SSHD_CONFIG"

# Disable SSH key-based authentication methods
set_ssh_config "AuthorizedKeysFile" "/dev/null" "$SSHD_CONFIG"

info "SSH configuration hardened"
echo ""

# ── Handle sshd_config.d includes ──
if [ -d "$SSHD_CONFIG_D" ]; then
    header "CHECKING SSH CONFIG INCLUDES"
    info "Files in sshd_config.d/ can silently override your hardening."
    info "Safest option: disable all includes."
    
    include_count=$(find "$SSHD_CONFIG_D" -name "*.conf" 2>/dev/null | wc -l)
    if [ "$include_count" -gt 0 ]; then
        warn "Found $include_count config files in $SSHD_CONFIG_D"
        warn "These can override main config settings!"
        
        if confirm "Disable all include files? (safer)"; then
            # Disable the files
            find "$SSHD_CONFIG_D" -name "*.conf" -exec mv {} {}.disabled \;
            ok "Disabled all include files (renamed to .conf.disabled)"
            
            # Also comment out the Include directive in main config (idempotent - only if not already commented)
            if grep -q "^Include /etc/ssh/sshd_config.d/\*.conf" "$SSHD_CONFIG" 2>/dev/null; then
                sed -i 's|^Include /etc/ssh/sshd_config.d/\*.conf|#Include /etc/ssh/sshd_config.d/*.conf  # Disabled by ssh_lockdown.sh|' "$SSHD_CONFIG"
                ok "Commented out Include directive in main config"
            elif grep -q "^Include ${SSHD_CONFIG_D}/\*.conf" "$SSHD_CONFIG" 2>/dev/null; then
                sed -i "s|^Include ${SSHD_CONFIG_D}/\*.conf|#Include ${SSHD_CONFIG_D}/*.conf  # Disabled by ssh_lockdown.sh|" "$SSHD_CONFIG"
                ok "Commented out Include directive in main config"
            elif grep -q "^#Include.*Disabled by ssh_lockdown.sh" "$SSHD_CONFIG" 2>/dev/null; then
                info "Include directive already commented (skipped)"
            fi
        else
            info "Skipped - may need manual review"
            warn "WARNING: Include files may override your settings!"
        fi
    else
        ok "No include files found"
    fi
    echo ""
fi

# ── Test SSH Configuration ──
header "TESTING SSH CONFIGURATION"
info "Runs sshd -t to validate config. Auto-restores backup if test fails."

if command -v sshd >/dev/null 2>&1; then
    if sshd -t 2>/dev/null; then
        ok "SSH configuration is valid"
    else
        err "SSH configuration test FAILED!"
        sshd -t
        err "Restoring backup..."
        cp "$BACKUP_DIR/sshd_config.bak" "$SSHD_CONFIG"
        exit 1
    fi
else
    warn "sshd command not found - skipping config test"
fi
echo ""

# ── Remove SSH Keys ──
header "SSH KEY REMOVAL"
info "Removes authorized_keys from ALL user homes (kills Red Team backdoor keys)."
info "Also removes private keys (id_rsa, id_ed25519, etc)."

if confirm "Remove ALL SSH keys from user home directories?"; then
    info "Scanning for SSH keys..."
    
    # Find all .ssh directories
    ssh_dirs=$(find /home /root -type d -name ".ssh" 2>/dev/null)
    
    if [ -z "$ssh_dirs" ]; then
        info "No .ssh directories found"
    else
        for ssh_dir in $ssh_dirs; do
            owner=$(stat -c '%U' "$ssh_dir" 2>/dev/null || stat -f '%Su' "$ssh_dir" 2>/dev/null)
            
            # Backup SSH keys before deletion
            if [ -f "$ssh_dir/authorized_keys" ]; then
                cp "$ssh_dir/authorized_keys" "$BACKUP_DIR/authorized_keys_${owner}_${TIMESTAMP}"
                ok "Backed up authorized_keys for $owner"
            fi
            
            # Remove key files
            removed=0
            for keyfile in "$ssh_dir/authorized_keys" "$ssh_dir/authorized_keys2" "$ssh_dir/id_rsa" "$ssh_dir/id_dsa" "$ssh_dir/id_ecdsa" "$ssh_dir/id_ed25519"; do
                if [ -f "$keyfile" ]; then
                    rm -f "$keyfile"
                    removed=$((removed + 1))
                fi
            done
            
            if [ $removed -gt 0 ]; then
                ok "Removed $removed key file(s) from $ssh_dir ($owner)"
            fi
        done
    fi
    
    info "SSH key removal complete"
else
    warn "Skipped SSH key removal"
fi
echo ""

# ── Restart SSH Service ──
header "RESTARTING SSH SERVICE"
info "Applies the config changes. DO NOT close your current SSH session until tested!"

# Detect init system
if command -v systemctl >/dev/null 2>&1; then
    # systemd
    if confirm "Restart SSH service now?"; then
        if systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null; then
            ok "SSH service restarted (systemd)"
            systemctl status sshd 2>/dev/null || systemctl status ssh 2>/dev/null | head -5
        else
            err "Failed to restart SSH service"
            exit 1
        fi
    else
        warn "Skipped SSH restart - changes will not take effect until manual restart"
    fi
elif command -v service >/dev/null 2>&1; then
    # SysVinit/Upstart
    if confirm "Restart SSH service now?"; then
        if service sshd restart 2>/dev/null || service ssh restart 2>/dev/null; then
            ok "SSH service restarted (service)"
        else
            err "Failed to restart SSH service"
            exit 1
        fi
    else
        warn "Skipped SSH restart - changes will not take effect until manual restart"
    fi
else
    warn "Could not detect init system - restart SSH manually"
    info "Try: systemctl restart sshd  OR  service sshd restart"
fi
echo ""

# ── Lock SSH Config ──
header "LOCK SSH CONFIGURATION"
info "chattr +i makes config immutable — Red Team can't modify it."
info "To edit later: chattr -i /etc/ssh/sshd_config"

if command -v chattr >/dev/null 2>&1; then
    if confirm "Make SSH config immutable with chattr +i?"; then
        if chattr +i "$SSHD_CONFIG" 2>/dev/null; then
            ok "Locked $SSHD_CONFIG (immutable)"
            info "To edit later: chattr -i $SSHD_CONFIG"
        else
            warn "Could not lock $SSHD_CONFIG (filesystem doesn't support chattr)"
        fi
        
        # Lock config.d directory too
        if [ -d "$SSHD_CONFIG_D" ]; then
            if chattr +i "$SSHD_CONFIG_D" 2>/dev/null; then
                ok "Locked $SSHD_CONFIG_D"
            fi
        fi
    else
        warn "Skipped locking SSH config"
    fi
else
    warn "chattr not available - cannot lock config"
fi
echo ""

# ── Summary ──
header "SSH HARDENING COMPLETE"
info "Summary of applied changes. Test SSH in a NEW terminal before closing this one!"

printf "${G}✓ Configuration Changes:${N}\n"
printf "  ${C}PasswordAuthentication:${N} yes\n"
printf "  ${C}PubkeyAuthentication:${N} no\n"
printf "  ${C}PermitRootLogin:${N} yes\n"
printf "  ${C}AuthorizedKeysFile:${N} /dev/null\n"
echo ""

printf "${G}✓ Backups:${N}\n"
printf "  ${C}Original (restore with --restore-backup): $ORIGINAL_BACKUP_DIR${N}\n"
printf "  ${C}Timestamped (this run): $BACKUP_DIR${N}\n"
echo ""

printf "${Y}⚠ IMPORTANT:${N}\n"
printf "  ${Y}1. SSH keys are now DISABLED - only password login works${N}\n"
printf "  ${Y}2. Make sure all team members know the new root password!${N}\n"
printf "  ${Y}3. Test SSH login in a NEW terminal before closing this one${N}\n"
printf "  ${Y}4. Config is locked - unlock with: chattr -i $SSHD_CONFIG${N}\n"
printf "  ${Y}5. Restore original config with: ./ssh_lockdown.sh --restore-backup${N}\n"
echo ""

printf "${C}Test SSH login:${N}\n"
printf "  ssh root@localhost\n"
echo ""
