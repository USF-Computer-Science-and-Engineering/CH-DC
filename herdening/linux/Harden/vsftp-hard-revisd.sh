#!/bin/bash
# ======================================================================
# VSFTPD HARDENING SCRIPT — Distro-Agnostic (CCDC)
# ======================================================================
# Description:
#   Hardens a vsftpd installation for competition use:
#     - Disables anonymous access
#     - Creates an allowed-user whitelist (userlist_deny=NO)
#     - Auto-detects chroot mode:
#         • Shared root: if existing config has local_root or you pass one
#         • Per-user: each user chrooted into their own home directory
#     - Sets secure file/directory permissions
#     - Configures passive port range (with firewall warning)
#     - Enables TLS if a certificate is available
#     - Strips version info from the banner
#     - Enables seccomp sandboxing
#     - Idempotent: safe to re-run
#
# Usage:
#   sudo ./vsftpd_hardening.sh <userlist.txt> [ftp_root]
#
#   userlist.txt  — one username per line (must be existing local users)
#   ftp_root      — optional shared FTP root directory
#                   If omitted, the script auto-detects:
#                     1. Reads local_root from existing vsftpd.conf → shared mode
#                     2. If no local_root found → per-user home directory mode
#
# Notes:
#   - Must be run as root.
#   - Backs up vsftpd.conf before making changes.
#   - Works on Debian/Ubuntu, RHEL/CentOS/Fedora, Arch, Alpine, SUSE.
# ======================================================================

set -euo pipefail

# ---------------------------
# Color helpers
# ---------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ---------------------------
# Pre-flight checks
# ---------------------------
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (use sudo)."
fi

if [[ -z "${1:-}" ]]; then
    echo "Usage: sudo $0 <userlist.txt> [ftp_root]"
    echo "  userlist.txt — file with one allowed FTP username per line"
    echo "  ftp_root     — shared FTP root (optional; auto-detects if omitted)"
    exit 1
fi

USERLIST_INPUT="$1"
FTP_ROOT_ARG="${2:-}"    # empty if not provided — triggers auto-detection later

if [[ ! -f "$USERLIST_INPUT" ]]; then
    error "Userlist file not found: $USERLIST_INPUT"
fi

# ---------------------------
# Detect distro & package mgr
# ---------------------------
detect_pkg_manager() {
    if command -v apt-get &>/dev/null; then
        PKG_MGR="apt"
    elif command -v dnf &>/dev/null; then
        PKG_MGR="dnf"
    elif command -v yum &>/dev/null; then
        PKG_MGR="yum"
    elif command -v pacman &>/dev/null; then
        PKG_MGR="pacman"
    elif command -v apk &>/dev/null; then
        PKG_MGR="apk"
    elif command -v zypper &>/dev/null; then
        PKG_MGR="zypper"
    else
        error "Unsupported package manager. Install vsftpd manually and re-run."
    fi
    info "Detected package manager: $PKG_MGR"
}

install_vsftpd() {
    if command -v vsftpd &>/dev/null; then
        info "vsftpd is already installed."
        return
    fi
    detect_pkg_manager
    warn "vsftpd not found — installing..."
    case "$PKG_MGR" in
        apt)    apt-get update -qq && apt-get install -y -qq vsftpd ;;
        dnf)    dnf install -y -q vsftpd ;;
        yum)    yum install -y -q vsftpd ;;
        pacman) pacman -S --noconfirm vsftpd ;;
        apk)    apk add --quiet vsftpd ;;
        zypper) zypper install -y vsftpd ;;
    esac
    info "vsftpd installed."
}

# ---------------------------
# Detect init system
# ---------------------------
restart_vsftpd() {
    if command -v systemctl &>/dev/null && systemctl list-units --type=service &>/dev/null 2>&1; then
        systemctl restart vsftpd.service
        systemctl enable vsftpd.service 2>/dev/null || true
        info "vsftpd restarted & enabled (systemd)."
    elif command -v rc-service &>/dev/null; then
        rc-service vsftpd restart
        rc-update add vsftpd default 2>/dev/null || true
        info "vsftpd restarted & enabled (OpenRC)."
    elif command -v service &>/dev/null; then
        service vsftpd restart
        info "vsftpd restarted (SysVinit)."
    else
        warn "Could not detect init system — restart vsftpd manually."
    fi
}

# ---------------------------
# Locate vsftpd.conf
# ---------------------------
find_vsftpd_conf() {
    for path in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do
        if [[ -f "$path" ]]; then
            VSFTPD_CONF="$path"
            info "Found config: $VSFTPD_CONF"
            return
        fi
    done
    error "Cannot find vsftpd.conf. Is vsftpd installed?"
}

# ---------------------------
# Idempotent config setter
# ---------------------------
# Sets key=value in vsftpd.conf idempotently.
# Removes ALL existing lines (commented or not) for the key, then appends once.
# Uses POSIX BRE only ([[:space:]] not \s) for BusyBox/Alpine compat.
set_conf() {
    local key="$1" value="$2"
    # Delete any existing lines for this key (commented or uncommented)
    sed -i "/^#\{0,1\}[[:space:]]*${key}=/d" "$VSFTPD_CONF"
    # Append the canonical value
    echo "${key}=${value}" >> "$VSFTPD_CONF"
}

# Removes a key entirely from the config (for obsolete directives).
remove_conf() {
    local key="$1"
    sed -i "/^#\{0,1\}[[:space:]]*${key}=/d" "$VSFTPD_CONF"
}

# ======================================================================
# MAIN
# ======================================================================
install_vsftpd
find_vsftpd_conf

# --- Backup original config ---
BACKUP="${VSFTPD_CONF}.bak.$(date +%Y%m%d%H%M%S)"
cp "$VSFTPD_CONF" "$BACKUP"
info "Config backed up to: $BACKUP"

# --- Strip comments and blank lines for a clean baseline ---
# The backup preserves the original. Working config should be unambiguous.
sed -i '/^[[:space:]]*#/d; /^[[:space:]]*$/d' "$VSFTPD_CONF"
info "Stripped stale comments from config (original preserved in backup)."

# ---------------------------
# 1. Disable anonymous access
# ---------------------------
info "Disabling anonymous login..."
set_conf "anonymous_enable" "NO"

# Remove stale anonymous directives — if red team re-enables anonymous_enable,
# these pre-configured permissions would be waiting.
for key in anon_upload_enable anon_mkdir_write_enable anon_other_write_enable anon_umask; do
    remove_conf "$key"
done

# Cap max_clients to a sane value (default configs sometimes have 5000+)
set_conf "max_clients" "50"

# ---------------------------
# 2. Enable local users
# ---------------------------
info "Enabling local user login..."
set_conf "local_enable" "YES"
set_conf "write_enable" "YES"

# ---------------------------
# 3. Detect and configure chroot mode
# ---------------------------
# Priority:
#   1. Explicit ftp_root argument      → shared mode
#   2. Existing local_root in config   → shared mode (preserve what was there)
#   3. Neither found                   → per-user home directory mode

CHROOT_MODE=""
FTP_ROOT=""

if [[ -n "$FTP_ROOT_ARG" ]]; then
    # User explicitly passed a shared root
    CHROOT_MODE="shared"
    FTP_ROOT="$FTP_ROOT_ARG"
    info "Chroot mode: SHARED (from argument: $FTP_ROOT)"
else
    # Check the backup (pre-strip) for an existing local_root
    EXISTING_ROOT="$(grep -E "^[[:space:]]*local_root=" "$BACKUP" 2>/dev/null | tail -1 | cut -d= -f2 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')" || true
    if [[ -n "$EXISTING_ROOT" ]]; then
        CHROOT_MODE="shared"
        FTP_ROOT="$EXISTING_ROOT"
        info "Chroot mode: SHARED (detected from existing config: $FTP_ROOT)"
    else
        CHROOT_MODE="per-user"
        info "Chroot mode: PER-USER (no local_root found — each user gets their home dir)"
    fi
fi

info "Configuring chroot ($CHROOT_MODE)..."
set_conf "chroot_local_user" "YES"
remove_conf "allow_writeable_chroot"

if [[ "$CHROOT_MODE" == "shared" ]]; then
    set_conf "local_root" "$FTP_ROOT"
else
    # Per-user mode: remove local_root so vsftpd uses each user's home dir
    remove_conf "local_root"
fi

# ---------------------------
# 4. Listen configuration
# ---------------------------
# Explicitly set one listener to avoid "could not bind" conflicts
# when both listen and listen_ipv6 default to YES.
info "Configuring listen directives..."
set_conf "listen" "YES"
set_conf "listen_ipv6" "NO"

# ---------------------------
# 5. Create & populate userlist
# ---------------------------
USERLIST_FILE="/etc/vsftpd.userlist"
info "Building allowed userlist: $USERLIST_FILE"

: > "$USERLIST_FILE"          # truncate (idempotent)
chmod 600 "$USERLIST_FILE"

ADDED=0
SKIPPED=0
# read without IFS= so leading/trailing whitespace is trimmed by default
# || [[ -n "$user" ]] ensures the last line is processed even without a trailing newline
while read -r user || [[ -n "$user" ]]; do
    [[ -z "$user" || "$user" == \#* ]] && continue   # skip blanks/comments
    if id "$user" &>/dev/null; then
        echo "$user" >> "$USERLIST_FILE"
        ADDED=$((ADDED + 1))
    else
        warn "User '$user' does not exist on this system — skipped."
        SKIPPED=$((SKIPPED + 1))
    fi
done < "$USERLIST_INPUT"

info "Added $ADDED user(s) to whitelist ($SKIPPED skipped)."

if [[ "$ADDED" -eq 0 ]]; then
    warn "WARNING: No valid users in whitelist — ALL FTP logins will be denied!"
    warn "Verify your userlist.txt contains valid local usernames."
fi

set_conf "userlist_enable" "YES"
set_conf "userlist_file"   "$USERLIST_FILE"
set_conf "userlist_deny"   "NO"

# ---------------------------
# 6. PAM service name
# ---------------------------
# On RHEL/CentOS this must be set explicitly or PAM auth can fail.
info "Setting PAM service name..."
set_conf "pam_service_name" "vsftpd"

# ---------------------------
# 7. FTP root permissions
# ---------------------------
# Create ftp_users group if it doesn't exist
if ! getent group ftp_users &>/dev/null; then
    groupadd ftp_users
    info "Created group: ftp_users"
fi

# Add whitelisted users to ftp_users group
while read -r user || [[ -n "$user" ]]; do
    usermod -aG ftp_users "$user" 2>/dev/null || true
done < "$USERLIST_FILE"

# Helper: lock down a single chroot directory
# Usage: harden_chroot_dir <dir>
#   - dir itself: root-owned, 755 (vsftpd chroot requirement)
#   - dir/uploads: writable by ftp_users, setgid
#   - existing files: group-readable
harden_chroot_dir() {
    local dir="$1"
    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir"
        info "  Created: $dir"
    fi

    # Chroot root must be owned by root and not writable
    chown root:ftp_users "$dir"
    chmod 0755 "$dir"

    # Writable subdirectory for uploads
    local upload_dir="$dir/uploads"
    if [[ ! -d "$upload_dir" ]]; then
        mkdir -p "$upload_dir"
        info "  Created writable subdirectory: $upload_dir"
    fi
    chown root:ftp_users "$upload_dir"
    chmod 2775 "$upload_dir"

    # Fix ownership/permissions on all contents
    find "$dir" -mindepth 1 -type d -exec chown root:ftp_users {} + -exec chmod 2775 {} +
    find "$dir" -mindepth 1 -type f -exec chown root:ftp_users {} + -exec chmod 0664 {} +

    # Re-enforce chroot root (find -mindepth 1 won't touch it, but be safe)
    chmod 0755 "$dir"
}

if [[ "$CHROOT_MODE" == "shared" ]]; then
    info "Setting shared FTP root permissions on: $FTP_ROOT"
    harden_chroot_dir "$FTP_ROOT"
    info "Permissions applied (chroot root=755, uploads=2775, group=ftp_users)."
else
    info "Setting per-user home directory permissions..."
    while read -r user || [[ -n "$user" ]]; do
        home_dir="$(getent passwd "$user" 2>/dev/null | cut -d: -f6)" || true
        if [[ -z "$home_dir" || ! -d "$home_dir" ]]; then
            warn "  $user: home directory not found — skipping permissions"
            continue
        fi
        info "  Hardening: $user → $home_dir"
        harden_chroot_dir "$home_dir"
    done < "$USERLIST_FILE"
    info "Per-user permissions applied (each home=755, uploads/=2775, group=ftp_users)."
    warn "NOTE: Home directories are now root-owned and read-only (vsftpd chroot requirement)."
    warn "Users who also SSH in cannot write to ~ (only to ~/uploads/)."
    warn "If this is a problem, consider using a separate FTP-only directory structure."
fi

# ---------------------------
# 8. Passive mode (firewall-friendly)
# ---------------------------
info "Configuring passive mode..."
set_conf "pasv_enable"    "YES"
set_conf "pasv_min_port"  "40000"
set_conf "pasv_max_port"  "40100"
echo
warn "REMINDER: Open passive ports 40000-40100 in your firewall."
warn "  iptables:  iptables -A INPUT -p tcp --dport 40000:40100 -j ACCEPT"
warn "  firewalld: firewall-cmd --add-port=40000-40100/tcp --permanent && firewall-cmd --reload"
warn "  ufw:       ufw allow 40000:40100/tcp"
echo

# ---------------------------
# 9. Sanitize banner (no version leak)
# ---------------------------
info "Setting neutral FTP banner..."
set_conf "ftpd_banner" "Welcome to FTP service."

# ---------------------------
# 10. Logging
# ---------------------------
info "Enabling transfer & command logging..."
set_conf "xferlog_enable" "YES"
set_conf "xferlog_std_format" "YES"
set_conf "dual_log_enable" "YES"
set_conf "log_ftp_protocol" "YES"

# ---------------------------
# 11. TLS (optional — enable if cert exists)
# ---------------------------
TLS_CERT="/etc/ssl/certs/vsftpd.pem"
TLS_KEY="/etc/ssl/private/vsftpd.key"

if [[ -f "$TLS_CERT" && -f "$TLS_KEY" ]]; then
    info "TLS certificate found — enabling FTPS..."
    set_conf "ssl_enable"       "YES"
    set_conf "rsa_cert_file"    "$TLS_CERT"
    set_conf "rsa_private_key_file" "$TLS_KEY"
    set_conf "force_local_data_ssl"  "YES"
    set_conf "force_local_logins_ssl" "YES"
    set_conf "ssl_tlsv1"        "NO"
    set_conf "ssl_sslv2"        "NO"
    set_conf "ssl_sslv3"        "NO"
    set_conf "ssl_tlsv1_1"      "NO"
    set_conf "ssl_tlsv1_2"      "YES"
else
    remove_conf "ssl_enable"
    warn "No TLS cert found at $TLS_CERT — skipping TLS."
    warn "To enable TLS, generate a cert and re-run:"
    warn "  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \\"
    warn "    -keyout $TLS_KEY -out $TLS_CERT"
fi

# ---------------------------
# 12. Additional hardening
# ---------------------------
info "Applying additional hardening..."
# Remove obsolete tcp_wrappers (removed in vsftpd 3.0+, can cause startup failure)
remove_conf "tcp_wrappers"

set_conf "ls_recurse_enable"    "NO"
set_conf "local_umask"          "027"
set_conf "file_open_mode"       "0640"
set_conf "hide_ids"             "YES"       # show "ftp" instead of real uid/gid
set_conf "max_per_ip"           "3"         # limit concurrent connections per IP
set_conf "idle_session_timeout" "300"
set_conf "data_connection_timeout" "120"
set_conf "seccomp_sandbox"      "YES"       # restrict syscalls via seccomp

# ---------------------------
# Done — restart service
# ---------------------------
echo
info "Configuration complete. Restarting vsftpd..."
restart_vsftpd

echo
info "========================================="
info " vsftpd hardening applied successfully."
info " Config  : $VSFTPD_CONF"
info " Backup  : $BACKUP"
info " Users   : $USERLIST_FILE ($ADDED users)"
if [[ "$CHROOT_MODE" == "shared" ]]; then
    info " Mode    : Shared root → $FTP_ROOT"
    info " Uploads : $FTP_ROOT/uploads (writable)"
else
    info " Mode    : Per-user home directories"
    info " Uploads : ~<user>/uploads (writable)"
fi
info "========================================="
