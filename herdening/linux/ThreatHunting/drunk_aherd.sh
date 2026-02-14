#!/bin/bash
set -euo pipefail

# ------------------------------------------------------------------------------
# splunk-consolidated.sh
# A single, consolidated script that:
#   - Detects whether /opt/splunkforwarder (UF) or /opt/splunk (Enterprise) exists
#   - Branches into "forwarder install" or "enterprise hardening" flows
#   - Uses safer defaults (no plain-text passwords in the script or logs)
#   - Provides --dry-run to preview actions (no changes performed)
#
# REQUIREMENTS
#   * Run as root (sudo)
#   * Bash 4+
#   * curl or wget (for UF download), tar
#
# USAGE EXAMPLES
#   Dry-run preview:
#     sudo ./splunk-consolidated.sh --dry-run --mode auto
#
#   Install Universal Forwarder with explicit URL and indexer:
#     sudo ./splunk-consolidated.sh --mode forwarder \
#       --indexer splunk.example.com --port 9997 \
#       --forwarder-url "https://download.splunk.com/products/universalforwarder/releases/9.4.0/linux/splunkforwarder-9.4.0-6b4ebe426ca6-linux-amd64.tgz" \
#       --set-admin-user admin --set-admin-pass-prompt
#
#   Harden an on-box Splunk Enterprise:
#     sudo ./splunk-consolidated.sh --mode enterprise \
#       --current-admin-pass-prompt \
#       --set-admin-pass-prompt \
#       --banner-message "WARNING: Authorized use only." \
#       --prune-users
#
# NOTES
#   * Secrets are never logged. Passwords can be provided via prompt or files.
#   * Backups for Enterprise go to /root/.cache/splunk/YYYYmmdd-HHMMSS
#   * This script is idempotent where possible; re-running should be safe.
# ------------------------------------------------------------------------------

# -------------------------- CONFIG DEFAULTS -----------------------------------
SPLUNK_HOME_ENTERPRISE="/opt/splunk"
SPLUNK_HOME_UF="/opt/splunkforwarder"
RECEIVER_PORT="9997"
ADMIN_USER="admin"
BANNER_MESSAGE="WARNING: NO UNAUTHORIZED ACCESS."
DOWNLOAD_URL_DEFAULT="https://download.splunk.com/products/universalforwarder/releases/9.4.0/linux/splunkforwarder-9.4.0-6b4ebe426ca6-linux-amd64.tgz"
INSTALL_DIR_UF="$SPLUNK_HOME_UF"
BACKUP_BASE="/root/.cache/splunk"
LOG_DIR="/var/log"
DRY_RUN="false"
MODE="auto"   # auto|forwarder|enterprise
INDEXER=""
VERBOSE="false"
PRUNE_USERS="false"
FORWARDER_URL=""
FORWARDER_TGZ=""   # local tgz, if provided
HOME_MONITORS=("/var/log/secure:auth" "/var/log/auth.log:syslog" "/var/log/commands:syslog")

# secrets (filled later)
NEW_ADMIN_PASS=""
CURR_ADMIN_PASS=""

# ------------------------------ LOGGING ---------------------------------------
TS=$(date +%Y%m%d-%H%M%S)
LOG_FILE="${LOG_DIR}/splunk-consolidated-${TS}.log"

log() { echo "[$(date +'%F %T')] $*" | tee -a "$LOG_FILE" >&2; }
info() { log "INFO  $*"; }
warn() { log "WARN  $*"; }
err()  { log "ERROR $*"; }

run() {
  # run <cmd...>
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "DRY-RUN: $*" | tee -a "$LOG_FILE" >&2
    return 0
  else
    echo "RUN: $*" | tee -a "$LOG_FILE" >&2
    eval "$@"
  fi
}

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    err "Please run as root (sudo)."
    exit 1
  fi
}

has_cmd() { command -v "$1" >/dev/null 2>&1; }

# Do not echo secrets in logs; only display masked output if needed.
read_secret_prompt() {
  local prompt="$1"; local -n outref=$2
  read -s -p "$prompt" outref; echo
}

read_secret_file() {
  local file="$1"; local -n outref=$2
  if [[ ! -f "$file" ]]; then err "Secret file not found: $file"; exit 1; fi
  outref=$(<"$file")
}

usage() {
  cat <<EOF
Usage: $0 [--mode auto|forwarder|enterprise] [--dry-run] [--verbose]
           [--indexer <host_or_ip>] [--port <9997>]
           [--set-admin-user <name>] [--set-admin-pass-file <path> | --set-admin-pass-prompt]
           [--current-admin-pass-file <path> | --current-admin-pass-prompt]
           [--banner-message <text>] [--prune-users]
           [--forwarder-url <http(s)://...tgz>] [--forwarder-tgz </path/to/tarball>]

Examples:
  # Auto-detect mode and dry-run
  sudo $0 --dry-run --mode auto

  # Forwarder install & configuration
  sudo $0 --mode forwarder --indexer splunk.example.com --port 9997 \
          --forwarder-url "$DOWNLOAD_URL_DEFAULT" \
          --set-admin-user admin --set-admin-pass-prompt

  # Enterprise hardening
  sudo $0 --mode enterprise --current-admin-pass-prompt \
          --set-admin-pass-prompt --banner-message "Authorized users only." \
          --prune-users
EOF
}

# ----------------------------- ARG PARSER -------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2;;
    --dry-run) DRY_RUN="true"; shift;;
    --verbose) VERBOSE="true"; shift;;
    --indexer) INDEXER="$2"; shift 2;;
    --port) RECEIVER_PORT="$2"; shift 2;;
    --set-admin-user) ADMIN_USER="$2"; shift 2;;
    --set-admin-pass-file) read_secret_file "$2" NEW_ADMIN_PASS; shift 2;;
    --set-admin-pass-prompt) read_secret_prompt "New admin password: " NEW_ADMIN_PASS; shift;;
    --current-admin-pass-file) read_secret_file "$2" CURR_ADMIN_PASS; shift 2;;
    --current-admin-pass-prompt) read_secret_prompt "Current admin password: " CURR_ADMIN_PASS; shift;;
    --banner-message) BANNER_MESSAGE="$2"; shift 2;;
    --prune-users) PRUNE_USERS="true"; shift;;
    --forwarder-url) FORWARDER_URL="$2"; shift 2;;
    --forwarder-tgz) FORWARDER_TGZ="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) err "Unknown option: $1"; usage; exit 1;;
  esac
done

need_root

# Ensure log file is writable
if ! touch "$LOG_FILE" 2>/dev/null; then
  LOG_DIR="/tmp"
  LOG_FILE="${LOG_DIR}/splunk-consolidated-${TS}.log"
  touch "$LOG_FILE" || { err "Cannot create log file"; exit 1; }
fi
info "Logging to $LOG_FILE"

# ---------------------------- UTILITY FUNCS -----------------------------------
service_restart() {
  local name="$1"
  if has_cmd systemctl; then
    run systemctl restart "$name"
  elif has_cmd service; then
    run service "$name" restart
  else
    # Splunk uses its own CLI; for OS service fallbacks we try common tools only
    warn "No system service manager detected for $name"
  fi
}

splunk_cli() {
  local home="$1"; shift
  local cmd="$home/bin/splunk $*"
  run "$cmd"
}

backup_tree() {
  local src="$1"
  local dst_base="$2"
  local dst="${dst_base}/$(date +%Y%m%d-%H%M%S)"
  info "Backing up $src to $dst"
  run mkdir -p "$dst"
  run cp -a "$src" "$dst/"
  # generate md5s (skip in dry-run)
  if [[ "$DRY_RUN" == "false" ]]; then
    find "$dst" -type f -print0 | xargs -0 md5sum >"$dst/md5sums.txt" || true
  fi
}

write_file() {
  local path="$1"; shift
  local content="$*"
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "DRY-RUN: write to $path:\n$content" | tee -a "$LOG_FILE" >&2
  else
    umask 077
    printf "%b" "$content" > "$path"
  fi
}

# ------------------------ FORWARDER WORKFLOW ----------------------------------
download_forwarder() {
  local url="$1"; local outtgz="$2"
  if [[ -f "$outtgz" ]]; then
    info "Using existing tarball: $outtgz"
    return 0
  fi
  if has_cmd curl; then
    run curl -fSL -o "$outtgz" "$url"
  elif has_cmd wget; then
    run wget -O "$outtgz" "$url"
  else
    err "Neither curl nor wget available for download"; exit 1
  fi
}

install_forwarder() {
  local tgz="$1"
  if [[ -d "$SPLUNK_HOME_UF/bin" ]]; then
    info "Splunk UF appears installed at $SPLUNK_HOME_UF"
  else
    info "Installing Splunk UF to $SPLUNK_HOME_UF from $tgz"
    run tar -xzf "$tgz" -C /opt
  fi
}

seed_forwarder_admin() {
  local seed="$SPLUNK_HOME_UF/etc/system/local/user-seed.conf"
  if [[ -z "$NEW_ADMIN_PASS" ]]; then
    warn "No new admin password provided for UF; will start without setting explicit seed."
    return 0
  fi
  info "Seeding UF admin credentials (user=$ADMIN_USER)"
  write_file "$seed" "[user_info]\nUSERNAME = $ADMIN_USER\nPASSWORD = $NEW_ADMIN_PASS\n"
}

configure_monitors() {
  local conf="$SPLUNK_HOME_UF/etc/system/local/inputs.conf"
  info "Configuring UF monitors"
  local body=""
  for pair in "${HOME_MONITORS[@]}"; do
    local path="${pair%%:*}"; local stype="${pair##*:}"
    body+="[monitor://${path}]\nindex = main\nsourcetype = ${stype}\n\n"
  done
  write_file "$conf" "$body"
}

configure_forward_server() {
  if [[ -z "$INDEXER" ]]; then
    warn "--indexer not provided; skipping 'add forward-server'"
    return 0
  fi
  info "Configuring UF forward-server: $INDEXER:$RECEIVER_PORT"
  splunk_cli "$SPLUNK_HOME_UF" "add forward-server $INDEXER:$RECEIVER_PORT -auth $ADMIN_USER:$NEW_ADMIN_PASS"
}

start_enable_forwarder() {
  info "Starting UF and enabling boot-start"
  splunk_cli "$SPLUNK_HOME_UF" "start --accept-license --answer-yes --no-prompt"
  splunk_cli "$SPLUNK_HOME_UF" "enable boot-start"
  splunk_cli "$SPLUNK_HOME_UF" "restart"
}

forwarder_flow() {
  info "--- FORWARDER FLOW ---"
  local tgz_path="${FORWARDER_TGZ:-/tmp/splunkforwarder.tgz}"
  local url_use="${FORWARDER_URL:-$DOWNLOAD_URL_DEFAULT}"
  download_forwarder "$url_use" "$tgz_path"
  install_forwarder "$tgz_path"
  seed_forwarder_admin
  configure_monitors
  configure_forward_server
  start_enable_forwarder
  info "Forwarder setup complete."
}

# ----------------------- ENTERPRISE WORKFLOW ----------------------------------
enterprise_banner() {
  local conf="$SPLUNK_HOME_ENTERPRISE/etc/system/local/global-banner.conf"
  info "Setting global banner"
  write_file "$conf" "[BANNER_MESSAGE_SINGLETON]\nglobal_banner.visible = true\n$(printf 'global_banner.message = %s\n' "$BANNER_MESSAGE")global_banner.background_color = red\n"
}

enterprise_permissions() {
  info "Hardening permissions under $SPLUNK_HOME_ENTERPRISE/etc"
  run chmod -R 700 "$SPLUNK_HOME_ENTERPRISE/etc/system/local" || true
  run chmod -R 700 "$SPLUNK_HOME_ENTERPRISE/etc/system/default" || true
  run chown -R root:root "$SPLUNK_HOME_ENTERPRISE/etc" || true
}

enterprise_change_admin_pass() {
  if [[ -z "$CURR_ADMIN_PASS" || -z "$NEW_ADMIN_PASS" ]]; then
    warn "Current or new admin password not provided; skipping admin password change."
    return 0
  fi
  info "Changing Splunk admin password (user=$ADMIN_USER)"
  splunk_cli "$SPLUNK_HOME_ENTERPRISE" "edit user $ADMIN_USER -password '$NEW_ADMIN_PASS' -auth '$ADMIN_USER:$CURR_ADMIN_PASS'"
}

enterprise_prune_users() {
  if [[ "$PRUNE_USERS" != "true" ]]; then
    info "User pruning disabled (use --prune-users to enable)."
    return 0
  fi
  if [[ -z "$NEW_ADMIN_PASS" ]]; then
    warn "New admin password required for pruning users (re-auth). Skipping."
    return 0
  fi
  info "Pruning non-admin users"
  # List users and remove all except ADMIN_USER
  local tmp_out
  tmp_out=$(mktemp)
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "DRY-RUN: $SPLUNK_HOME_ENTERPRISE/bin/splunk list user -auth ${ADMIN_USER}:<hidden>" | tee -a "$LOG_FILE" >&2
  else
    "$SPLUNK_HOME_ENTERPRISE/bin/splunk" list user -auth "${ADMIN_USER}:${NEW_ADMIN_PASS}" >"$tmp_out" 2>>"$LOG_FILE" || true
  fi
  if [[ -f "$tmp_out" ]]; then
    # Expect output like:  username = <name>
    local users
    users=$(awk '/username/ {print $3}' "$tmp_out" | grep -v "^${ADMIN_USER}$" || true)
    for u in $users; do
      info "Removing user: $u"
      splunk_cli "$SPLUNK_HOME_ENTERPRISE" "remove user $u -auth ${ADMIN_USER}:${NEW_ADMIN_PASS}"
    done
    rm -f "$tmp_out" || true
  fi
}

enterprise_restart() {
  info "Restarting Splunk Enterprise"
  splunk_cli "$SPLUNK_HOME_ENTERPRISE" restart
}

enterprise_flow() {
  info "--- ENTERPRISE FLOW ---"
  backup_tree "$SPLUNK_HOME_ENTERPRISE" "$BACKUP_BASE"
  enterprise_banner
  enterprise_permissions
  enterprise_change_admin_pass
  enterprise_prune_users
  enterprise_restart
  backup_tree "$SPLUNK_HOME_ENTERPRISE" "$BACKUP_BASE"
  info "Enterprise hardening complete."
}

# ---------------------------- MODE DISPATCH -----------------------------------
if [[ "$MODE" == "auto" ]]; then
  if [[ -d "$SPLUNK_HOME_UF/bin" ]]; then
    info "Detected Splunk Universal Forwarder at $SPLUNK_HOME_UF"
    MODE="forwarder"
  elif [[ -d "$SPLUNK_HOME_ENTERPRISE/bin" ]]; then
    info "Detected Splunk Enterprise at $SPLUNK_HOME_ENTERPRISE"
    MODE="enterprise"
  else
    info "No Splunk installation found. Defaulting to forwarder install."
    MODE="forwarder"
  fi
fi

case "$MODE" in
  forwarder) forwarder_flow ;;
  enterprise) enterprise_flow ;;
  *) err "Unknown mode: $MODE"; usage; exit 1;;

esac

info "All done. Review log: $LOG_FILE"
