#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------------------------
#  Herd Wazuh Agent Installer + Enroller (agent name–first)
#  - Installs and enrolls a Wazuh agent using a specific AGENT NAME.
#  - Supports Linux (APT / YUM / DNF / Zypper) and FreeBSD (pkg).
#  - Optional password if your manager enforces password auth.
#  - Optional Suricata install via --with-suricata.
#
# Docs referenced:
#  * Deployment variables (WAZUH_AGENT_NAME, etc.)  -> Wazuh docs.        (Linux) 
#  * agent-auth -A <name>                           -> Wazuh tools docs.
#  * Linux package install flows                    -> Wazuh install docs.
#  * FreeBSD package/port availability              -> pkgs.org / FreeBSD status.
# ------------------------------------------------------------------------------

# --------- Defaults / CLI ---------
MANAGER=""
AGENT_NAME=""
AGENT_GROUP="${WAZUH_AGENT_GROUP:-}"
REG_SERVER=""
REG_PORT="1515"
PASSWORD="${WAZUH_REGISTRATION_PASSWORD:-}"
WAZUH_VERSION="${WAZUH_VERSION:-}"      # optional pin
WITH_SURICATA="false"

usage() {
  cat <<'USAGE'
Usage:
  wazuh-agent-install.sh \
    --manager <IP_or_FQDN> \
    --name <AGENT_NAME> \
    [--group <group[,group2,...]>] \
    [--reg-server <IP_or_FQDN>] \
    [--reg-port <1515>] \
    [--password <enrollment_password>] \
    [--version <4.x.y>] \
    [--with-suricata]

Details
  * --name is REQUIRED and becomes the agent's display name.
  * --password is OPTIONAL (use only if your manager enforces password auth).
  * Enrollment happens on TCP 1515 (default); data channel uses 1514/TCP. 
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manager) MANAGER="$2"; shift 2;;
    --name) AGENT_NAME="$2"; shift 2;;
    --group) AGENT_GROUP="$2"; shift 2;;
    --reg-server) REG_SERVER="$2"; shift 2;;
    --reg-port) REG_PORT="$2"; shift 2;;
    --password) PASSWORD="$2"; shift 2;;
    --version) WAZUH_VERSION="$2"; shift 2;;
    --with-suricata) WITH_SURICATA="true"; shift 1;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown option: $1"; usage; exit 1;;
  esac
done

if [[ -z "$MANAGER" || -z "$AGENT_NAME" ]]; then
  echo "ERROR: --manager and --name are required." >&2
  usage
  exit 1
fi
REG_SERVER="${REG_SERVER:-$MANAGER}"

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Please run as root."
    exit 1
  fi
}

has_cmd() { command -v "$1" >/dev/null 2>&1; }

ossec_bin_dir() {
  # Common install path is /var/ossec on Linux/FreeBSD; check both.
  if [[ -x /var/ossec/bin/agent-auth ]]; then echo "/var/ossec/bin"; return; fi
  if [[ -x /usr/local/var/ossec/bin/agent-auth ]]; then echo "/usr/local/var/ossec/bin"; return; fi
  echo "/var/ossec/bin"  # best effort
}

enable_and_start_agent() {
  if has_cmd systemctl; then
    systemctl daemon-reload || true
    systemctl enable wazuh-agent || true
    systemctl restart wazuh-agent || systemctl start wazuh-agent
  elif has_cmd service; then
    service wazuh-agent start || true
  elif has_cmd rc-service; then
    rc-service wazuh-agent start || true
  elif [[ "$(uname -s)" == "FreeBSD" ]]; then
    sysrc -f /etc/rc.conf wazuh_agent_enable="YES" >/dev/null
    service wazuh-agent restart || service wazuh-agent start || true
  fi
}

enroll_with_name() {
  local BIN
  BIN="$(ossec_bin_dir)"
  local cmd=("$BIN/agent-auth" -A "$AGENT_NAME" -m "$REG_SERVER" -p "$REG_PORT")
  # If manager enforces password auth, pass it explicitly:
  if [[ -n "${PASSWORD:-}" ]]; then cmd+=(-P "$PASSWORD"); fi
  "${cmd[@]}"
}

linux_install() {
  echo "[*] Installing Wazuh agent on Linux..."
  require_root

  # Export deployment variables so the package post-install configures the agent. 
  # (WAZUH_AGENT_NAME, WAZUH_MANAGER, optional PASSWORD/GROUP) 
  export WAZUH_MANAGER="$MANAGER"
  export WAZUH_REGISTRATION_SERVER="$REG_SERVER"
  export WAZUH_REGISTRATION_PASSWORD="${PASSWORD:-}"
  export WAZUH_AGENT_NAME="$AGENT_NAME"
  export WAZUH_AGENT_GROUP="$AGENT_GROUP"

  if has_cmd apt-get; then
    # APT repo + install (per Wazuh docs).
    apt-get update -y
    apt-get install -y gnupg apt-transport-https curl
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
      | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
    chmod 644 /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list
    apt-get update -y
    apt-get install -y wazuh-agent

  elif has_cmd dnf || has_cmd yum; then
    # YUM/DNF repo + install.
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
    cat >/etc/yum.repos.d/wazuh.repo <<'EOF'
[wazuh]
name=Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
EOF
    if has_cmd dnf; then dnf -y install wazuh-agent; else yum -y install wazuh-agent; fi

  elif has_cmd zypper; then
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
    zypper -n addrepo https://packages.wazuh.com/4.x/yum/ wazuh
    zypper -n refresh
    zypper -n install wazuh-agent

  else
    echo "ERROR: Unsupported Linux package manager (APT/YUM/DNF/ZYpp expected)."
    echo "See packages list if you need manual download: https://documentation.wazuh.com/current/installation-guide/packages-list.html"
    exit 1
  fi

  enable_and_start_agent

  # If not connected yet, enroll explicitly with the requested name.
  local STATE="/var/ossec/var/run/wazuh-agentd.state"
  if [[ ! -f "$STATE" ]] || ! grep -q "status=connected" "$STATE"; then
    enroll_with_name
    enable_and_start_agent
  fi

  echo "[+] Linux: Wazuh agent installed and enrolled as '$AGENT_NAME'."
}

freebsd_install() {
  echo "[*] Installing Wazuh agent on FreeBSD..."
  require_root

  # Use official FreeBSD package/port for wazuh-agent.
  env ASSUME_ALWAYS_YES=yes pkg update -f || true
  env ASSUME_ALWAYS_YES=yes pkg install -y wazuh-agent

  # Pre-seed minimal client settings via env variables is not standard on FreeBSD pkg;
  # ensure enrollment with agent-auth using the desired name:
  if [[ -n "${PASSWORD:-}" ]]; then
    echo "$PASSWORD" > /var/ossec/etc/authd.pass
    chmod 640 /var/ossec/etc/authd.pass
  fi

  # Ensure manager is present in ossec.conf <client>/<server>/<address>:
  if [[ -f /var/ossec/etc/ossec.conf ]] && ! grep -q "<address>" /var/ossec/etc/ossec.conf; then
    awk -v m="$MANAGER" '
      /<client>/ && c==0 {print; print "  <server>\n    <address>" m "</address>\n  </server>"; c=1; next} {print}
    ' /var/ossec/etc/ossec.conf > /var/ossec/etc/ossec.conf.new && mv /var/ossec/etc/ossec.conf.new /var/ossec/etc/ossec.conf
  fi

  enable_and_start_agent
  enroll_with_name
  enable_and_start_agent
  echo "[+] FreeBSD: Wazuh agent installed and enrolled as '$AGENT_NAME'."
}

install_suricata_if_requested() {
  [[ "$WITH_SURICATA" != "true" ]] && return 0

  echo "[*] Installing Suricata (as requested)..."
  if has_cmd apt-get; then
    apt-get update -y
    apt-get install -y suricata auditd || true
  elif has_cmd dnf || has_cmd yum; then
    (has_cmd dnf && dnf -y install epel-release) || (has_cmd yum && yum -y install epel-release) || true
    (has_cmd dnf && dnf -y install suricata audit) || (has_cmd yum && yum -y install suricata audit) || true
  elif [[ "$(uname -s)" == "FreeBSD" ]]; then
    env ASSUME_ALWAYS_YES=yes pkg install -y suricata || true
  else
    echo "[!] Suricata install skipped: unsupported pkg manager on this system."
  fi
}

main() {
  case "$(uname -s)" in
    Linux)   linux_install ;;
    FreeBSD) freebsd_install ;;
    *) echo "Unsupported OS: $(uname -s)"; exit 1;;
  esac

  install_suricata_if_requested

  echo "-------------------------------------------------------------------"
  echo " Manager:    $MANAGER"
  echo " Name:       $AGENT_NAME"
  [[ -n "$AGENT_GROUP" ]] && echo " Groups:     $AGENT_GROUP"
  [[ -n "$PASSWORD" ]] && echo " Password:   [set]"
  echo " Enrollment: Server ${REG_SERVER}:${REG_PORT}"
  echo " Status:     $(grep -o 'status=[^ ]*' /var/ossec/var/run/wazuh-agentd.state 2>/dev/null || echo unknown)"
}

main "$@"
