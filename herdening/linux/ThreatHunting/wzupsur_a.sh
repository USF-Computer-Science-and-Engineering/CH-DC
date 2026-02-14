#!/bin/bash
set -euo pipefail

# ------------------------------------------------------------------------------
# Herd 2026 Wazuh Agent + Suricata (Emerging Threats rules) unified installer
#   - Installs and enrolls Wazuh Agent using an explicit agent NAME (preferred)
#     or, optionally, an enrollment PASSWORD if your manager enforces it.
#   - Supports Linux (APT, YUM/DNF, Zypper) and FreeBSD (pkg).
#   - Installs Suricata and loads Emerging Threats open rules by default.
#     Use --no-suricata if you only want the Wazuh agent.
#
# Requirements: root privileges
# ------------------------------------------------------------------------------

# ------------- Defaults and CLI parsing -------------
MANAGER=""
AGENT_NAME=""
AGENT_GROUP="${WAZUH_AGENT_GROUP:-}"
REG_SERVER=""
REG_PORT="1515"
PASSWORD="${WAZUH_REGISTRATION_PASSWORD:-}"
INSTALL_SURICATA="true"   # default ON per user request
HOME_NET=""              # optional CIDR or IP; if empty we'll try to detect host IP

usage() {
  cat <<'USAGE'
Usage:
  sudo ./wazuh-agent-suricata.sh \
    --manager <IP_or_FQDN> \
    --name <AGENT_NAME> \
    [--group <group[,group2,...]>] \
    [--reg-server <IP_or_FQDN>] \
    [--reg-port <1515>] \
    [--password <enrollment_password>] \
    [--home-net <CIDR_or_IP>] \
    [--no-suricata]

Notes
  * --name is REQUIRED and becomes the agent's display name.
  * --password is OPTIONAL (use only if your manager enforces password auth).
  * Enrollment uses TCP 1515; data channel uses TCP 1514.
USAGE
}

# Parse args
while [ $# -gt 0 ]; do
  case "$1" in
    --manager) MANAGER="$2"; shift 2;;
    --name) AGENT_NAME="$2"; shift 2;;
    --group) AGENT_GROUP="$2"; shift 2;;
    --reg-server) REG_SERVER="$2"; shift 2;;
    --reg-port) REG_PORT="$2"; shift 2;;
    --password) PASSWORD="$2"; shift 2;;
    --home-net) HOME_NET="$2"; shift 2;;
    --no-suricata) INSTALL_SURICATA="false"; shift 1;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown option: $1" >&2; usage; exit 1;;
  esac
done

if [ -z "$MANAGER" ] || [ -z "$AGENT_NAME" ]; then
  echo "ERROR: --manager and --name are required." >&2
  usage
  exit 1
fi
REG_SERVER="${REG_SERVER:-$MANAGER}"

require_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "Please run as root."
    exit 1
  fi
}

has_cmd() { command -v "$1" >/dev/null 2>&1; }

service_restart() {
  # Usage: service_restart <name>
  local name="$1"
  if has_cmd systemctl; then
    systemctl restart "$name" || systemctl start "$name" || true
  elif has_cmd service; then
    service "$name" restart || service "$name" start || true
  elif has_cmd rc-service; then
    rc-service "$name" restart || rc-service "$name" start || true
  else
    # FreeBSD service
    if [ "$(uname -s)" = "FreeBSD" ] && has_cmd service; then
      service "$name" restart || service "$name" start || true
    fi
  fi
}

service_enable() {
  # Usage: service_enable <name>
  local name="$1"
  if has_cmd systemctl; then
    systemctl enable "$name" || true
  elif [ "$(uname -s)" = "FreeBSD" ] && has_cmd sysrc; then
    sysrc -f /etc/rc.conf "${name}_enable=YES" >/dev/null || true
  fi
}

ossec_bin_dir() {
  if [ -x /var/ossec/bin/agent-auth ]; then echo "/var/ossec/bin"; return; fi
  if [ -x /usr/local/var/ossec/bin/agent-auth ]; then echo "/usr/local/var/ossec/bin"; return; fi
  echo "/var/ossec/bin"
}

enable_and_start_agent() {
  service_enable wazuh-agent
  service_restart wazuh-agent
}

enroll_with_name() {
  # Build command with optional -P
  local bin
  bin="$(ossec_bin_dir)"
  if [ -z "$PASSWORD" ]; then
    "$bin/agent-auth" -A "$AGENT_NAME" -m "$REG_SERVER" -p "$REG_PORT"
  else
    "$bin/agent-auth" -A "$AGENT_NAME" -m "$REG_SERVER" -p "$REG_PORT" -P "$PASSWORD"
  fi
}

linux_install_agent() {
  echo "[*] Installing Wazuh agent on Linux..."
  require_root

  # Export deployment variables so postinst auto-configures the agent
  export WAZUH_MANAGER="$MANAGER"
  export WAZUH_REGISTRATION_SERVER="$REG_SERVER"
  export WAZUH_REGISTRATION_PASSWORD="${PASSWORD:-}"
  export WAZUH_AGENT_NAME="$AGENT_NAME"
  export WAZUH_AGENT_GROUP="$AGENT_GROUP"

  if has_cmd apt-get; then
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
    zypper -n addrepo https://packages.wazuh.com/4.x/yum/ wazuh || true
    zypper -n refresh || true
    zypper -n install wazuh-agent

  else
    echo "ERROR: Unsupported Linux package manager (APT/YUM/DNF/ZYpp expected)." >&2
    exit 1
  fi

  enable_and_start_agent

  # Ensure connected; if not, force enrollment with name.
  local state
  state="/var/ossec/var/run/wazuh-agentd.state"
  if [ ! -f "$state" ] || ! grep -q "status=connected" "$state" 2>/dev/null; then
    enroll_with_name || true
    enable_and_start_agent
  fi
  echo "[+] Linux: Wazuh agent installed and enrolled as '$AGENT_NAME'."
}

freebsd_install_agent() {
  echo "[*] Installing Wazuh agent on FreeBSD..."
  require_root
  env ASSUME_ALWAYS_YES=yes pkg update -f || true
  env ASSUME_ALWAYS_YES=yes pkg install -y wazuh-agent

  # If password is required by the manager, create authd.pass
  if [ -n "$PASSWORD" ]; then
    echo "$PASSWORD" > /var/ossec/etc/authd.pass
    chmod 640 /var/ossec/etc/authd.pass
  fi

  # Ensure manager address exists in ossec.conf
  if [ -f /var/ossec/etc/ossec.conf ] && ! grep -q "<address>" /var/ossec/etc/ossec.conf; then
    awk -v m="$MANAGER" '
      /<client>/ && c==0 {print; print "  <server>\n    <address>" m "</address>\n  </server>"; c=1; next} {print}
    ' /var/ossec/etc/ossec.conf > /var/ossec/etc/ossec.conf.new && mv /var/ossec/etc/ossec.conf.new /var/ossec/etc/ossec.conf
  fi

  enable_and_start_agent
  enroll_with_name || true
  enable_and_start_agent
  echo "[+] FreeBSD: Wazuh agent installed and enrolled as '$AGENT_NAME'."
}

install_suricata_and_rules() {
  echo "[*] Installing Suricata and Emerging Threats rules..."

  if [ "$(uname -s)" = "FreeBSD" ]; then
    env ASSUME_ALWAYS_YES=yes pkg install -y suricata || true
  elif has_cmd apt-get; then
    # Use OISF PPA for Ubuntu/Debian
    if has_cmd add-apt-repository; then
      add-apt-repository ppa:oisf/suricata-stable -y >/dev/null 2>&1 || true
    fi
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y suricata >/dev/null 2>&1 || true
  elif has_cmd dnf || has_cmd yum; then
    (has_cmd dnf && dnf -y install epel-release) || (has_cmd yum && yum -y install epel-release) || true
    (has_cmd dnf && dnf -y install suricata) || (has_cmd yum && yum -y install suricata) || true
  elif has_cmd zypper; then
    zypper -n install suricata || true
  else
    echo "[!] Could not determine package manager for Suricata; skipping installation." >&2
    return 0
  fi

  # Download Emerging Threats open rules
  tmpd="$(mktemp -d)"; trap 'rm -rf "$tmpd"' EXIT
  ( cd "$tmpd" && \
    curl -fsSLO https://rules.emergingthreats.net/open/suricata-6.0.8/emerging.rules.tar.gz \
      || wget -q https://rules.emergingthreats.net/open/suricata-6.0.8/emerging.rules.tar.gz \
      || fetch -q https://rules.emergingthreats.net/open/suricata-6.0.8/emerging.rules.tar.gz )
  tar -xzf "$tmpd/emerging.rules.tar.gz" -C "$tmpd"
  mkdir -p /etc/suricata/rules
  cp -f "$tmpd"/rules/*.rules /etc/suricata/rules/
  chmod 0644 /etc/suricata/rules/*.rules || true

  # Configure suricata.yaml minimally
  CONF="/etc/suricata/suricata.yaml"
  if [ ! -f "$CONF" ]; then
    echo "[!] Suricata config not found at $CONF; skipping config edits." >&2
    return 0
  fi

  # Determine interface and HOME_NET value
  local_iface=""
  local_ip_cidr=""
  local_ip=""
  if has_cmd ip; then
    local_iface="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
    [ -z "$local_iface" ] && local_iface="eth0"
    local_ip_cidr="$(ip -4 addr show "$local_iface" 2>/dev/null | awk '/inet / {print $2; exit}')"
    local_ip="${local_ip_cidr%%/*}"
  fi
  # HOME_NET preference: CLI --home-net, else detected local_ip, else leave untouched
  if [ -n "$HOME_NET" ]; then
    hn="$HOME_NET"
  else
    hn="$local_ip"
  fi

  # Edits (best-effort, tolerant)
  if [ -n "$hn" ]; then
    sed -i -e "s|^ *HOME_NET:.*|    HOME_NET: \"${hn}\"|" "$CONF" || true
  fi
  sed -i -e "s|^ *EXTERNAL_NET:.*|    EXTERNAL_NET: \"any\"|" "$CONF" || true
  sed -i -e "s|^ *default-rule-path:.*|default-rule-path: /etc/suricata/rules|" "$CONF" || true

  if grep -q "^ *rule-files:" "$CONF"; then
    if ! awk '/^ *rule-files:/{flag=1;next}/^[^[:space:]]/{flag=0}flag' "$CONF" | grep -q '"\*.rules"'; then
      sed -i -e "/^ *rule-files:/a\
  - \"*.rules\"" "$CONF"
    fi
  else
    sed -i -e "/^ *default-rule-path:/a\
rule-files:\
  - \"*.rules\"" "$CONF"
  fi

  if grep -q "^ *stats:" "$CONF"; then
    sed -i -e "/^ *stats:/,/^[a-z]/ s|^ *enabled:.*|  enabled: yes|" "$CONF" || true
  else
    sed -i -e "/^# Global stats configuration/a\
stats:\
  enabled: yes" "$CONF" || true
  fi

  if [ -n "$local_iface" ]; then
    sed -i -e "/^af-packet:/,/^[a-z]/ s|^  - interface:.*|  - interface: ${local_iface}|" "$CONF" || true
  fi

  # Validate and restart
  if has_cmd suricata; then
    suricata -T -c "$CONF" >/dev/null 2>&1 || echo "[!] Suricata config test failed; please review $CONF." >&2
  fi
  service_restart suricata
  echo "[+] Suricata configured (HOME_NET='${hn:-unchanged}', rules loaded)."
}

main() {
  case "$(uname -s)" in
    Linux)   linux_install_agent ;;
    FreeBSD) freebsd_install_agent ;;
    *) echo "Unsupported OS: $(uname -s)"; exit 1;;
  esac

  if [ "$INSTALL_SURICATA" = "true" ]; then
    install_suricata_and_rules
  else
    echo "[*] Skipping Suricata installation (per --no-suricata)."
  fi

  echo "-------------------------------------------------------------------"
  echo " Manager:    $MANAGER"
  echo " Name:       $AGENT_NAME"
  [ -n "$AGENT_GROUP" ] && echo " Groups:     $AGENT_GROUP"
  [ -n "$PASSWORD" ] && echo " Password:   [set]"
  echo " Enrollment: Server ${REG_SERVER}:${REG_PORT}"
  if [ -f /var/ossec/var/run/wazuh-agentd.state ]; then
    grep -q "status=connected" /var/ossec/var/run/wazuh-agentd.state 2>/dev/null && \
      echo " Status:     connected" || echo " Status:     pending/unknown"
  else
    echo " Status:     unknown"
  fi
}

main "$@"
