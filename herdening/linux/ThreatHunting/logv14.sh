#!/bin/sh
#
#  NOTE: The first batch of audit events after running this script will be
#  noise from the setup itself (writing to /etc/audit/, /etc/rsyslog.d/, etc).
#  This is expected and can be ignored.
# ============================================================================

# --- Colors for output ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Helper functions ---
log_info()    { printf "${GREEN}[+]${NC} %s\n" "$1"; }
log_warn()    { printf "${YELLOW}[!]${NC} %s\n" "$1"; }
log_error()   { printf "${RED}[-]${NC} %s\n" "$1"; }
log_section() { printf "\n${CYAN}=== %s ===${NC}\n" "$1"; }

# --- Root check ---
if [ "$(id -u)" -ne 0 ]; then
    log_error "This script must be run as root (or with sudo)."
    exit 1
fi

# --- Detect package manager ---
detect_pkg_mgr() {
    if command -v apt-get >/dev/null 2>&1; then
        PKG_MGR="apt"
    elif command -v dnf >/dev/null 2>&1; then
        PKG_MGR="dnf"
    elif command -v yum >/dev/null 2>&1; then
        PKG_MGR="yum"
    elif command -v zypper >/dev/null 2>&1; then
        PKG_MGR="zypper"
    elif command -v pacman >/dev/null 2>&1; then
        PKG_MGR="pacman"
    else
        log_error "No supported package manager found."
        exit 1
    fi
    log_info "Detected package manager: $PKG_MGR"
}

install_pkg() {
    case "$PKG_MGR" in
        apt)    apt-get install -y "$1" ;;
        dnf)    dnf install -y "$1" ;;
        yum)    yum install -y "$1" ;;
        zypper) zypper install -y "$1" ;;
        pacman) pacman -S --noconfirm "$1" ;;
    esac
}

# --- Detect init system ---
detect_init() {
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        INIT="systemd"
    elif command -v rc-service >/dev/null 2>&1; then
        INIT="openrc"
    elif [ -f /etc/init.d/auditd ]; then
        INIT="sysvinit"
    else
        INIT="unknown"
    fi
    log_info "Detected init system: $INIT"
}

svc_enable_start() {
    _svc="$1"
    case "$INIT" in
        systemd)
            systemctl enable "$_svc" 2>/dev/null || true
            systemctl restart "$_svc" 2>/dev/null || systemctl start "$_svc" 2>/dev/null || true
            ;;
        openrc)
            rc-update add "$_svc" default 2>/dev/null || true
            rc-service "$_svc" restart 2>/dev/null || rc-service "$_svc" start 2>/dev/null || true
            ;;
        sysvinit)
            if command -v update-rc.d >/dev/null 2>&1; then
                update-rc.d "$_svc" defaults 2>/dev/null || true
            elif command -v chkconfig >/dev/null 2>&1; then
                chkconfig "$_svc" on 2>/dev/null || true
            fi
            /etc/init.d/"$_svc" restart 2>/dev/null || /etc/init.d/"$_svc" start 2>/dev/null || true
            ;;
        *)
            log_warn "Unknown init system - please start $_svc manually."
            ;;
    esac
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

log_section "Linux Logging Setup"
log_info "Starting at $(date)"

detect_pkg_mgr
detect_init

# --- Check for previous run ---
if [ -f /etc/audit/rules.d/99-ccdc.rules ] || grep -q "Competition Configuration" /etc/audit/auditd.conf 2>/dev/null; then
    log_warn "This script appears to have already run."
    log_warn "Re-running will overwrite current config. Previous backups preserved."
fi

BACKUP_DIR="/root/logging_backup_$(date +%Y%m%d%H%M%S)"
mkdir -p "$BACKUP_DIR"
log_info "Backup directory: $BACKUP_DIR"

# ============================================================================
# STEP 1: Install required packages
# ============================================================================
log_section "Installing Packages"

if ! command -v auditctl >/dev/null 2>&1; then
    log_info "Installing auditd..."
    case "$PKG_MGR" in
        apt)     install_pkg auditd; install_pkg audispd-plugins 2>/dev/null || true ;;
        yum|dnf) install_pkg audit ;;
        *)       install_pkg audit ;;
    esac
else
    log_info "auditd already installed."
fi

if ! command -v lastcomm >/dev/null 2>&1; then
    log_info "Installing process accounting..."
    case "$PKG_MGR" in
        apt)     install_pkg acct ;;
        yum|dnf) install_pkg psacct ;;
        *)       install_pkg acct 2>/dev/null || log_warn "Could not install process accounting." ;;
    esac
else
    log_info "Process accounting already installed."
fi

if ! command -v rsyslogd >/dev/null 2>&1; then
    log_info "Installing rsyslog..."
    install_pkg rsyslog 2>/dev/null || log_warn "Could not install rsyslog. Skipping."
else
    log_info "rsyslog already installed."
fi

# ============================================================================
# STEP 2: Configure auditd.conf
# ============================================================================
log_section "Configuring auditd.conf"

AUDITD_CONF="/etc/audit/auditd.conf"
[ -f "$AUDITD_CONF" ] && cp -p "$AUDITD_CONF" "$BACKUP_DIR/"

# NOTE: log_format=ENRICHED requires auditd >=2.8. If this box runs
# RHEL/CentOS 7 or older, change ENRICHED to RAW below.
cat > "$AUDITD_CONF" << 'AUDITD_CONF_EOF'
#
# auditd.conf - Competition Configuration
#

local_events = yes
log_file = /var/log/audit/audit.log
log_format = ENRICHED
log_group = root
priority_boost = 4
flush = INCREMENTAL_ASYNC
freq = 50
num_logs = 10
max_log_file = 50
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
admin_space_left = 50
admin_space_left_action = SYSLOG
disk_full_action = SYSLOG
disk_error_action = SYSLOG

# DO NOT halt the system on audit failure during competition.
# Losing logs is bad. Losing the box is worse.
overflow_action = SYSLOG

name_format = HOSTNAME
AUDITD_CONF_EOF

log_info "auditd.conf written."

# ============================================================================
# STEP 3: Deploy Audit Rules
# ============================================================================
log_section "Deploying Audit Rules"

if [ -d /etc/audit/rules.d ]; then
    RULES_DIR="/etc/audit/rules.d"
    for f in "$RULES_DIR"/*.rules; do
        [ -f "$f" ] && cp -p "$f" "$BACKUP_DIR/" 2>/dev/null
    done
    RULES_FILE="$RULES_DIR/99-ccdc.rules"
else
    RULES_FILE="/etc/audit/audit.rules"
    [ -f "$RULES_FILE" ] && cp -p "$RULES_FILE" "$BACKUP_DIR/"
fi

log_info "Writing rules to: $RULES_FILE"

cat > "$RULES_FILE" << 'AUDIT_RULES_EOF'
# ============================================================================
# Audit Rules - Competition Configuration
# ============================================================================
# Organized: Exclusions first (first-match-wins), then watches by priority.
# All rules tagged with -k keys for searching via ausearch -k <key>.
# ============================================================================

# Clear existing rules
-D

# Buffer: large enough for competition load
-b 8192

# Backlog wait: max time (ms) kernel blocks when backlog is full.
# 60000 = 60s. Prevents indefinite hangs under heavy load.
--backlog_wait_time 60000

# Failure mode: 1 = printk (log and continue). NEVER use 2 (panic) in competition.
-f 1

# Rate limit: 0 = unlimited. We want everything.
-r 0

# Ignore errors from paths that don't exist on this system
-i

# ============================================================================
# NOISE REDUCTION (first-match-wins, so exclusions go first)
# ============================================================================

-a always,exclude -F msgtype=EOE
-a always,exclude -F msgtype=AVC
-a always,exclude -F msgtype=CRYPTO_KEY_USER

# Cron daemon noise (portable - works with or without SELinux)
# We still catch crontab file modifications via watches below.
-a never,exit -F exe=/usr/sbin/cron
-a never,exit -F exe=/usr/sbin/crond
-a never,exit -F exe=/usr/sbin/anacron

# ============================================================================
# SELF-AUDITING - Protect the audit trail
# T1070.002 - Clear Linux Logs / T1562.001 - Impair Defenses
# ============================================================================

-w /var/log/audit/ -p wra -k audit-log-tamper
-w /etc/audit/ -p wa -k audit-config-tamper
-w /etc/libaudit.conf -p wa -k audit-config-tamper
-w /etc/audisp/ -p wa -k audit-config-tamper

-w /sbin/auditctl -p x -k audit-tools
-w /sbin/auditd -p x -k audit-tools
-w /usr/sbin/auditctl -p x -k audit-tools
-w /usr/sbin/auditd -p x -k audit-tools
-w /usr/sbin/augenrules -p x -k audit-tools
-w /usr/sbin/ausearch -p x -k audit-tools
-w /usr/sbin/aureport -p x -k audit-tools

# Log files
-w /var/log/syslog -p wa -k log-tamper
-w /var/log/messages -p wa -k log-tamper
-w /var/log/auth.log -p wa -k log-tamper
-w /var/log/secure -p wa -k log-tamper
-w /var/log/kern.log -p wa -k log-tamper
-w /var/log/wtmp -p wa -k log-tamper
-w /var/log/btmp -p wa -k log-tamper
-w /var/run/utmp -p wa -k log-tamper
-w /var/log/lastlog -p wa -k log-tamper
-w /var/log/faillog -p wa -k log-tamper
-w /var/log/tallylog -p wa -k log-tamper

# Syslog config
-w /etc/rsyslog.conf -p wa -k syslog-config
-w /etc/rsyslog.d/ -p wa -k syslog-config
-w /etc/syslog-ng/ -p wa -k syslog-config
-w /etc/syslog.conf -p wa -k syslog-config

# ============================================================================
# AUTHENTICATION & CREDENTIAL ACCESS
# T1078 - Valid Accounts / T1110 - Brute Force / T1003 - Credential Dumping
# ============================================================================

-w /etc/passwd -p wa -k identity-modify
-w /etc/shadow -p wa -k identity-modify
-w /etc/group -p wa -k identity-modify
-w /etc/gshadow -p wa -k identity-modify
-w /etc/security/opasswd -p wa -k identity-modify

-w /var/log/faillock/ -p wa -k login-tracking
-w /var/run/faillock/ -p wa -k login-tracking

-w /etc/pam.d/ -p wa -k pam-config
-w /etc/security/ -p wa -k pam-config
-w /etc/nsswitch.conf -p wa -k nss-config
-w /etc/nss_ldap.conf -p wa -k nss-config
-w /etc/ldap.conf -p wa -k nss-config

# User/group management commands
-w /usr/sbin/useradd -p x -k user-modify
-w /usr/sbin/userdel -p x -k user-modify
-w /usr/sbin/usermod -p x -k user-modify
-w /usr/sbin/groupadd -p x -k group-modify
-w /usr/sbin/groupdel -p x -k group-modify
-w /usr/sbin/groupmod -p x -k group-modify
-w /usr/sbin/adduser -p x -k user-modify
-w /usr/sbin/addgroup -p x -k group-modify
-w /usr/bin/passwd -p x -k passwd-change
-w /usr/bin/chpasswd -p x -k passwd-change
-w /usr/bin/chage -p x -k passwd-change
-w /usr/bin/gpasswd -p x -k passwd-change
-w /usr/sbin/newusers -p x -k user-modify

# SSH configuration and keys (root + all users)
-w /etc/ssh/ -p wa -k ssh-config
-w /root/.ssh/ -p wa -k ssh-keys
# Per-user .ssh/ watches are appended dynamically below (see DYNAMIC RULES)

# Sudoers
-w /etc/sudoers -p wa -k sudo-config
-w /etc/sudoers.d/ -p wa -k sudo-config

# Privilege escalation commands
-w /usr/bin/sudo -p x -k priv-escalation
-w /usr/bin/su -p x -k priv-escalation
-w /usr/bin/pkexec -p x -k priv-escalation

# ============================================================================
# PRIVILEGE ESCALATION
# T1548 - Abuse Elevation Control / T1068 - Exploitation for Privesc
# ============================================================================

# Permission changes (SUID bit setting, etc.)
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=-1 -k perm-change
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=-1 -k perm-change

# Ownership changes
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=-1 -k owner-change
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=-1 -k owner-change

# Extended attributes
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=-1 -k xattr-change
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=-1 -k xattr-change

# ptrace - process injection / debugging (T1055)
# Watch dangerous operations:
#   0x4  = PTRACE_POKETEXT (write to process code)
#   0x5  = PTRACE_POKEDATA (write to process data)
#   0x6  = PTRACE_POKEUSR  (write to process user area)
#   0x10 = PTRACE_ATTACH   (attach to process - precedes injection/credential dump)
# No catch-all — general ptrace (e.g. strace, gdb) is too noisy and the specific
# operations above cover the injection/hijack cases that matter.
-a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k process-inject
-a always,exit -F arch=b32 -S ptrace -F a0=0x4 -k process-inject
-a always,exit -F arch=b64 -S ptrace -F a0=0x5 -k process-inject
-a always,exit -F arch=b32 -S ptrace -F a0=0x5 -k process-inject
-a always,exit -F arch=b64 -S ptrace -F a0=0x6 -k process-inject
-a always,exit -F arch=b32 -S ptrace -F a0=0x6 -k process-inject
-a always,exit -F arch=b64 -S ptrace -F a0=0x10 -k process-inject
-a always,exit -F arch=b32 -S ptrace -F a0=0x10 -k process-inject

# ============================================================================
# PERSISTENCE MECHANISMS
# T1053 - Scheduled Tasks / T1037 - Boot Scripts / T1543 - System Process
# ============================================================================

# Cron
-w /etc/crontab -p wa -k cron-persist
-w /etc/cron.d/ -p wa -k cron-persist
-w /etc/cron.daily/ -p wa -k cron-persist
-w /etc/cron.hourly/ -p wa -k cron-persist
-w /etc/cron.weekly/ -p wa -k cron-persist
-w /etc/cron.monthly/ -p wa -k cron-persist
-w /var/spool/cron/ -p wa -k cron-persist
-w /var/spool/cron/crontabs/ -p wa -k cron-persist
-w /usr/bin/crontab -p x -k cron-persist

# at
-w /var/spool/at/ -p wa -k at-persist
-w /etc/at.allow -p wa -k at-persist
-w /etc/at.deny -p wa -k at-persist
-w /usr/bin/at -p x -k at-persist

# Systemd
-w /etc/systemd/system/ -p wa -k systemd-persist
-w /usr/lib/systemd/system/ -p wa -k systemd-persist
-w /lib/systemd/system/ -p wa -k systemd-persist
-w /etc/systemd/user/ -p wa -k systemd-persist
-w /usr/lib/systemd/user/ -p wa -k systemd-persist
-w /run/systemd/system/ -p wa -k systemd-persist
-w /etc/systemd/system-generators/ -p wa -k systemd-persist
-w /usr/lib/systemd/system-generators/ -p wa -k systemd-persist

# Init / rc
-w /etc/init.d/ -p wa -k init-persist
-w /etc/init/ -p wa -k init-persist
-w /etc/rc.local -p wa -k init-persist
-w /etc/rc.d/ -p wa -k init-persist

# Shell profiles (login persistence)
-w /etc/profile -p wa -k shell-persist
-w /etc/profile.d/ -p wa -k shell-persist
-w /etc/bashrc -p wa -k shell-persist
-w /etc/bash.bashrc -p wa -k shell-persist
-w /etc/environment -p wa -k shell-persist
-w /etc/shells -p wa -k shell-persist

# LD_PRELOAD / library hijacking (T1574.006)
-w /etc/ld.so.conf -p wa -k lib-hijack
-w /etc/ld.so.conf.d/ -p wa -k lib-hijack
-w /etc/ld.so.preload -p wa -k lib-hijack

# MOTD (can execute code on login)
-w /etc/update-motd.d/ -p wa -k motd-persist

# ============================================================================
# KERNEL MODULES
# T1547.006 - Kernel Modules and Extensions
# ============================================================================

-w /usr/sbin/insmod -p x -k kernel-module
-w /usr/sbin/rmmod -p x -k kernel-module
-w /usr/sbin/modprobe -p x -k kernel-module
-w /sbin/insmod -p x -k kernel-module
-w /sbin/rmmod -p x -k kernel-module
-w /sbin/modprobe -p x -k kernel-module
-a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module -k kernel-module
-a always,exit -F arch=b32 -S init_module -S finit_module -S delete_module -k kernel-module

-w /etc/modprobe.conf -p wa -k modprobe-config
-w /etc/modprobe.d/ -p wa -k modprobe-config

# kexec (T1014 - Rootkit)
-a always,exit -F arch=b64 -S kexec_load -S kexec_file_load -k kexec
-a always,exit -F arch=b32 -S sys_kexec_load -k kexec

# ============================================================================
# NETWORK CONFIGURATION
# T1016 / T1049
# ============================================================================

-w /etc/hosts -p wa -k network-config
-w /etc/hosts.allow -p wa -k network-config
-w /etc/hosts.deny -p wa -k network-config
-w /etc/hostname -p wa -k network-config
-w /etc/resolv.conf -p wa -k network-config
-w /etc/network/ -p wa -k network-config
-w /etc/networks -p wa -k network-config
-w /etc/netplan/ -p wa -k network-config
-w /etc/NetworkManager/ -p wa -k network-config
-w /etc/sysconfig/network -p wa -k network-config
-w /etc/sysconfig/network-scripts/ -p wa -k network-config

# Firewall config files
-w /etc/iptables/ -p wa -k firewall-config
-w /etc/nftables.conf -p wa -k firewall-config
-w /etc/ufw/ -p wa -k firewall-config
-w /etc/firewalld/ -p wa -k firewall-config

# Firewall tools
-w /usr/sbin/iptables -p x -k firewall-tools
-w /usr/sbin/ip6tables -p x -k firewall-tools
-w /usr/sbin/nft -p x -k firewall-tools
-w /usr/sbin/ufw -p x -k firewall-tools
-w /usr/bin/firewall-cmd -p x -k firewall-tools
-w /sbin/iptables -p x -k firewall-tools
-w /sbin/ip6tables -p x -k firewall-tools

# ============================================================================
# TIME CHANGES
# T1070.006 - Timestomp
# ============================================================================

-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
-w /etc/timezone -p wa -k time-change
-w /etc/ntp.conf -p wa -k time-change
-w /etc/chrony.conf -p wa -k time-change
-w /etc/chrony/ -p wa -k time-change

# ============================================================================
# SUSPICIOUS TOOL EXECUTION
# T1018 Remote Discovery / T1046 Scanning / T1040 Sniffing / T1105 Transfer
# ============================================================================

# Recon
-w /usr/bin/nmap -p x -k recon-tools
-w /usr/bin/nc -p x -k recon-tools
-w /usr/bin/ncat -p x -k recon-tools
-w /usr/bin/netcat -p x -k recon-tools
-w /usr/bin/socat -p x -k recon-tools
-w /usr/bin/tcpdump -p x -k recon-tools
-w /usr/sbin/tcpdump -p x -k recon-tools
-w /usr/bin/tshark -p x -k recon-tools
-w /usr/bin/wireshark -p x -k recon-tools
-w /usr/bin/rawshark -p x -k recon-tools
-w /usr/bin/masscan -p x -k recon-tools
-w /usr/bin/nc.openbsd -p x -k recon-tools
-w /usr/bin/nc.traditional -p x -k recon-tools
-w /usr/bin/nping -p x -k recon-tools
-w /usr/bin/hping3 -p x -k recon-tools

# File transfer / exfiltration
# NOTE: curl/wget will fire on legitimate package management. This is expected
# and acceptable - the events provide useful forensic context.
-w /usr/bin/wget -p x -k exfil-tools
-w /usr/bin/curl -p x -k exfil-tools
-w /usr/bin/scp -p x -k exfil-tools
-w /usr/bin/sftp -p x -k exfil-tools
-w /usr/bin/ftp -p x -k exfil-tools
-w /usr/bin/rsync -p x -k exfil-tools
-w /usr/bin/base64 -p x -k exfil-tools

# Remote access
-w /usr/bin/ssh -p x -k remote-access
-w /usr/bin/telnet -p x -k remote-access
-w /usr/bin/rdesktop -p x -k remote-access
-w /usr/bin/xfreerdp -p x -k remote-access

# Compilers (attacker building exploits on-box)
-w /usr/bin/gcc -p x -k compile-tools
-w /usr/bin/cc -p x -k compile-tools
-w /usr/bin/make -p x -k compile-tools
-w /usr/bin/as -p x -k compile-tools

# Scripting interpreters
# NOTE: On boxes where Python is part of a scored service, these will be noisy.
# Disable selectively per-box if needed, but keep by default - red team
# frequently uses python/perl for reverse shells and exploit scripts.
-w /usr/bin/python -p x -k script-exec
-w /usr/bin/python2 -p x -k script-exec
-w /usr/bin/python3 -p x -k script-exec
-w /usr/bin/perl -p x -k script-exec
-w /usr/bin/ruby -p x -k script-exec

# Docker / containers
-w /usr/bin/docker -p x -k container-tools
-w /usr/bin/dockerd -p x -k container-tools
-w /usr/bin/podman -p x -k container-tools

# ============================================================================
# SYSTEM CONFIGURATION
# T1082 - System Information Discovery
# ============================================================================

-w /etc/sysctl.conf -p wa -k sysctl-config
-w /etc/sysctl.d/ -p wa -k sysctl-config

-a always,exit -F arch=b64 -S sethostname -S setdomainname -k hostname-change
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k hostname-change

-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -k mount-ops
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -k mount-ops

# ============================================================================
# SOFTWARE INSTALLATION
# T1072 - Software Deployment Tools
# ============================================================================

-w /usr/bin/dpkg -p x -k software-install
-w /usr/bin/apt -p x -k software-install
-w /usr/bin/apt-get -p x -k software-install
-w /usr/bin/aptitude -p x -k software-install
-w /usr/bin/yum -p x -k software-install
-w /usr/bin/dnf -p x -k software-install
-w /usr/bin/rpm -p x -k software-install
-w /bin/rpm -p x -k software-install
-w /usr/bin/zypper -p x -k software-install
-w /usr/bin/snap -p x -k software-install
-w /usr/bin/flatpak -p x -k software-install
-w /usr/bin/pip -p x -k software-install
-w /usr/bin/pip3 -p x -k software-install
-w /usr/local/bin/pip -p x -k software-install
-w /usr/local/bin/pip3 -p x -k software-install

# ============================================================================
# COMMAND EXECUTION AUDITING
# Logs every command run by human-login users (auid >= 1000).
# Skips system daemons automatically. This is the single highest-value rule
# for catching red team activity.
# ============================================================================

-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=-1 -k exec-cmd
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=-1 -k exec-cmd

# ============================================================================
# 32-BIT API EXPLOITATION (on 64-bit systems)
# Attackers may use 32-bit execve to bypass 64-bit-only monitoring.
# Only monitors execve, not all syscalls (which would flood logs).
# ============================================================================

-a always,exit -F arch=b32 -S execve -F auid<1000 -F auid!=-1 -k 32bit-api

# ============================================================================
# SPECIAL FILESYSTEM OPERATIONS
# ============================================================================

# Device nodes (rootkit indicator - T1014)
-a always,exit -F arch=b64 -S mknod -S mknodat -k special-files
-a always,exit -F arch=b32 -S mknod -S mknodat -k special-files

# File deletion (covering tracks - T1070.004)
# NOTE: These are noisy (every mv, rm, editor swap triggers them). With execve
# auditing enabled, most deletions are already visible via the command that ran.
# Disable these on high-noise boxes if log volume becomes a problem.
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=-1 -k file-delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=-1 -k file-delete

# Failed file access (permission denied)
-a always,exit -F arch=b64 -S open -S openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k access-denied
-a always,exit -F arch=b32 -S open -S openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k access-denied
-a always,exit -F arch=b64 -S open -S openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k access-denied
-a always,exit -F arch=b32 -S open -S openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k access-denied

# ============================================================================
# Outbound network connections (reverse shells, C2 callbacks)
# NOTE: Commented out by default - very noisy on boxes running web services,
# DNS, mail, etc. Enable on quiet boxes or when actively hunting for C2.
# ============================================================================
# -a always,exit -F arch=b64 -S connect -F auid>=1000 -F auid!=-1 -k network-connect
# -a always,exit -F arch=b32 -S connect -F auid>=1000 -F auid!=-1 -k network-connect

AUDIT_RULES_EOF

# --- Dynamic rules: per-user .ssh/ watches ---
for _home in /home/*/; do
    if [ -d "$_home" ]; then
        printf -- '-w %s.ssh/ -p wa -k ssh-keys\n' "$_home" >> "$RULES_FILE"
    fi
done

# Append immutable flag as the very last rule (must be last)
cat >> "$RULES_FILE" << 'IMMUTABLE_EOF'

# ============================================================================
# MAKE RULES IMMUTABLE (uncomment when config is finalized)
# Prevents rule changes without reboot. Stops red team from disabling logging.
# ============================================================================
# -e 2
IMMUTABLE_EOF

log_info "Audit rules written to $RULES_FILE"

# ============================================================================
# STEP 4: Configure rsyslog
# ============================================================================
log_section "Configuring rsyslog"

RSYSLOG_CONF="/etc/rsyslog.conf"
RSYSLOG_ENHANCED="/etc/rsyslog.d/50-enhanced.conf"

if [ -f "$RSYSLOG_CONF" ] && [ -d /etc/rsyslog.d ]; then
    cp -p "$RSYSLOG_CONF" "$BACKUP_DIR/"
    [ -f "$RSYSLOG_ENHANCED" ] && cp -p "$RSYSLOG_ENHANCED" "$BACKUP_DIR/"
    cat > "$RSYSLOG_ENHANCED" << 'RSYSLOG_EOF'
# Enhanced Logging Configuration
auth,authpriv.*                 /var/log/auth.log
kern.*                          /var/log/kern.log
*.emerg                         :omusrmsg:*
cron.*                          /var/log/cron.log

# REMOTE FORWARDING: If you have a log server, uncomment and set the IP.
# This makes your audit trail survivable if red team gets root.
# *.* @@<logserver-ip>:514
RSYSLOG_EOF
    log_info "rsyslog drop-in written to $RSYSLOG_ENHANCED"
elif command -v syslog-ng >/dev/null 2>&1; then
    log_warn "syslog-ng detected. Configure manually if needed."
else
    log_warn "No rsyslog config directory found. Skipping."
fi

# ============================================================================
# STEP 5: Configure journald (systemd only)
# ============================================================================
if [ "$INIT" = "systemd" ] && [ -d /etc/systemd ]; then
    log_section "Configuring journald"
    JOURNALD_CONF="/etc/systemd/journald.conf"
    [ -f "$JOURNALD_CONF" ] && cp -p "$JOURNALD_CONF" "$BACKUP_DIR/"
    mkdir -p /var/log/journal
    cat > "$JOURNALD_CONF" << 'JOURNALD_EOF'
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=500M
SystemKeepFree=100M
# No rate limiting - we want everything during competition
RateLimitIntervalSec=0
RateLimitBurst=0
ForwardToSyslog=yes
JOURNALD_EOF
    log_info "journald configured for persistent storage, no rate limiting."
fi

# ============================================================================
# STEP 6: Enable process accounting
# ============================================================================
log_section "Enabling Process Accounting"

if command -v accton >/dev/null 2>&1; then
    if [ -f /var/account/pacct ]; then
        ACCT_FILE="/var/account/pacct"
    elif [ -f /var/log/account/pacct ]; then
        ACCT_FILE="/var/log/account/pacct"
    else
        mkdir -p /var/account
        touch /var/account/pacct
        ACCT_FILE="/var/account/pacct"
    fi
    accton "$ACCT_FILE" 2>/dev/null || true
    case "$PKG_MGR" in
        apt) svc_enable_start acct ;;
        *)   svc_enable_start psacct ;;
    esac
    log_info "Process accounting enabled. Use 'lastcomm' and 'sa' to query."
else
    log_warn "Process accounting tools not found. Skipping."
fi

# ============================================================================
# STEP 7: Install syshealth monitoring helper
# ============================================================================
log_section "Installing Monitoring Helper"

cat > /usr/sbin/syshealth << 'LOGWATCH_EOF'
#!/bin/sh
case "${1:-help}" in
    auth)
        echo "=== Authentication Events ==="
        ausearch -k identity-modify -k passwd-change -k user-modify -k login-tracking -ts recent 2>/dev/null || \
            tail -50 /var/log/auth.log 2>/dev/null || \
            journalctl -u sshd --since "1 hour ago" 2>/dev/null
        ;;
    persist)
        echo "=== Persistence Changes ==="
        ausearch -k cron-persist -k systemd-persist -k init-persist -k shell-persist -k at-persist -ts recent 2>/dev/null
        ;;
    priv)
        echo "=== Privilege Escalation ==="
        ausearch -k priv-escalation -k perm-change -k owner-change -k sudo-config -ts recent 2>/dev/null
        ;;
    network)
        echo "=== Network Changes ==="
        ausearch -k network-config -k firewall-config -k firewall-tools -ts recent 2>/dev/null
        ;;
    tamper)
        echo "=== Log Tampering ==="
        ausearch -k audit-log-tamper -k audit-config-tamper -k log-tamper -k syslog-config -ts recent 2>/dev/null
        ;;
    tools)
        echo "=== Suspicious Tools ==="
        ausearch -k recon-tools -k exfil-tools -k compile-tools -k remote-access -ts recent 2>/dev/null
        ;;
    exec)
        _since="${2:-recent}"
        echo "=== Command Execution (human users, since $_since) ==="
        aureport -x --summary -ts "$_since" 2>/dev/null || \
            ausearch -k exec-cmd -ts "$_since" 2>/dev/null | tail -500
        ;;
    kernel)
        echo "=== Kernel Modules ==="
        ausearch -k kernel-module -k kexec -k modprobe-config -ts recent 2>/dev/null
        ;;
    software)
        echo "=== Software Installation ==="
        ausearch -k software-install -ts recent 2>/dev/null
        ;;
    denied)
        echo "=== Access Denied ==="
        ausearch -k access-denied -ts recent 2>/dev/null
        ;;
    logins)
        echo "=== Current ===" && w
        echo "" && echo "=== Recent ===" && last -20
        echo "" && echo "=== Failed ==="
        lastb -20 2>/dev/null || ausearch -m USER_LOGIN --success no -ts recent 2>/dev/null
        ;;
    watch)
        tail -f /var/log/audit/audit.log
        ;;
    summary)
        aureport --summary 2>/dev/null
        echo "" && echo "=== Failed ===" && aureport --failed 2>/dev/null | tail -20
        echo "" && echo "=== Auth ===" && aureport --auth 2>/dev/null | tail -20
        ;;
    status)
        auditctl -s 2>/dev/null
        echo "" && echo "Rules: $(auditctl -l 2>/dev/null | wc -l)"
        echo "Log:   $(ls -lh /var/log/audit/audit.log 2>/dev/null | awk '{print $5}')"
        echo "Disk:  $(df -h /var/log | tail -1 | awk '{print $4 " free"}')"
        ;;
    *)
        cat << 'HELPEOF'
Usage: syshealth <command>

  auth      Authentication & credential events
  persist   Persistence changes (cron, systemd, rc, profiles)
  priv      Privilege escalation (sudo, chmod, chown)
  network   Network/firewall changes
  tamper    Log/audit tampering attempts
  tools     Suspicious tool execution (nmap, nc, wget...)
  exec      Commands run by human users (execve)
  kernel    Kernel module activity
  software  Package installation
  denied    Access denied events
  logins    Current / recent / failed logins
  watch     Live tail audit.log
  summary   aureport summary
  status    Audit system health

Quick reference:
  ausearch -k <key> -ts recent        Last 15 min by key
  ausearch -k <key> -ts today         Today by key
  ausearch -m USER_LOGIN --success no  Failed logins
  ausearch -c <command>                By command name
  ausearch -ui <uid>                   By user ID
HELPEOF
        ;;
esac
LOGWATCH_EOF

chmod +x /usr/sbin/syshealth
log_info "Monitoring helper installed: /usr/sbin/syshealth"

# ============================================================================
# STEP 8: Start / Restart services
# ============================================================================
log_section "Starting Services"

if command -v rsyslogd >/dev/null 2>&1; then
    svc_enable_start rsyslog
    log_info "rsyslog restarted."
fi

if [ "$INIT" = "systemd" ]; then
    systemctl restart systemd-journald 2>/dev/null || true
    log_info "journald restarted."
fi

# Load audit rules
if command -v augenrules >/dev/null 2>&1; then
    _err=$(augenrules --load 2>&1)
    if [ $? -eq 0 ]; then
        log_info "Audit rules loaded via augenrules."
    else
        log_warn "augenrules failed: $_err"
    fi
fi

# Restart auditd (special handling - often rejects systemctl restart)
if [ "$INIT" = "systemd" ]; then
    if service auditd restart 2>/dev/null || \
       systemctl restart auditd 2>/dev/null || \
       auditctl -R "$RULES_FILE" 2>/dev/null; then
        log_info "auditd restarted."
    else
        log_warn "Could not restart auditd. Try: service auditd restart"
    fi
else
    svc_enable_start auditd
    log_info "auditd restarted."
fi

# ============================================================================
# STEP 9: Verify
# ============================================================================
log_section "Verification"

RULE_COUNT=$(auditctl -l 2>/dev/null | wc -l)
log_info "Active audit rules: $RULE_COUNT"

if [ "$RULE_COUNT" -lt 10 ]; then
    log_warn "Rule count seems low. Check for errors:"
    log_warn "  auditctl -l          # list loaded rules"
    log_warn "  journalctl -u auditd # check for errors"
fi

AUDIT_STATUS=$(auditctl -s 2>/dev/null | grep "enabled" || echo "unknown")
log_info "Audit status: $AUDIT_STATUS"

# ============================================================================
# SUMMARY
# ============================================================================
log_section "Setup Complete"

cat << SUMMARY_EOF

  Key files:
    Audit rules:   $RULES_FILE
    Audit config:  /etc/audit/auditd.conf
    Audit log:     /var/log/audit/audit.log
    Backups:       $BACKUP_DIR

  Quick commands:
    syshealth logins     Who's logged in / failed logins
    syshealth tamper     Log tampering attempts
    syshealth persist    Persistence changes
    syshealth exec       Commands run by human users
    syshealth tools      Suspicious tool execution
    syshealth watch      Live tail of audit log
    syshealth summary    aureport summary
    syshealth status     Audit health check

  Audit rule keys (ausearch -k <key>):
    audit-log-tamper  audit-config-tamper  audit-tools   log-tamper
    identity-modify   login-tracking       pam-config    ssh-config
    ssh-keys          sudo-config          priv-escalation
    perm-change       owner-change         process-inject
    cron-persist      systemd-persist      init-persist  shell-persist
    lib-hijack        kernel-module        kexec
    network-config    firewall-config      firewall-tools
    time-change       hostname-change      mount-ops
    recon-tools       exfil-tools          remote-access
    compile-tools     script-exec          container-tools
    software-install  exec-cmd             32bit-api
    file-delete       access-denied        special-files

  To lock rules (prevents changes without reboot):
    Uncomment '-e 2' at the end of $RULES_FILE
    Then: augenrules --load  OR  service auditd restart

SUMMARY_EOF

log_info "Done at $(date)"
