#!/usr/bin/env bash

if [[ $EUID -ne 0 ]]; then
   echo "[!] This script must be run as root (sudo)" 
   exit 1
fi

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            debian|ubuntu|kali|mint) echo "debian" ;;
            rhel|centos|rocky|alma|fedora|ol) echo "rhel" ;;
            *) echo "unknown" ;;
        esac
    elif [ -f /etc/debian_version ]; then
        echo "debian"
    elif [ -f /etc/redhat-release ]; then
        echo "rhel"
    else
        echo "unknown"
    fi
}

get_web_user() {
    if id "www-data" &>/dev/null; then echo "www-data"
    elif id "apache" &>/dev/null; then echo "apache"
    elif id "nginx" &>/dev/null; then echo "nginx"
    else echo "root"
    fi
}

find_bin() {
    local name="$1"
    for dir in /usr/bin /usr/sbin /bin /sbin; do
        [ -f "$dir/$name" ] && echo "$dir/$name" && return
    done
}

DISTRO_FAMILY=$(detect_distro)
WEB_USER=$(get_web_user)
HOSTNAME=$(hostname || echo "unknown_host")
TIMESTAMP=$(date +%Y%m%d_%H%M)
BACKUP_ROOT="/root/Injects_${HOSTNAME}_${TIMESTAMP}"

mkdir -p -m 700 "$BACKUP_ROOT"
echo "--- Starting Aggressive Backup for $HOSTNAME ---"
echo "    Detected distro family: $DISTRO_FAMILY"

echo "$DISTRO_FAMILY" > "$BACKUP_ROOT/.distro_family"
echo "$WEB_USER" > "$BACKUP_ROOT/.web_user"

mkdir -p "$BACKUP_ROOT/system"
cp /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers "$BACKUP_ROOT/system/" 2>/dev/null
cp /etc/sysctl.conf /etc/fstab /etc/resolv.conf "$BACKUP_ROOT/system/" 2>/dev/null
tar -czf "$BACKUP_ROOT/system/pam_configs.tar.gz" /etc/pam.d 2>/dev/null

mkdir -p "$BACKUP_ROOT/shell"
echo "[*] Backing up shell configs..."
[ -f "/etc/bash.bashrc" ] && cp /etc/bash.bashrc "$BACKUP_ROOT/shell/"
[ -f "/etc/bashrc" ] && cp /etc/bashrc "$BACKUP_ROOT/shell/"
[ -f "/etc/profile" ] && cp /etc/profile "$BACKUP_ROOT/shell/"
[ -d "/etc/profile.d" ] && tar -czf "$BACKUP_ROOT/shell/profile_d.tar.gz" /etc/profile.d 2>/dev/null
[ -f "/root/.bashrc" ] && cp /root/.bashrc "$BACKUP_ROOT/shell/root_bashrc"
[ -f "/root/.bash_profile" ] && cp /root/.bash_profile "$BACKUP_ROOT/shell/root_bash_profile"
[ -f "/root/.profile" ] && cp /root/.profile "$BACKUP_ROOT/shell/root_profile"
[ -f "/root/.bash_aliases" ] && cp /root/.bash_aliases "$BACKUP_ROOT/shell/root_bash_aliases"
find /home -maxdepth 2 -type f \( -name ".bashrc" -o -name ".bash_profile" -o -name ".profile" \) 2>/dev/null | while read rc; do
    user=$(echo "$rc" | cut -d'/' -f3)
    filename=$(basename "$rc")
    cp "$rc" "$BACKUP_ROOT/shell/${user}_${filename}" 2>/dev/null
done
echo "  ✓ Shell configs backed up"

mkdir -p "$BACKUP_ROOT/auth"
echo "[*] Capturing SSSD, KRB5, and NSS..."
[ -d "/etc/sssd" ] && tar -czf "$BACKUP_ROOT/auth/sssd_etc.tar.gz" /etc/sssd 2>/dev/null
[ -d "/var/lib/sss" ] && tar -czf "$BACKUP_ROOT/auth/sssd_cache.tar.gz" /var/lib/sss 2>/dev/null
[ -f "/etc/nsswitch.conf" ] && cp /etc/nsswitch.conf "$BACKUP_ROOT/auth/"
[ -f "/etc/ldap/ldap.conf" ] && cp /etc/ldap/ldap.conf "$BACKUP_ROOT/auth/ldap_debian.conf"
[ -f "/etc/openldap/ldap.conf" ] && cp /etc/openldap/ldap.conf "$BACKUP_ROOT/auth/ldap_rhel.conf"
[ -f "/etc/samba/smb.conf" ] && cp /etc/samba/smb.conf "$BACKUP_ROOT/auth/"
[ -d "/var/lib/samba/private" ] && tar -czf "$BACKUP_ROOT/auth/samba_secrets.tar.gz" /var/lib/samba/private 2>/dev/null
[ -d "/var/lib/realmd" ] && tar -czf "$BACKUP_ROOT/auth/realmd.tar.gz" /var/lib/realmd 2>/dev/null
[ -f "/etc/krb5.conf" ] && cp /etc/krb5.conf "$BACKUP_ROOT/auth/"
[ -d "/etc/krb5.conf.d" ] && tar -czf "$BACKUP_ROOT/auth/krb5_conf_d.tar.gz" /etc/krb5.conf.d 2>/dev/null
[ -f "/etc/krb5.keytab" ] && cp /etc/krb5.keytab "$BACKUP_ROOT/auth/machine.keytab"

mkdir -p "$BACKUP_ROOT/ssh"
cp -r /etc/ssh/* "$BACKUP_ROOT/ssh/" 2>/dev/null
find /home /root -name ".ssh" -type d 2>/dev/null | while read -r dir; do
    user_name=$(basename "$(dirname "$dir")")
    tar -czf "$BACKUP_ROOT/ssh/keys_${user_name}.tar.gz" "$dir" 2>/dev/null
done

mkdir -p "$BACKUP_ROOT/network"
command -v iptables-save >/dev/null && iptables-save > "$BACKUP_ROOT/network/iptables.rules" 2>/dev/null
command -v ufw >/dev/null && ufw status numbered > "$BACKUP_ROOT/network/ufw.rules" 2>/dev/null
command -v nft >/dev/null && nft list ruleset > "$BACKUP_ROOT/network/nft.rules" 2>/dev/null
if command -v firewall-cmd >/dev/null; then
    firewall-cmd --list-all --zone=public > "$BACKUP_ROOT/network/firewalld_public.txt" 2>/dev/null
    firewall-cmd --list-all-zones > "$BACKUP_ROOT/network/firewalld_all_zones.txt" 2>/dev/null
    [ -d "/etc/firewalld" ] && tar -czf "$BACKUP_ROOT/network/firewalld_etc.tar.gz" /etc/firewalld 2>/dev/null
fi

echo "[*] Backing up network routes and interfaces..."
ip route show > "$BACKUP_ROOT/network/routes.txt" 2>/dev/null
ip addr show > "$BACKUP_ROOT/network/addresses.txt" 2>/dev/null
[ -f "/etc/network/interfaces" ] && cp /etc/network/interfaces "$BACKUP_ROOT/network/" 2>/dev/null
[ -d "/etc/network/interfaces.d" ] && tar -czf "$BACKUP_ROOT/network/interfaces_d.tar.gz" /etc/network/interfaces.d 2>/dev/null
[ -d "/etc/NetworkManager" ] && tar -czf "$BACKUP_ROOT/network/NetworkManager.tar.gz" /etc/NetworkManager 2>/dev/null
[ -d "/etc/netplan" ] && tar -czf "$BACKUP_ROOT/network/netplan.tar.gz" /etc/netplan 2>/dev/null
[ -d "/etc/sysconfig/network-scripts" ] && tar -czf "$BACKUP_ROOT/network/network-scripts.tar.gz" /etc/sysconfig/network-scripts 2>/dev/null
[ -f "/etc/sysconfig/network" ] && cp /etc/sysconfig/network "$BACKUP_ROOT/network/sysconfig_network" 2>/dev/null
echo "  ✓ Network routes and interfaces backed up"

mkdir -p "$BACKUP_ROOT/services"
TARGETS=("dovecot" "postfix" "exim" "exim4" "nginx" "apache" "apache2" "httpd" "mysql" "mariadb" "postgresql" "bind" "bind9" "named" "vsftpd" "proftpd" "samba" "smb" "snmpd" "nfs-server" "nfs-kernel-server" "openvpn" "telnetd" "caddy" "gitea" "courier" "unbound" "dnsmasq")

echo "[*] Backing up standard services..."
for svc in "${TARGETS[@]}"; do
    CONF_PATHS=$(ls -d /etc/${svc}* 2>/dev/null)
    if [ -n "$CONF_PATHS" ]; then
        tar -czf "$BACKUP_ROOT/services/${svc}_etc.tar.gz" $CONF_PATHS 2>/dev/null
    fi
done

echo -e "\n[*] Detecting services not in backup list..."
RUNNING_SERVICES=$(systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print $1}' | sed 's/.service$//')
UNLISTED=()
SYSTEM_EXCLUDE="^(systemd|dbus|user@|getty|cron|crond|rsyslog|syslog|udev|network|multi-user|graphical|accounts-daemon|avahi|colord|cups|lightdm|gdm|ModemManager|NetworkManager|polkit|qemu|rtkit|udisks|upower|wpa_supplicant|firewalld|tuned|chronyd|auditd|irqbalance|lvm2|dmraid|mdmonitor|multipathd|iscsid|bluetooth|switcheroo|power-profiles|thermald|fwupd|packagekit|snap|snapd|plymouth|cloud-init|cloud-final|cloud-config|amazon-ssm|waagent|rhsmcertd|insights-client|cockpit).*$"

for running in $RUNNING_SERVICES; do
    [[ "$running" =~ $SYSTEM_EXCLUDE ]] && continue
    FOUND=0
    for target in "${TARGETS[@]}"; do
        if [[ "$running" == *"$target"* ]]; then
            FOUND=1
            break
        fi
    done
    [ $FOUND -eq 0 ] && UNLISTED+=("$running")
done

if [ ${#UNLISTED[@]} -gt 0 ]; then
    echo -e "\n[\e[33m NOTICE \e[0m] Found services not in backup list:"
    for svc in "${UNLISTED[@]}"; do
        echo "  - $svc"
    done
    read -p "
Backup these services? [y/N]: " response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        for svc in "${UNLISTED[@]}"; do
            CONF_PATHS=$(ls -d /etc/${svc}* 2>/dev/null)
            if [ -n "$CONF_PATHS" ]; then
                echo "[*] Backing up $svc..."
                tar -czf "$BACKUP_ROOT/services/${svc}_etc.tar.gz" $CONF_PATHS 2>/dev/null
            fi
        done
        echo "✓ Additional services backed up"
    else
        echo "Skipping additional services"
    fi
fi

mkdir -p "$BACKUP_ROOT/binaries"
echo "[*] Backing up critical binaries..."
CRITICAL_BIN_NAMES=("sudo" "su" "sshd" "ssh" "login" "passwd" "useradd" "usermod" "apt" "apt-get" "dpkg" "dnf" "yum" "rpm" "ps" "netstat" "ss" "ls" "find" "grep")
for name in "${CRITICAL_BIN_NAMES[@]}"; do
    bin_path=$(find_bin "$name")
    [ -n "$bin_path" ] && cp "$bin_path" "$BACKUP_ROOT/binaries/$name" 2>/dev/null
done
find "$BACKUP_ROOT/binaries" -type f -exec sha256sum {} \; > "$BACKUP_ROOT/binaries/HASHES.txt"

mkdir -p "$BACKUP_ROOT/webroot"
echo "[*] Backing up web content..."
[ -d "/var/www" ] && tar -czf "$BACKUP_ROOT/webroot/var_www.tar.gz" /var/www 2>/dev/null && echo "  ✓ /var/www backed up"
[ -d "/usr/share/nginx/html" ] && tar -czf "$BACKUP_ROOT/webroot/nginx_html.tar.gz" /usr/share/nginx/html 2>/dev/null && echo "  ✓ /usr/share/nginx/html backed up"
[ -d "/srv/www" ] && tar -czf "$BACKUP_ROOT/webroot/srv_www.tar.gz" /srv/www 2>/dev/null && echo "  ✓ /srv/www backed up"

mkdir -p "$BACKUP_ROOT/webapps"
echo "[*] Detecting web applications..."

if [ -d "/var/www/html/wp-content" ] || [ -d "/usr/share/nginx/html/wp-content" ]; then
    echo "  - WordPress detected"
    WP_ROOT=$(find /var/www /usr/share/nginx/html /opt -name "wp-config.php" -exec dirname {} \; 2>/dev/null | head -1)
    if [ -n "$WP_ROOT" ]; then
        cp "$WP_ROOT/wp-config.php" "$BACKUP_ROOT/webapps/" 2>/dev/null
        tar -czf "$BACKUP_ROOT/webapps/wordpress_content.tar.gz" "$WP_ROOT/wp-content" 2>/dev/null
        [ -f "$WP_ROOT/.htaccess" ] && cp "$WP_ROOT/.htaccess" "$BACKUP_ROOT/webapps/wordpress_htaccess"
    fi
fi

if systemctl list-unit-files 2>/dev/null | grep -q "gitea.service"; then
    echo "  - Gitea detected"
    GITEA_CONF=$(find /etc -name "app.ini" -path "*/gitea/*" 2>/dev/null | head -1)
    [ -n "$GITEA_CONF" ] && cp "$GITEA_CONF" "$BACKUP_ROOT/webapps/gitea_app.ini" 2>/dev/null
    [ -d "/opt/gitea" ] && tar -czf "$BACKUP_ROOT/webapps/gitea_data.tar.gz" /opt/gitea 2>/dev/null
    [ -d "/var/lib/gitea" ] && tar -czf "$BACKUP_ROOT/webapps/gitea_lib.tar.gz" /var/lib/gitea 2>/dev/null
fi

if [ -d "/var/www/rainloop" ] || [ -d "/usr/share/nginx/rainloop" ]; then
    echo "  - Rainloop detected"
    RAINLOOP_ROOT=$(find /var/www /usr/share/nginx -type d -name "rainloop" 2>/dev/null | head -1)
    [ -n "$RAINLOOP_ROOT" ] && tar -czf "$BACKUP_ROOT/webapps/rainloop_data.tar.gz" "$RAINLOOP_ROOT/data" 2>/dev/null
fi

if [ -d "/var/www/jekyll" ] || [ -d "/srv/jekyll" ]; then
    echo "  - Jekyll detected"
    JEKYLL_ROOT=$(find /var/www /srv -type d -name "jekyll" -o -name "_site" 2>/dev/null | head -1)
    [ -n "$JEKYLL_ROOT" ] && tar -czf "$BACKUP_ROOT/webapps/jekyll_site.tar.gz" "$JEKYLL_ROOT" 2>/dev/null
fi

if systemctl list-unit-files 2>/dev/null | grep -q "filestash.service"; then
    echo "  - Filestash detected"
    [ -d "/etc/filestash" ] && tar -czf "$BACKUP_ROOT/webapps/filestash_config.tar.gz" /etc/filestash 2>/dev/null
fi

mkdir -p "$BACKUP_ROOT/packages"
echo "[*] Backing up package manager data..."
if [ -d "/etc/apt" ]; then
    tar -czf "$BACKUP_ROOT/packages/apt_etc.tar.gz" /etc/apt 2>/dev/null
    cp /etc/apt/sources.list "$BACKUP_ROOT/packages/" 2>/dev/null
    tar -czf "$BACKUP_ROOT/packages/apt_sources.tar.gz" /etc/apt/sources.list.d 2>/dev/null
    tar -czf "$BACKUP_ROOT/packages/apt_keyrings.tar.gz" /etc/apt/trusted.gpg.d /etc/apt/keyrings 2>/dev/null
    dpkg --get-selections > "$BACKUP_ROOT/packages/dpkg_selections.txt" 2>/dev/null
    apt-mark showmanual > "$BACKUP_ROOT/packages/manually_installed.txt" 2>/dev/null
fi
if [ -d "/etc/yum.repos.d" ]; then
    tar -czf "$BACKUP_ROOT/packages/yum_repos.tar.gz" /etc/yum.repos.d 2>/dev/null
    rpm -qa > "$BACKUP_ROOT/packages/rpm_packages.txt" 2>/dev/null
    [ -d "/etc/pki/rpm-gpg" ] && tar -czf "$BACKUP_ROOT/packages/rpm_keyrings.tar.gz" /etc/pki/rpm-gpg 2>/dev/null
    [ -d "/etc/dnf" ] && tar -czf "$BACKUP_ROOT/packages/dnf_etc.tar.gz" /etc/dnf 2>/dev/null
fi
command -v snap >/dev/null && snap list > "$BACKUP_ROOT/packages/snap_list.txt" 2>/dev/null
echo "  ✓ Package manager backed up"

mkdir -p "$BACKUP_ROOT/baseline"
echo "[*] Recording Auth Status & Processes..."
ps auxf > "$BACKUP_ROOT/baseline/processes.txt"
ss -plunt > "$BACKUP_ROOT/baseline/ports.txt" 2>/dev/null
command -v realm >/dev/null && realm list > "$BACKUP_ROOT/baseline/domain_status.txt" 2>/dev/null
command -v adcli >/dev/null && adcli info "$(hostname -d 2>/dev/null)" >> "$BACKUP_ROOT/baseline/domain_status.txt" 2>/dev/null

echo -e "\n--- VERIFICATION REPORT ---"
CHECK_LIST=("ssh" "sssd" "nsswitch" "krb5" "pam" "passwd")
for item in "${CHECK_LIST[@]}"; do
    if find "$BACKUP_ROOT" -name "*$item*" 2>/dev/null | grep -q "$item"; then
        echo -e "[\e[32m OK \e[0m] $item found."
    else
        echo -e "[\e[31m MISSING \e[0m] $item NOT FOUND."
    fi
done

echo -e "\n--- SERVICE STATUS ---"
ALL_SERVICES=("${TARGETS[@]}" "${UNLISTED[@]}")
for svc in "${ALL_SERVICES[@]}"; do
    if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}.service"; then
        STATUS=$(systemctl is-active "$svc" 2>/dev/null)
        case $STATUS in
            active)        echo -e "[\e[32m ACTIVE \e[0m] $svc" ;;
            inactive|dead) echo -e "[\e[33m INACTIVE \e[0m] $svc" ;;
            failed)        echo -e "[\e[31m FAILED \e[0m] $svc" ;;
        esac
    fi
done

chmod -R 600 "$BACKUP_ROOT"
chmod 700 "$BACKUP_ROOT"
echo -e "\n--- Backup Complete: $BACKUP_ROOT ---"
