#!/usr/bin/env bash

if [[ $EUID -ne 0 ]]; then
   echo "[!] Must run as root"
   exit 1
fi

BACKUP_DIR=$(ls -td /root/Injects_* /var/tmp/backups_* 2>/dev/null | head -1)

if [ -z "$BACKUP_DIR" ]; then
    echo "[!] No backup found"
    exit 1
fi

detect_distro() {
    if [ -f "$BACKUP_DIR/.distro_family" ]; then
        cat "$BACKUP_DIR/.distro_family"
        return
    fi
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
    if [ -f "$BACKUP_DIR/.web_user" ]; then
        cat "$BACKUP_DIR/.web_user"
        return
    fi
    if id "www-data" &>/dev/null; then echo "www-data"
    elif id "apache" &>/dev/null; then echo "apache"
    elif id "nginx" &>/dev/null; then echo "nginx"
    else echo "root"
    fi
}

DISTRO_FAMILY=$(detect_distro)
WEB_USER=$(get_web_user)

restart_svc() {
    for svc in "$@"; do
        if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}.service"; then
            systemctl restart "$svc" >/dev/null 2>&1
        fi
    done
}

check_status() {
    local svc=$1
    if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}.service"; then
        STATUS=$(systemctl is-active "$svc" 2>/dev/null)
        case $STATUS in
            active)        echo -e "[\e[32m ACTIVE \e[0m] $svc" ;;
            inactive|dead) echo -e "[\e[33m INACTIVE \e[0m] $svc" ;;
            failed)        echo -e "[\e[31m FAILED \e[0m] $svc" ;;
            *)             echo -e "[\e[90m UNKNOWN \e[0m] $svc" ;;
        esac
    fi
}

check_status_multi() {
    for svc in "$@"; do
        check_status "$svc"
    done
}

echo "=== CCDC RESTORE MENU ==="
echo "Backup: $BACKUP_DIR"
echo "Distro: $DISTRO_FAMILY"
echo ""
echo "AUTHENTICATION & ACCESS:"
echo "  1) SSH (sshd_config + keys)"
echo "  2) Auth (SSSD + Kerberos + LDAP)"
echo "  3) Users (passwd/shadow/group)"
echo "  4) PAM (login policies)"
echo "  5) Sudoers"
echo "  6) Shell Configs (bashrc, profile)"
echo ""
echo "NETWORK & SECURITY:"
echo "  7) Firewall (iptables/ufw/nftables/firewalld)"
echo "  8) Network configs (resolv.conf, etc)"
echo ""
echo "WEB SERVERS:"
echo "  9) Apache/httpd"
echo "  10) Nginx"
echo "  11) Caddy"
echo ""
echo "DATABASES:"
echo "  12) MySQL/MariaDB"
echo "  13) PostgreSQL"
echo ""
echo "MAIL:"
echo "  14) Postfix"
echo "  15) Dovecot"
echo "  16) Exim"
echo "  17) Courier"
echo ""
echo "FILE/DOMAIN SERVICES:"
echo "  18) Samba"
echo "  19) FTP (vsftpd/proftpd)"
echo "  20) Gitea"
echo ""
echo "NETWORK SERVICES:"
echo "  21) BIND/Named (DNS)"
echo "  22) Unbound (DNS)"
echo "  23) dnsmasq (DNS)"
echo "  24) SNMP"
echo "  25) NFS"
echo "  26) OpenVPN"
echo ""
echo "WEB CONTENT:"
echo "  27) Full Web Root (/var/www)"
echo "  28) WordPress"
echo ""
echo "PACKAGE MANAGER:"
echo "  29) APT/YUM/DNF (repos + keyrings)"
echo ""
echo "NUCLEAR OPTIONS:"
echo "  30) All Auth (SSH + SSSD + Users + PAM + Shell)"
echo "  31) All Services"
echo "  32) EVERYTHING"
echo ""
echo "VERIFICATION & EMERGENCY:"
echo "  33) Verify Binaries (check for rootkits)"
echo "  34) Restore Binaries (LAST RESORT)"
echo ""
read -p "Select [1-34]: " choice

case $choice in
    1)
        echo "[*] Restoring SSH..."
        cp -r "$BACKUP_DIR/ssh/"* /etc/ssh/
        chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null
        chmod 644 /etc/ssh/sshd_config
        restart_svc sshd ssh
        echo "✓ SSH restored"
        check_status sshd
        ;;
    2)
        echo "[*] Restoring authentication..."
        tar -xzf "$BACKUP_DIR/auth/sssd_etc.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/auth/sssd_cache.tar.gz" -C / 2>/dev/null
        cp "$BACKUP_DIR/auth/nsswitch.conf" /etc/nsswitch.conf 2>/dev/null
        cp "$BACKUP_DIR/auth/krb5.conf" /etc/krb5.conf 2>/dev/null
        tar -xzf "$BACKUP_DIR/auth/krb5_conf_d.tar.gz" -C / 2>/dev/null
        cp "$BACKUP_DIR/auth/machine.keytab" /etc/krb5.keytab 2>/dev/null
        if [ "$DISTRO_FAMILY" = "debian" ]; then
            [ -f "$BACKUP_DIR/auth/ldap_debian.conf" ] && mkdir -p /etc/ldap && cp "$BACKUP_DIR/auth/ldap_debian.conf" /etc/ldap/ldap.conf
        elif [ "$DISTRO_FAMILY" = "rhel" ]; then
            [ -f "$BACKUP_DIR/auth/ldap_rhel.conf" ] && mkdir -p /etc/openldap && cp "$BACKUP_DIR/auth/ldap_rhel.conf" /etc/openldap/ldap.conf
        else
            [ -f "$BACKUP_DIR/auth/ldap_debian.conf" ] && [ -d "/etc/ldap" ] && cp "$BACKUP_DIR/auth/ldap_debian.conf" /etc/ldap/ldap.conf
            [ -f "$BACKUP_DIR/auth/ldap_rhel.conf" ] && [ -d "/etc/openldap" ] && cp "$BACKUP_DIR/auth/ldap_rhel.conf" /etc/openldap/ldap.conf
        fi
        tar -xzf "$BACKUP_DIR/auth/realmd.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/auth/samba_secrets.tar.gz" -C / 2>/dev/null
        chmod 600 /etc/sssd/sssd.conf /etc/krb5.keytab 2>/dev/null
        restart_svc sssd
        echo "✓ Auth restored"
        check_status sssd
        realm list 2>/dev/null
        ;;
    3)
        echo "[*] Restoring users..."
        cp "$BACKUP_DIR/system/passwd" /etc/passwd
        cp "$BACKUP_DIR/system/shadow" /etc/shadow
        cp "$BACKUP_DIR/system/group" /etc/group
        cp "$BACKUP_DIR/system/gshadow" /etc/gshadow
        echo "✓ Users restored"
        ;;
    4)
        echo "[*] Restoring PAM..."
        tar -xzf "$BACKUP_DIR/system/pam_configs.tar.gz" -C / 2>/dev/null
        echo "✓ PAM restored"
        ;;
    5)
        echo "[*] Restoring sudoers..."
        cp "$BACKUP_DIR/system/sudoers" /etc/sudoers 2>/dev/null
        echo "✓ Sudoers restored"
        ;;
    6)
        echo "[*] Restoring shell configs..."
        [ -f "$BACKUP_DIR/shell/bash.bashrc" ] && cp "$BACKUP_DIR/shell/bash.bashrc" /etc/bash.bashrc
        [ -f "$BACKUP_DIR/shell/bashrc" ] && cp "$BACKUP_DIR/shell/bashrc" /etc/bashrc
        [ -f "$BACKUP_DIR/shell/profile" ] && cp "$BACKUP_DIR/shell/profile" /etc/profile
        tar -xzf "$BACKUP_DIR/shell/profile_d.tar.gz" -C / 2>/dev/null
        [ -f "$BACKUP_DIR/shell/root_bashrc" ] && cp "$BACKUP_DIR/shell/root_bashrc" /root/.bashrc
        [ -f "$BACKUP_DIR/shell/root_bash_profile" ] && cp "$BACKUP_DIR/shell/root_bash_profile" /root/.bash_profile
        [ -f "$BACKUP_DIR/shell/root_profile" ] && cp "$BACKUP_DIR/shell/root_profile" /root/.profile
        for rc in "$BACKUP_DIR/shell/"*_bashrc "$BACKUP_DIR/shell/"*_bash_profile "$BACKUP_DIR/shell/"*_profile; do
            [ -f "$rc" ] || continue
            filename=$(basename "$rc")
            user=$(echo "$filename" | cut -d'_' -f1)
            rctype=$(echo "$filename" | cut -d'_' -f2-)
            [ -d "/home/$user" ] && cp "$rc" "/home/$user/.$rctype" 2>/dev/null
        done
        echo "✓ Shell configs restored"
        ;;
    7)
        echo "[*] Restoring firewall..."
        [ -f "$BACKUP_DIR/network/iptables.rules" ] && command -v iptables-restore >/dev/null && iptables-restore < "$BACKUP_DIR/network/iptables.rules"
        [ -f "$BACKUP_DIR/network/nft.rules" ] && command -v nft >/dev/null && nft -f "$BACKUP_DIR/network/nft.rules"
        if [ -f "$BACKUP_DIR/network/firewalld_etc.tar.gz" ] && command -v firewall-cmd >/dev/null; then
            tar -xzf "$BACKUP_DIR/network/firewalld_etc.tar.gz" -C / 2>/dev/null
            restart_svc firewalld
            echo "  ✓ firewalld config restored"
        fi
        [ -f "$BACKUP_DIR/network/ufw.rules" ] && echo "UFW rules at: $BACKUP_DIR/network/ufw.rules (manual review needed)"
        echo "✓ Firewall restored"
        command -v iptables >/dev/null && iptables -L -n 2>/dev/null | head -20
        command -v firewall-cmd >/dev/null && firewall-cmd --list-all 2>/dev/null
        ;;
    8)
        echo "[*] Restoring network configs..."
        cp "$BACKUP_DIR/system/resolv.conf" /etc/resolv.conf 2>/dev/null
        cp "$BACKUP_DIR/system/fstab" /etc/fstab 2>/dev/null
        [ -f "$BACKUP_DIR/network/interfaces" ] && cp "$BACKUP_DIR/network/interfaces" /etc/network/interfaces 2>/dev/null
        tar -xzf "$BACKUP_DIR/network/interfaces_d.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/network/NetworkManager.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/network/netplan.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/network/network-scripts.tar.gz" -C / 2>/dev/null
        [ -f "$BACKUP_DIR/network/sysconfig_network" ] && cp "$BACKUP_DIR/network/sysconfig_network" /etc/sysconfig/network 2>/dev/null
        echo "✓ Network configs restored"
        ;;
    9)
        echo "[*] Restoring Apache..."
        tar -xzf "$BACKUP_DIR/services/apache_etc.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/services/apache2_etc.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/services/httpd_etc.tar.gz" -C / 2>/dev/null
        restart_svc apache2 httpd
        echo "✓ Apache restored"
        check_status_multi apache2 httpd
        ;;
    10)
        echo "[*] Restoring Nginx..."
        tar -xzf "$BACKUP_DIR/services/nginx_etc.tar.gz" -C / 2>/dev/null
        restart_svc nginx
        echo "✓ Nginx restored"
        check_status nginx
        ;;
    11)
        echo "[*] Restoring Caddy..."
        tar -xzf "$BACKUP_DIR/services/caddy_etc.tar.gz" -C / 2>/dev/null
        restart_svc caddy
        echo "✓ Caddy restored"
        check_status caddy
        ;;
    12)
        echo "[*] Restoring MySQL/MariaDB..."
        tar -xzf "$BACKUP_DIR/services/mysql_etc.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/services/mariadb_etc.tar.gz" -C / 2>/dev/null
        restart_svc mysql mysqld mariadb
        echo "✓ MySQL/MariaDB restored"
        check_status_multi mysql mysqld mariadb
        ;;
    13)
        echo "[*] Restoring PostgreSQL..."
        tar -xzf "$BACKUP_DIR/services/postgresql_etc.tar.gz" -C / 2>/dev/null
        restart_svc postgresql
        echo "✓ PostgreSQL restored"
        check_status postgresql
        ;;
    14)
        echo "[*] Restoring Postfix..."
        tar -xzf "$BACKUP_DIR/services/postfix_etc.tar.gz" -C / 2>/dev/null
        restart_svc postfix
        echo "✓ Postfix restored"
        check_status postfix
        ;;
    15)
        echo "[*] Restoring Dovecot..."
        tar -xzf "$BACKUP_DIR/services/dovecot_etc.tar.gz" -C / 2>/dev/null
        restart_svc dovecot
        echo "✓ Dovecot restored"
        check_status dovecot
        ;;
    16)
        echo "[*] Restoring Exim..."
        tar -xzf "$BACKUP_DIR/services/exim_etc.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/services/exim4_etc.tar.gz" -C / 2>/dev/null
        restart_svc exim4 exim
        echo "✓ Exim restored"
        check_status_multi exim4 exim
        ;;
    17)
        echo "[*] Restoring Courier..."
        tar -xzf "$BACKUP_DIR/services/courier_etc.tar.gz" -C / 2>/dev/null
        restart_svc courier courier-imap courier-pop
        echo "✓ Courier restored"
        check_status courier
        ;;
    18)
        echo "[*] Restoring Samba..."
        tar -xzf "$BACKUP_DIR/services/samba_etc.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/services/smb_etc.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/auth/samba_secrets.tar.gz" -C / 2>/dev/null
        restart_svc smbd nmbd smb nmb
        echo "✓ Samba restored"
        check_status_multi smbd nmbd smb nmb
        ;;
    19)
        echo "[*] Restoring FTP..."
        tar -xzf "$BACKUP_DIR/services/vsftpd_etc.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/services/proftpd_etc.tar.gz" -C / 2>/dev/null
        restart_svc vsftpd proftpd
        echo "✓ FTP restored"
        check_status_multi vsftpd proftpd
        ;;
    20)
        echo "[*] Restoring Gitea..."
        tar -xzf "$BACKUP_DIR/services/gitea_etc.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/webapps/gitea_data.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/webapps/gitea_lib.tar.gz" -C / 2>/dev/null
        restart_svc gitea
        echo "✓ Gitea restored"
        check_status gitea
        ;;
    21)
        echo "[*] Restoring BIND..."
        tar -xzf "$BACKUP_DIR/services/bind_etc.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/services/bind9_etc.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/services/named_etc.tar.gz" -C / 2>/dev/null
        restart_svc bind9 named
        echo "✓ BIND restored"
        check_status_multi bind9 named
        ;;
    22)
        echo "[*] Restoring Unbound..."
        tar -xzf "$BACKUP_DIR/services/unbound_etc.tar.gz" -C / 2>/dev/null
        restart_svc unbound
        echo "✓ Unbound restored"
        check_status unbound
        ;;
    23)
        echo "[*] Restoring dnsmasq..."
        tar -xzf "$BACKUP_DIR/services/dnsmasq_etc.tar.gz" -C / 2>/dev/null
        restart_svc dnsmasq
        echo "✓ dnsmasq restored"
        check_status dnsmasq
        ;;
    24)
        echo "[*] Restoring SNMP..."
        tar -xzf "$BACKUP_DIR/services/snmpd_etc.tar.gz" -C / 2>/dev/null
        restart_svc snmpd
        echo "✓ SNMP restored"
        check_status snmpd
        ;;
    25)
        echo "[*] Restoring NFS..."
        tar -xzf "$BACKUP_DIR/services/nfs-server_etc.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/services/nfs-kernel-server_etc.tar.gz" -C / 2>/dev/null
        restart_svc nfs-server nfs-kernel-server
        echo "✓ NFS restored"
        check_status_multi nfs-server nfs-kernel-server
        ;;
    26)
        echo "[*] Restoring OpenVPN..."
        tar -xzf "$BACKUP_DIR/services/openvpn_etc.tar.gz" -C / 2>/dev/null
        restart_svc openvpn
        echo "✓ OpenVPN restored"
        check_status openvpn
        ;;
    27)
        echo "[*] Restoring full web root..."
        tar -xzf "$BACKUP_DIR/webroot/var_www.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/webroot/nginx_html.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/webroot/srv_www.tar.gz" -C / 2>/dev/null
        chown -R "$WEB_USER:$WEB_USER" /var/www 2>/dev/null
        restart_svc apache2 httpd nginx
        echo "✓ Web root restored (owner: $WEB_USER)"
        ;;
    28)
        echo "[*] Restoring WordPress..."
        WP_ROOT=$(find /var/www /usr/share/nginx/html /opt -name "wp-config.php" -exec dirname {} \; 2>/dev/null | head -1)
        if [ -n "$WP_ROOT" ]; then
            cp "$BACKUP_DIR/webapps/wp-config.php" "$WP_ROOT/" 2>/dev/null
            tar -xzf "$BACKUP_DIR/webapps/wordpress_content.tar.gz" -C / 2>/dev/null
            [ -f "$BACKUP_DIR/webapps/wordpress_htaccess" ] && cp "$BACKUP_DIR/webapps/wordpress_htaccess" "$WP_ROOT/.htaccess"
            chown -R "$WEB_USER:$WEB_USER" "$WP_ROOT" 2>/dev/null
            restart_svc apache2 httpd nginx
            echo "✓ WordPress restored (owner: $WEB_USER)"
        else
            echo "❌ WordPress not found"
        fi
        ;;
    29)
        echo "[*] Restoring package manager..."
        tar -xzf "$BACKUP_DIR/packages/apt_etc.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/packages/apt_keyrings.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/packages/yum_repos.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/packages/rpm_keyrings.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/packages/dnf_etc.tar.gz" -C / 2>/dev/null
        if command -v apt >/dev/null; then
            apt update 2>/dev/null
        elif command -v dnf >/dev/null; then
            dnf clean all 2>/dev/null
        elif command -v yum >/dev/null; then
            yum clean all 2>/dev/null
        fi
        echo "✓ Package manager restored"
        ;;
    30)
        echo "[*] RESTORING ALL AUTH..."
        cp -r "$BACKUP_DIR/ssh/"* /etc/ssh/
        chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null
        tar -xzf "$BACKUP_DIR/auth/sssd_etc.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/auth/sssd_cache.tar.gz" -C / 2>/dev/null
        cp "$BACKUP_DIR/auth/"*.conf /etc/ 2>/dev/null
        chmod 600 /etc/sssd/sssd.conf /etc/krb5.keytab 2>/dev/null
        cp "$BACKUP_DIR/system/passwd" /etc/passwd
        cp "$BACKUP_DIR/system/shadow" /etc/shadow
        cp "$BACKUP_DIR/system/group" /etc/group
        tar -xzf "$BACKUP_DIR/system/pam_configs.tar.gz" -C / 2>/dev/null
        cp "$BACKUP_DIR/system/sudoers" /etc/sudoers 2>/dev/null
        [ -f "$BACKUP_DIR/shell/bash.bashrc" ] && cp "$BACKUP_DIR/shell/bash.bashrc" /etc/bash.bashrc
        [ -f "$BACKUP_DIR/shell/bashrc" ] && cp "$BACKUP_DIR/shell/bashrc" /etc/bashrc
        [ -f "$BACKUP_DIR/shell/root_bashrc" ] && cp "$BACKUP_DIR/shell/root_bashrc" /root/.bashrc
        restart_svc sshd ssh
        restart_svc sssd
        echo "✓ ALL AUTH RESTORED"
        check_status sshd
        check_status sssd
        ;;
    31)
        echo "[*] RESTORING ALL SERVICES..."
        for t in "$BACKUP_DIR/services/"*.tar.gz; do
            [ -f "$t" ] && tar -xzf "$t" -C / 2>/dev/null
        done
        restart_svc apache2 httpd
        restart_svc nginx
        restart_svc caddy
        restart_svc mysql mysqld mariadb
        restart_svc postfix
        restart_svc dovecot
        restart_svc exim4 exim
        restart_svc bind9 named
        restart_svc unbound
        restart_svc dnsmasq
        restart_svc smbd smb
        restart_svc nmbd nmb
        restart_svc vsftpd
        restart_svc proftpd
        restart_svc gitea
        restart_svc snmpd
        restart_svc nfs-server nfs-kernel-server
        restart_svc openvpn
        echo "✓ ALL SERVICES RESTORED"
        echo ""
        for svc in apache2 httpd nginx caddy mysql mysqld mariadb postfix dovecot exim4 exim bind9 named smbd smb vsftpd gitea snmpd nfs-server nfs-kernel-server; do
            check_status "$svc"
        done
        ;;
    32)
        echo "[*] NUCLEAR RESTORE - EVERYTHING..."
        tar -xzf "$BACKUP_DIR/system/pam_configs.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/auth/sssd_etc.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/auth/sssd_cache.tar.gz" -C / 2>/dev/null
        cp "$BACKUP_DIR/system/"* /etc/ 2>/dev/null
        cp "$BACKUP_DIR/auth/"*.conf /etc/ 2>/dev/null
        cp -r "$BACKUP_DIR/ssh/"* /etc/ssh/ 2>/dev/null
        tar -xzf "$BACKUP_DIR/shell/profile_d.tar.gz" -C / 2>/dev/null
        [ -f "$BACKUP_DIR/shell/bash.bashrc" ] && cp "$BACKUP_DIR/shell/bash.bashrc" /etc/bash.bashrc
        [ -f "$BACKUP_DIR/shell/bashrc" ] && cp "$BACKUP_DIR/shell/bashrc" /etc/bashrc
        for t in "$BACKUP_DIR/services/"*.tar.gz; do [ -f "$t" ] && tar -xzf "$t" -C / 2>/dev/null; done
        tar -xzf "$BACKUP_DIR/webroot/var_www.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/webroot/nginx_html.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/packages/apt_keyrings.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/packages/rpm_keyrings.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/packages/dnf_etc.tar.gz" -C / 2>/dev/null
        tar -xzf "$BACKUP_DIR/network/firewalld_etc.tar.gz" -C / 2>/dev/null
        chown -R "$WEB_USER:$WEB_USER" /var/www 2>/dev/null
        chmod 600 /etc/ssh/ssh_host_*_key /etc/sssd/sssd.conf 2>/dev/null
        restart_svc sshd ssh
        restart_svc sssd
        restart_svc apache2 httpd
        restart_svc nginx
        restart_svc caddy
        restart_svc mysql mysqld mariadb
        restart_svc postfix
        restart_svc dovecot
        restart_svc exim4 exim
        restart_svc bind9 named
        restart_svc smbd smb
        restart_svc nmbd nmb
        restart_svc vsftpd
        restart_svc proftpd
        restart_svc gitea
        restart_svc snmpd
        restart_svc nfs-server nfs-kernel-server
        restart_svc openvpn
        restart_svc firewalld
        echo "✓ FULL RESTORE COMPLETE"
        echo ""
        echo "=== SERVICE STATUS ==="
        for svc in sshd sssd apache2 httpd nginx caddy mysql mysqld mariadb postfix dovecot exim4 exim bind9 named smbd smb vsftpd gitea snmpd nfs-server nfs-kernel-server openvpn; do
            check_status "$svc"
        done
        ;;
    33)
        echo "[*] Verifying system binaries..."
        echo ""
        COMPROMISED=0
        for bin in sudo sshd ssh passwd su ls ps grep ss apt dpkg yum dnf rpm; do
            CURRENT_BIN=""
            for loc in /usr/bin /usr/sbin /bin /sbin; do
                if [ -f "$loc/$bin" ]; then
                    CURRENT_BIN="$loc/$bin"
                    break
                fi
            done
            [ -z "$CURRENT_BIN" ] && continue
            CURRENT_HASH=$(sha256sum "$CURRENT_BIN" 2>/dev/null | awk '{print $1}')
            BACKUP_HASH=$(grep "/${bin}$\|/${bin} " "$BACKUP_DIR/binaries/HASHES.txt" 2>/dev/null | head -1 | awk '{print $1}')
            if [ -n "$BACKUP_HASH" ]; then
                if [ "$CURRENT_HASH" = "$BACKUP_HASH" ]; then
                    echo -e "[\e[32m OK \e[0m] $bin - matches backup"
                else
                    echo -e "[\e[31m COMPROMISED \e[0m] $bin - HASH MISMATCH"
                    echo "     Current:  $CURRENT_HASH"
                    echo "     Backup:   $BACKUP_HASH"
                    COMPROMISED=1
                fi
            fi
        done
        echo ""
        if [ $COMPROMISED -eq 1 ]; then
            echo -e "[\e[33m WARNING \e[0m] Compromised binaries detected!"
            echo "Recommended action:"
            command -v apt >/dev/null && echo "  sudo apt reinstall openssh-server sudo coreutils procps"
            command -v dnf >/dev/null && echo "  sudo dnf reinstall openssh-server sudo coreutils procps-ng"
            command -v yum >/dev/null && ! command -v dnf >/dev/null && echo "  sudo yum reinstall openssh-server sudo coreutils procps-ng"
        else
            echo -e "[\e[32m ALL CLEAR \e[0m] No compromised binaries detected"
        fi
        ;;
    34)
        echo "[!] WARNING: Only use if package manager is completely broken!"
        echo ""
        read -p "Continue with binary restore? [y/N]: " response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            echo "[*] Restoring binaries..."
            mkdir -p /tmp/backup_bins
            cp "$BACKUP_DIR/binaries/"* /tmp/backup_bins/ 2>/dev/null
            for bin in /tmp/backup_bins/*; do
                binname=$(basename "$bin")
                [[ "$binname" == "HASHES.txt" ]] && continue
                if [[ "$binname" =~ ^(sshd|useradd|usermod)$ ]]; then
                    cp "$bin" /usr/sbin/ 2>/dev/null
                else
                    cp "$bin" /usr/bin/ 2>/dev/null
                fi
            done
            chmod 755 /usr/bin/* /usr/sbin/* 2>/dev/null
            rm -rf /tmp/backup_bins
            echo "✓ Binaries restored"
            echo ""
            echo -e "[\e[33m IMPORTANT \e[0m] NOW REINSTALL WITH PACKAGE MANAGER:"
            command -v apt >/dev/null && echo "  sudo apt reinstall openssh-server sudo coreutils procps"
            command -v dnf >/dev/null && echo "  sudo dnf reinstall openssh-server sudo coreutils procps-ng"
            command -v yum >/dev/null && ! command -v dnf >/dev/null && echo "  sudo yum reinstall openssh-server sudo coreutils procps-ng"
        else
            echo "Binary restore cancelled"
        fi
        ;;
    *)
        echo "[!] Invalid choice"
        exit 1
        ;;
esac

echo ""
