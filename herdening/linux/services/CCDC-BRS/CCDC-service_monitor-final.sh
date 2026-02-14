#!/usr/bin/env bash

SERVICES=(
    "sshd"
    "sssd"
    "apache2"
    "httpd"
    "nginx"
    "caddy"
    "mysql"
    "mysqld"
    "mariadb"
    "postgresql"
    "postfix"
    "dovecot"
    "exim4"
    "exim"
    "courier"
    "bind9"
    "named"
    "unbound"
    "dnsmasq"
    "smbd"
    "smb"
    "nmbd"
    "nmb"
    "vsftpd"
    "proftpd"
    "gitea"
    "snmpd"
    "nfs-server"
    "nfs-kernel-server"
    "openvpn"
)

LOG_FILE="/var/log/ccdc_monitor.log"
ALERT_FILE="/var/tmp/service_alerts.txt"

log_event() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

log_screen() {
    echo -e "$1"
}

check_and_restart() {
    local service=$1

    if ! systemctl list-unit-files 2>/dev/null | grep -q "^${service}.service"; then
        return
    fi

    if ! systemctl is-active --quiet "$service"; then
        STATUS=$(systemctl is-active "$service" 2>/dev/null)
        log_event "ALERT: $service is $STATUS"
        ERROR_MSG=$(journalctl -u "$service" -n 1 --no-pager -o cat 2>/dev/null | head -c 200)
        log_event "   Error: ${ERROR_MSG:-No error available}"
        echo "[$(date)] $service DOWN - ${ERROR_MSG}" >> "$ALERT_FILE"
        log_screen "[\e[31m ✗ \e[0m] $service - attempting restart..."
        systemctl restart "$service" >/dev/null 2>&1
        sleep 2
        if systemctl is-active --quiet "$service"; then
            log_event "SUCCESS: $service restarted"
            log_screen "[\e[32m ✓ \e[0m] $service - restart successful"
        else
            log_event "FAILED: $service restart FAILED"
            log_screen "[\e[31m ✗ \e[0m] $service - RESTART FAILED (check logs)"
        fi
    fi
}

mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null

clear
echo "=== CCDC Service Monitor ==="
echo "Log file: $LOG_FILE"
echo "Alert file: $ALERT_FILE"
echo ""

echo "Detected services on this host:"
for service in "${SERVICES[@]}"; do
    if systemctl list-unit-files 2>/dev/null | grep -q "^${service}.service"; then
        STATUS=$(systemctl is-active "$service" 2>/dev/null)
        case $STATUS in
            active)        echo -e "  [\e[32m ✓ \e[0m] $service" ;;
            inactive|dead) echo -e "  [\e[33m - \e[0m] $service (inactive)" ;;
            failed)        echo -e "  [\e[31m ✗ \e[0m] $service (failed)" ;;
        esac
    fi
done
echo ""

log_event "=== CCDC Service Monitor Started ==="
log_event "Monitoring: ${SERVICES[*]}"

while true; do
    for service in "${SERVICES[@]}"; do
        check_and_restart "$service"
    done
    echo -e "[\e[90m$(date '+%H:%M:%S')\e[0m] Scan complete - sleeping 30s..."
    sleep 30
done
