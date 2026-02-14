#!/usr/bin/env bash

OUTPUT="/root/services_$(hostname)_$(date +%Y%m%d_%H%M).txt"
exec > >(tee -a "$OUTPUT")

echo "================================================================="
echo "  CCDC Quick Service Enumeration - $(date)"
echo "================================================================="

echo -e "\n[1] HOSTNAME"
echo "-----------------------------------------------------------------"
hostname

echo -e "\n[2] IP ADDRESS"
echo "-----------------------------------------------------------------"
ip -4 a 2>/dev/null | grep inet | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1

echo -e "\n[3] SERVICES, PORTS & VERSIONS"
echo "-----------------------------------------------------------------"

if command -v nmap &>/dev/null; then
    echo "[*] Running nmap version scan on localhost..."
    nmap -sV -p- --open localhost 2>/dev/null | grep -E "^[0-9]+/|PORT" | awk '
    BEGIN { printf "%-10s %-15s %-20s %-40s\n", "PORT", "STATE", "SERVICE", "VERSION"; 
            print "-----------------------------------------------------------------" }
    /^PORT/ { next }
    /^[0-9]/ { 
        port=$1; 
        state=$2; 
        service=$3; 
        version="";
        for(i=4; i<=NF; i++) version=version" "$i;
        printf "%-10s %-15s %-20s %-40s\n", port, state, service, version
    }'
else
    echo "[!] nmap not installed - using fallback (no version detection)"
    echo "[!] Install with: apt install nmap -y"
    echo ""
    printf "%-10s %-20s %-30s\n" "PROTO" "PORT" "PROCESS"
    echo "-----------------------------------------------------------------"
    ss -tulpn 2>/dev/null | grep LISTEN | while read -r line; do
        proto=$(echo "$line" | awk '{print $1}')
        port=$(echo "$line" | awk '{print $5}' | rev | cut -d: -f1 | rev)
        pid=$(echo "$line" | grep -oE 'pid=[0-9]+' | cut -d= -f2)
        
        if [ -n "$pid" ]; then
            proc=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ' | awk '{print $1}' | xargs basename)
            printf "%-10s %-20s %-30s\n" "$proto" "$port" "${proc:-Unknown}"
        fi
    done
fi

echo -e "\n[4] CCDC TARGET SERVICES STATUS"
echo "-----------------------------------------------------------------"
TARGETS=("ssh" "sshd" "dovecot" "postfix" "exim" "nginx" "apache2" "httpd" "mysql" "mariadb" "postgresql" "bind" "bind9" "named" "vsftpd" "proftpd" "samba" "smb" "smbd" "snmpd" "nfs-server" "nfs-kernel-server" "openvpn" "telnetd" "caddy" "gitea" "courier" "unbound" "dnsmasq" "docker")

for svc in "${TARGETS[@]}"; do
    if systemctl list-unit-files 2>/dev/null | grep -qE "^${svc}\.service"; then
        status=$(systemctl is-active "$svc" 2>/dev/null)
        [ "$status" = "active" ] && echo "[✓] $svc - RUNNING" || echo "[ ] $svc - stopped"
    fi
done

echo -e "\n[5] ADMIN USERS"
echo "-----------------------------------------------------------------"
grep -E '^(sudo|wheel|admin):' /etc/group

echo -e "\n[6] FIREWALL STATUS"
echo "-----------------------------------------------------------------"
if command -v ufw &>/dev/null; then
    ufw status 2>/dev/null | head -20
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --list-all 2>/dev/null
else
    iptables -L -n 2>/dev/null | head -20
fi

echo -e "\n================================================================="
echo "  Report saved: $OUTPUT"
echo "================================================================="