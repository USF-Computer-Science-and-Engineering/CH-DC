#!/usr/bin/env bash

# Ensure we run as root
if [ "$(id -u)" != "0" ]; then
  echo "ERROR: This script must be run as root!"
  exit 1
fi

read -p "Enter TCP ports to allow (space-separated, e.g. 22 80 443): " PORTS

which iptables >/dev/null 2>&1
HAS_IPTABLES=$?

which ipfw >/dev/null 2>&1
HAS_IPFW=$?

if [ $HAS_IPTABLES -ne 0 ] && [ $HAS_IPFW -ne 0 ]; then
  echo "ERROR: Neither 'iptables' nor 'ipfw' were found on this system."
  echo "This script supports only:"
  echo "  - Linux (with iptables)"
  echo "  - FreeBSD (with ipfw)."
  exit 1
fi

apply_firewall_rules() {
  while true; do
    if [ $HAS_IPTABLES -eq 0 ]; then
      echo "[+] Flushing iptables rules..."
      iptables -F
      iptables -X
      iptables -t nat -F
      iptables -t nat -X
      iptables -t mangle -F
      iptables -t mangle -X

      echo "[+] Setting default policies (DROP incoming, DROP forwarding, ALLOW outgoing)..."
      iptables -P INPUT DROP
      iptables -P FORWARD DROP
      iptables -P OUTPUT ACCEPT

      echo "[+] Allowing loopback interface traffic..."
      iptables -A INPUT -i lo -j ACCEPT

      echo "[+] Allowing established and related incoming traffic..."
      iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

      echo "[+] Allowing incoming TCP on the specified ports: $PORTS"
      for port in $PORTS; do
        iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
      done


    elif [ $HAS_IPFW -eq 0 ]; then
      echo "[+] Flushing ipfw rules..."
      ipfw -q flush

      echo "[+] Setting default deny rule..."
      ipfw -q add 100 deny all from any to any

      echo "[+] Allowing loopback traffic (rule #50)..."
      ipfw -q add 50 allow all from any to any via lo0

      echo "[+] Allowing established TCP sessions (rule #60)..."
      ipfw -q add 60 allow tcp from any to any established

      echo "[+] Allowing inbound TCP on the specified ports: $PORTS"
      PRIO=200
      for port in $PORTS; do
        ipfw -q add $PRIO allow tcp from any to me dst-port "$port"
        PRIO=$((PRIO + 1))
      done
    fi

    echo "[+] Firewall rules applied. Sleeping 30 seconds..."
    sleep 30
  done
}

apply_firewall_rules
