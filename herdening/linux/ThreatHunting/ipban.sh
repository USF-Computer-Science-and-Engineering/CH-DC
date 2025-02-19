#!/bin/bash

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root" >&2
  exit 1
fi

id_like_line=$(grep '^ID=' /etc/os-release)

operatingSystem=$(echo $id_like_line | cut -d'=' -f2 | tr -d '"')


if [ "$operatingSystem" = "debian" ] || [ "$operatingSystem" = "ubuntu" ]; then
	if [ $# -eq 0 ]; then
		echo "Not blocking IP addresses - no IP supplied"
	else
		iptables -I INPUT -s $1 -j DROP
		iptables -I OUTPUT -d $1 -j DROP
	fi
	iptables-save > /etc/iptables/rules.v4
	ip6tables-save > /etc/iptables/rules.v6
	sleep 2
	reboot
elif [ "$operatingSystem" = "fedora" ] || [ "$operatingSystem" = "centos" ]; then
	if [ $# -eq 0 ]; then
		echo "Not blocking IP addresses - no IP supplied"
	else
		iptables -I INPUT -s $1 -j DROP
		iptables -I OUTPUT -d $1 -j DROP
	fi
	service iptables save
	systemctl enable iptables
	sleep 2
	reboot
fi
