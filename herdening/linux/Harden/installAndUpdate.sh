#!/bin/bash

# Determine the package manager
if command -v apt > /dev/null; then
    pkgManager="apt"
elif command -v dnf > /dev/null; then
    pkgManager="dnf"
elif command -v yum > /dev/null; then
    pkgManager="yum"
else
    echo "No known package manager found. Script will exit."
    exit 1
fi

echo "Using package manager: $pkgManager"

# Define a generic update, install, and remove function
update_system() {
    sudo $pkgManager update -y
    if [ "$pkgManager" = "apt" ]; then
        sudo $pkgManager upgrade -y
    fi
}

install_package() {
    for pkg in "$@"; do
        echo "Attempting to install $pkg..."
        sudo $pkgManager install -y "$pkg" || echo "Failed to install $pkg. Skipping..."
    done
}

remove_package() {
    if [ "$pkgManager" = "apt" ]; then
        sudo $pkgManager purge -y "$@"
    else
        sudo $pkgManager remove -y "$@"
    fi
}

fix_missing_apt() {
    if [ "$pkgManager" = "apt" ]; then
        sudo apt update --fix-missing
    fi
}

enable_service() {
    sudo systemctl enable "$@"
    sudo systemctl start "$@"
}

fix_missing_apt

# Update system
update_system

# Install packages
# Added iptables-persistent and iptables-services to the package list
packageList="epel-release inotify-tools rsyslog git socat fail2ban zip net-tools htop e2fsprogs ufw rkhunter debsums chkrootkit rbash iptables-persistent iptables-services clamav clamav-daemon"
install_package $packageList

remove_package cron

# Special handling for UFW, considering its availability
# Removed the UFW installation from here because it's now included directly in the package list

# Enable and start fail2ban
enable_service fail2ban

echo "Package installation and configuration completed."
