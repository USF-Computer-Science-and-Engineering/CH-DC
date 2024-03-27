#!/bin/bash

sudo ufw disable
sudo ufw --force reset

# Define arrays of TCP and UDP ports to open
#tcp_ports=(20 21 22 80 88 135 389 443 445 464 636 3306 3268 3269 9389 49443) # Add your desired TCP ports here
#udp_ports=(53) # Add your desired UDP ports here
tcp_ports=()
udp_ports=()
# Set default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Loop through the tcp_ports array and allow each TCP port
for port in "${tcp_ports[@]}"; do
    sudo ufw allow $port/tcp
done

# Loop through the udp_ports array and allow each UDP port
for port in "${udp_ports[@]}"; do
    sudo ufw allow $port/udp
done

# Enable UFW
sudo ufw enable

# Restart UFW to apply changes
sudo ufw reload

# Check the status of UFW
sudo ufw status verbose
