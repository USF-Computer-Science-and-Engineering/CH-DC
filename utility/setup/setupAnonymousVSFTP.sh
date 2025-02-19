#!/bin/bash

# Update the system and install vsftpd
sudo apt-get update
sudo apt-get install -y vsftpd

# Backup the original vsftpd configuration
sudo cp /etc/vsftpd.conf /etc/vsftpd.conf.bak

# Enable anonymous FTP access
sudo sed -i 's/anonymous_enable=NO/anonymous_enable=YES/' /etc/vsftpd.conf

# Specify the local root directory for anonymous users (optional)
# Uncomment and set the desired directory
# sudo echo "anon_root=/var/ftp/pub" >> /etc/vsftpd.conf

# Restart vsftpd to apply changes
sudo systemctl restart vsftpd

echo "vsftpd installation and configuration complete. Anonymous login is enabled."