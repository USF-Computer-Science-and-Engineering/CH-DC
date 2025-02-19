#!/bin/bash
# This will rotate all SSH keys and passwords, logging as required. User will be prompted for the password.
excludeUser=(
    "blackteam_adm"
    "root"
)

hostname=$(hostname)

keyDir="/etc/ssh/shared_keys"
mkdir -p "$keyDir"

sshKey="$keyDir/shared_key"
if [ ! -f "$sshKey" ]; then
    ssh-keygen -t rsa -b 4096 -f "$sshKey" -N ''
    echo "Shared SSH key pair generated."
else
    echo "Shared SSH key pair already exists."
fi

echo "Enter the new passphrase for all users (except for logging $excludeUser):"
read -s sharedPassphrase

if [[ -z "$sharedPassphrase" ]]; then
    echo "Passphrase cannot be empty. Exiting..."
    exit 1
fi

getent passwd | while IFS=: read -r username password uid gid full home shell; do
    if [[ ! " ${excludeUser[@]} " =~ " ${username} " ]]; then
        if [[ "$shell" == *sh ]]; then
            echo "$username:$sharedPassphrase" | chpasswd
            if [ $? -eq 0 ]; then
                echo "Password changed for $username"
            else
                echo "Failed to change password for $username"
                continue
            fi
            
            userSshDir="$home/.ssh"
            if [[ "$shell" == *sh ]]; then
                mkdir -p $userSshDir
                echo "" > "$userSshDir/authorized_keys"
                chown -R "$username":"$gid" "$userSshDir" 
                chmod 644 "$userSshDir/authorized_keys"
                echo "Shared SSH keys set for $username."
            fi
        fi
    fi
done

# Changing root user password
passwd

echo "Script completed."
