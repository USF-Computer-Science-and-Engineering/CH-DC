#!/bin/bash

# Array of users to exclude from changing to rbash
excludeFromRBash=("seccdc_black" "root")

# Array of valid login shells
valid_shells=(/bin/bash /bin/sh /usr/bin/zsh /usr/bin/fish)

# Function to check if an item is in an array
containsElement () {
  local e match="$1"
  shift
  for e; do [[ "$e" == "$match" ]] && return 0; done
  return 1
}

while IFS=: read -r username _ _ _ _ home shell; do
  if containsElement "$shell" "${valid_shells[@]}" && ! containsElement "$username" "${excludeFromRBash[@]}"; then
    echo "Changing shell for $username to rbash..."
    chsh -s /bin/rbash "$username" >/dev/null
    
    find "$home" -type f \( -name ".*shrc" -o -name ".*profile" -o -name ".*history" \) -exec rm -f {} +


    echo 'HISTFILE=/dev/null
unset HISTFILE
PATH=/usr/local/rbin
export PATH' > "$home/.bashrc"
    cp "$home/.bashrc" "$home/.bash_profile" 
    cp "$home/.bashrc" "$home/.profile" 

    chown -R "$username":"$username" "$home"
    chmod 644 "$home/.bashrc" "$home/.bash_profile" "$home/.profile"

    chmod -R go-w "$home"
    find "$home" -type d -exec chmod go+x {} +
    chattr +i "$home/.bashrc" "$home/.bash_profile" "$home/.profile"

  fi
done < /etc/passwd

mkdir -p /usr/local/rbin
chown root:root /usr/local/rbin
chmod 755 /usr/local/rbin
ln -s /usr/bin/whoami /usr/local/rbin/whoami
ln -s /usr/bin/id /usr/local/rbin/id

chown root:root /usr/local/rbin/whoami
chown root:root /usr/local/rbin/id
chmod 755 /usr/local/rbin/whoami
chmod 755 /usr/local/rbin/id

echo "Shell change process completed."
