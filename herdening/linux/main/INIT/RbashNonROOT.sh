#!/usr/bin/env bash

################################################################################
#  RESTRICT USERS (LOCAL + AD):
#   - /bin/rbash for local users (via usermod)
#   - ForceCommand /bin/rbash in SSH for AD (or any usermod-fail) users
#   - Only "id" and "whoami" in ~/bin
#   - Extremely locked-down .bashrc / .bash_profile
#   - Prompt checks for LD_PRELOAD, environment builtins disabled
################################################################################

RBASH_SHELL="/bin/rbash"
ID_CMD="/usr/bin/id"
WHOAMI_CMD="/usr/bin/whoami"
SHELLS_FILE="/etc/shells"
SSHD_CONFIG="/etc/ssh/sshd_config"

# Ensure /bin/rbash exists
if [ ! -x "$RBASH_SHELL" ]; then
    echo "Creating /bin/rbash as a symlink to /bin/bash"
    ln -s /bin/bash /bin/rbash || { echo "Failed to create /bin/rbash"; exit 1; }
fi

# Ensure /bin/rbash is in /etc/shells for it to be a valid login shell
if ! grep -q "^$RBASH_SHELL$" "$SHELLS_FILE"; then
    echo "$RBASH_SHELL" >> "$SHELLS_FILE"
fi

# List of shell init files to remove
RC_FILES=(
    ".bashrc" ".bash_profile" ".profile" ".bash_logout"
    ".zshrc" ".zprofile" ".zlogin" ".zlogout"
    ".cshrc" ".tcshrc"
    ".kshrc" ".shrc"
)

# We'll read from getent passwd so we see AD users if SSSD/Winbind enumerates them
while IFS=: read -r username password uid gid gecos homedir shell; do
    
    # Skip excluded users or system users
    # Adjust or add more exclusions as needed
    if [[ "$username" == "root" || \
          "$username" == "postgres" || \
          "$username" == "seccdc_black" ]]; then
        continue
    fi

    # Possibly skip system/service accounts by checking UID range, e.g.:
    # if (( uid < 1000 )); then
    #     continue
    # fi
    
    # Only handle if homedir is under /home and shell is not false/nologin
    if [[ "$homedir" == /home/* && -n "$shell" && \
          "$shell" != "/bin/false" && "$shell" != "/usr/sbin/nologin" ]]; then
        echo "Processing user: $username with home $homedir"

        # Ensure the home directory actually exists
        if [ ! -d "$homedir" ]; then
            echo "Home directory for $username does not exist. Skipping."
            continue
        fi

        # Try changing the user's shell to rbash
        echo "Changing shell for $username to $RBASH_SHELL"
        usermod_failed=false
        if ! usermod -s "$RBASH_SHELL" "$username" 2>/dev/null; then
            echo "usermod failed for $username. Possibly a domain (AD) user."
            echo " - We'll fallback to SSH ForceCommand for $username."
            usermod_failed=true
        fi

        # Remove old shell RC files
        for rcfile in "${RC_FILES[@]}"; do
            if [ -e "$homedir/$rcfile" ]; then
                rm -f "$homedir/$rcfile"
            fi
        done

        # Create ~/bin if not exists
        user_bin_dir="$homedir/bin"
        if [ ! -d "$user_bin_dir" ]; then
            mkdir -p "$user_bin_dir"
        else
            # Clean up any existing files
            rm -f "$user_bin_dir"/*
        fi

        # Place only id and whoami in ~/bin
        ln -s "$ID_CMD"     "$user_bin_dir/id"
        ln -s "$WHOAMI_CMD" "$user_bin_dir/whoami"

        # Adjust permissions
        chown "$username":"$username" "$user_bin_dir" "$user_bin_dir/id" "$user_bin_dir/whoami"
        chmod 500 "$user_bin_dir"

        # Create minimal .bash_profile
        user_bash_profile="$homedir/.bash_profile"
        cat << 'EOF' > "$user_bash_profile"
# Minimal login file for restricted shell

# Immediately check if LD_PRELOAD or LD_LIBRARY_PATH is set at login
if [[ -n "$LD_PRELOAD" || -n "$LD_LIBRARY_PATH" ]]; then
    echo "LD_PRELOAD/LD_LIBRARY_PATH usage not allowed in this restricted shell."
    exit 1
fi

# Set PATH strictly to ~/bin
PATH="$HOME/bin"
export PATH

# Source .bashrc if it exists
if [ -f "$HOME/.bashrc" ]; then
    . "$HOME/.bashrc"
fi
EOF

        # Create highly restrictive .bashrc
        user_bashrc="$homedir/.bashrc"
        cat << 'EOF' > "$user_bashrc"
# ------------------------------------------------------------------------------
# Use PROMPT_COMMAND to keep checking environment each time user presses Enter
# ------------------------------------------------------------------------------
PROMPT_COMMAND='
if [[ -n "$LD_PRELOAD" || -n "$LD_LIBRARY_PATH" ]]; then
    echo "LD_PRELOAD/LD_LIBRARY_PATH usage not allowed in this restricted shell."
    exit 1
fi
'
declare -r PROMPT_COMMAND 2>/dev/null || true

# ------------------------------------------------------------------------------
# Restrict PATH again
# ------------------------------------------------------------------------------
PATH="$HOME/bin"
export PATH

# ------------------------------------------------------------------------------
# Enter restricted mode
# ------------------------------------------------------------------------------
set -r

# ------------------------------------------------------------------------------
# Disable builtins that manipulate environment or allow escapes
# ------------------------------------------------------------------------------
enable -n .
enable -n eval
enable -n exec
enable -n command
enable -n bg
enable -n fg
enable -n jobs
enable -n kill
enable -n suspend

enable -n alias
enable -n export
enable -n unset
enable -n set
enable -n typeset
enable -n declare
enable -n readonly

# Optionally also disable exit/logout if you want a user trapped
# enable -n exit
# enable -n logout
EOF

        chown "$username":"$username" "$user_bash_profile" "$user_bashrc"
        chmod 400 "$user_bash_profile" "$user_bashrc"

        # Restrict home directory permissions: read & execute only, no write
        chmod 500 "$homedir"

        # If usermod failed, we try ForceCommand in SSH
        # so that SSH logins are forced into /bin/rbash
        if [ "$usermod_failed" = true ]; then
            # Prevent duplicating lines each time we run
            if ! grep -q "Match User $username" "$SSHD_CONFIG"; then
                echo "" >> "$SSHD_CONFIG"
                echo "# Force /bin/rbash for $username" >> "$SSHD_CONFIG"
                echo "Match User $username" >> "$SSHD_CONFIG"
                echo "    ForceCommand $RBASH_SHELL" >> "$SSHD_CONFIG"
                echo "Added ForceCommand for $username in $SSHD_CONFIG"
            else
                echo "ForceCommand for $username already exists in $SSHD_CONFIG"
            fi
        fi

        echo "User $username is now restricted with .bashrc/.bash_profile in place."
    fi

done < <(getent passwd)

# Finally, reload SSH (if any ForceCommand lines were added)
if pgrep sshd >/dev/null 2>&1; then
    echo "Reloading SSH to apply ForceCommand changes..."
    systemctl reload ssh || systemctl restart ssh
fi

echo "All done."
