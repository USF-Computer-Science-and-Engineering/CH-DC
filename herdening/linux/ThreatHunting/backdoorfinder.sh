#!/bin/bash
# Simplified Interactive Backdoor Detection & Removal Script
# Supports Ubuntu and CentOS.
# WARNING: This script makes system modifications. Test in a safe environment.

##############################
# 1. OS Identification       #
##############################
identify_os() {
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [[ "$ID" == "ubuntu" ]]; then
      OS="Ubuntu"
    elif [[ "$ID" == "centos" || "$ID_LIKE" == *"rhel"* ]]; then
      OS="CentOS"
    else
      OS="Unknown"
    fi
  else
    echo "Unable to determine the operating system."
    exit 1
  fi
}

##############################
# 2. AT Service Removal      #
##############################
remove_at() {
  if command -v at >/dev/null 2>&1; then
    echo "[*] AT service detected. Listing scheduled jobs:"
    atq
    read -p "Remove all AT jobs and uninstall AT? (y/n): " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
      atq | awk '{print $1}' | while read -r job; do
        atrm "$job"
        echo "Removed job $job"
      done
      if [[ "$OS" == "Ubuntu" ]]; then
        sudo apt-get remove --purge -y at
      elif [[ "$OS" == "CentOS" ]]; then
        sudo yum remove -y at
      fi
      echo "[*] AT service removed."
    else
      echo "[*] Skipping AT removal."
    fi
  else
    echo "[*] AT service not found."
  fi
}

##############################
# 3. Cron Service Removal    #
##############################
remove_cron() {
  if command -v crontab >/dev/null 2>&1; then
    echo "[*] Cron detected. Listing current user's cron jobs:"
    crontab -l 2>/dev/null
    read -p "Clear current user's cron jobs? (y/n): " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
      crontab -r
      echo "[*] User cron jobs cleared."
    fi
    read -p "Uninstall cron service? (y/n): " ans2
    if [[ "$ans2" =~ ^[Yy]$ ]]; then
      if [[ "$OS" == "Ubuntu" ]]; then
        sudo apt-get remove --purge -y cron
      elif [[ "$OS" == "CentOS" ]]; then
        sudo yum remove -y cronie
      fi
      echo "[*] Cron service removed."
    else
      echo "[*] Skipping cron service removal."
    fi
  else
    echo "[*] Cron service not found."
  fi
}

##############################
# 4. Git Removal & Cleanup   #
##############################
remove_git() {
  if command -v git >/dev/null 2>&1; then
    echo "[*] Git is installed."
    read -p "Remove Git and related persistence (pre-commit hooks, .git directories)? (y/n): " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
      # Remove malicious pre-commit hooks
      find / -name "pre-commit" -exec grep -l 'setsid /bin/bash' {} \; 2>/dev/null | while read -r hook; do
        rm -f "$hook"
        echo "Removed pre-commit hook: $hook"
      done
      # Remove malicious pager configurations (prompt for a directory)
      read -p "Specify directory to search for malicious pager config (or leave blank to skip): " dir
      if [ -n "$dir" ]; then
        grep -r 'pager = nohup setsid /bin/bash' "$dir" 2>/dev/null | while read -r line; do
          file=$(echo "$line" | cut -d: -f1)
          sed -i '/pager = nohup setsid \/bin\/bash/d' "$file"
          echo "Removed pager config from: $file"
        done
      fi
      # Remove all .git directories
      find / -type d -name ".git" 2>/dev/null | while read -r gitdir; do
        rm -rf "$gitdir"
        echo "Removed .git directory: $gitdir"
      done
      # Uninstall Git
      if [[ "$OS" == "Ubuntu" ]]; then
        sudo apt-get remove --purge -y git && sudo apt-get autoremove -y
      elif [[ "$OS" == "CentOS" ]]; then
        if command -v yum >/dev/null 2>&1; then
          sudo yum remove -y git
        else
          sudo dnf remove -y git
        fi
      fi
      echo "[*] Git removed."
    else
      echo "[*] Skipping Git removal."
    fi
  else
    echo "[*] Git not installed."
  fi
}

##############################
# 5. XDG Persistence         #
##############################
handle_xdg() {
  echo "[*] Scanning XDG autostart directories for suspicious .desktop files..."
  suspicious=0
  for file in $(find /etc/xdg/autostart ~/.config/autostart -type f -name "*.desktop" 2>/dev/null); do
    echo "Found: $file"
    if grep -E "(sh -i|nc -e|bash -c 'sh -i|tcp/[0-9]+)" "$file" &>/dev/null; then
      echo "[!] Suspicious content in $file"
      suspicious=1
    fi
  done
  if [ $suspicious -eq 1 ]; then
    read -p "Remove all XDG-related directories and unset XDG variables? (y/n): " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
      rm -rf "${XDG_CONFIG_HOME:-$HOME/.config}" "${XDG_DATA_HOME:-$HOME/.local/share}" "${XDG_CACHE_HOME:-$HOME/.cache}"
      unset XDG_CONFIG_HOME XDG_DATA_HOME XDG_CACHE_HOME XDG_CONFIG_DIRS XDG_DATA_DIRS XDG_RUNTIME_DIR
      sudo rm -rf /etc/xdg /usr/share/xdg
      echo "[*] XDG persistence removed."
    else
      echo "[*] XDG persistence not removed."
    fi
  else
    echo "[*] No suspicious XDG entries found."
  fi
}

##############################
# 6. Web Shell Detection     #
##############################
detect_web_shells() {
  local target_dir="${1:-/var/www/}"
  echo "[*] Scanning $target_dir for suspicious web shell files..."
  find "$target_dir" -type f \( -name "*.php" -o -name "*.py" -o -name "*.cgi" -o -name "*.pl" \) 2>/dev/null | while read -r file; do
    if grep -qE "(eval\(.*base64_decode|system\(.*\)|exec\(.*\)|shell_exec\(.*\)|passthru\(.*\)|popen\(.*\)|reverse shell)" "$file"; then
      echo "[!] Suspicious file: $file"
      echo "Details: $(stat -c '%a %U:%G %y' "$file")"
      read -p "Remove this file? (y/n): " ans
      if [[ "$ans" =~ ^[Yy]$ ]]; then
        rm -f "$file"
        echo "Removed $file"
      fi
    fi
  done
}

##############################
# 7. Udev Persistence        #
##############################
run_udev() {
  echo "[*] Running Udev Persistence Detection..."
  total=0
  for bin in "/bin/sedexp" "/usr/bin/atest" "/usr/bin/crontest"; do
    if [ -f "$bin" ]; then
      echo "[!] Suspicious binary found: $bin"
      total=$((total+1))
    fi
  done
  for rule in /etc/udev/rules.d/*; do
    if [ -f "$rule" ] && grep -q "RUN+=" "$rule"; then
      echo "[!] Suspicious udev rule: $rule"
      total=$((total+1))
    fi
  done
  for svc in "/etc/systemd/system/systemdtest.service" "/usr/lib/systemd/system/systemdtest.service"; do
    if [ -f "$svc" ]; then
      echo "[!] Suspicious systemd service: $svc"
      total=$((total+1))
    fi
  done
  for user in $(cut -f1 -d: /etc/passwd); do
    if crontab -u "$user" -l 2>/dev/null | grep -q -E "atest|crontest|bash -i|/dev/tcp/"; then
      echo "[!] Suspicious cron job for user: $user"
      total=$((total+1))
    fi
  done
  echo "[*] Udev detection complete. Total suspicious indicators: $total"
}

##############################
# 8. Authorized Keys         #
##############################
list_authorized_keys() {
  echo "[*] Listing authorized SSH keys for all users:"
  for user in $(cut -f1 -d: /etc/passwd); do
    user_home=$(eval echo "~$user")
    if [ -f "$user_home/.ssh/authorized_keys" ]; then
      echo "User: $user"
      cat "$user_home/.ssh/authorized_keys"
      echo "----------------------"
    fi
  done
}
remove_authorized_keys() {
  list_authorized_keys
  read -p "Remove all authorized SSH keys? (y/n): " ans
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    for user in $(cut -f1 -d: /etc/passwd); do
      user_home=$(eval echo "~$user")
      if [ -f "$user_home/.ssh/authorized_keys" ]; then
        rm -f "$user_home/.ssh/authorized_keys"
        echo "Removed authorized_keys for $user"
      fi
    done
  fi
}

##############################
# 9. /etc/passwd Backdoor   #
##############################
detect_passwd_backdoor() {
  echo "[*] Scanning /etc/passwd for suspicious backdoor entries..."
  suspicious=()
  while IFS=: read -r username _ uid gid _ _ shell; do
    if [[ "$uid" -eq 0 && "$gid" -eq 0 && "$shell" == "/bin/bash" && "$username" != "root" ]]; then
      suspicious+=("$username")
    fi
  done < /etc/passwd
  if [ ${#suspicious[@]} -gt 0 ]; then
    echo "Suspicious backdoor users detected:"
    printf "%s\n" "${suspicious[@]}"
    read -p "Attempt to fix these entries? (y/n): " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
      for user in "${suspicious[@]}"; do
        next_uid=$(awk -F: 'BEGIN {max=999} ($3>=1000 && $3>max) {max=$3} END {print max+1}' /etc/passwd)
        sudo cp /etc/passwd /etc/passwd.bak
        sudo sed -i "s/^\($user:[^:]*:\)0:/\1$next_uid:/" /etc/passwd
        echo "Fixed UID for $user to $next_uid"
      done
    fi
  else
    echo "[*] No suspicious entries found in /etc/passwd."
  fi
}

##############################
# 10. Reinstall PAM          #
##############################
reinstall_pam() {
  read -p "Reinstall PAM to remove potential backdoors? (y/n): " ans
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    if [[ "$OS" == "Ubuntu" ]]; then
      sudo apt update && sudo apt install --reinstall -y libpam-modules libpam-modules-bin libpam-runtime
    elif [[ "$OS" == "CentOS" ]]; then
      sudo yum reinstall -y pam
    fi
    echo "[*] PAM reinstalled."
  else
    echo "[*] Skipping PAM reinstallation."
  fi
}

##############################
# 11. Bind Shell Removal     #
##############################
remove_bind_shells() {
  echo "[*] Checking for bind shell binaries..."
  for bin in /tmp/bd86 /tmp/bd64; do
    if [ -f "$bin" ]; then
      pkill -f "$bin"
      rm -f "$bin"
      echo "Removed bind shell binary: $bin"
    fi
  done
  for pattern in "nc\.traditional.*-l.*-p" "nc.*-l.*-p" "node -e" "socat TCP-LISTEN" "socket -svp"; do
    if pgrep -f "$pattern" >/dev/null; then
      pkill -f "$pattern"
      echo "Killed processes matching: $pattern"
    fi
  done
}

##############################
# 12. Reverse Shell Killing  #
##############################
kill_reverse_shells() {
  echo "[*] Killing reverse shell processes..."
  for pattern in "bash -i >& /dev/tcp" "nc -e /bin/sh" "python -c" "python3 -c" "ruby -rsocket -e"; do
    pgrep -f "$pattern" | while read -r pid; do
      kill -9 "$pid" && echo "Killed process PID $pid matching $pattern"
    done
  done
}

##############################
# 13. Shell Profile Cleanup  #
##############################
remove_shell_profiles() {
  echo "[*] Cleaning shell profiles..."
  for file in /etc/profile /etc/bash.bashrc ~/.bashrc ~/.profile ~/.bash_profile ~/.zshrc; do
    if [ -f "$file" ]; then
      cp "$file" "${file}.backup"
      sed -i '/nohup bash -i > \/dev\/tcp/d;/setsid nohup bash -c/d;/bash -i >& \/dev\/tcp/d;/sh -i >& \/dev\/udp/d' "$file"
      echo "Cleaned $file (backup at ${file}.backup)"
    fi
  done
}

##############################
# 14. /etc/rc.local Cleanup   #
##############################
remove_rc_local() {
  if [ -f /etc/rc.local ]; then
    cp /etc/rc.local /etc/rc.local.backup
    for pattern in "/bin/bash -c 'sh -i >& /dev/tcp/" "setsid nohup bash -c 'sh -i >& /dev/tcp/" "nohup setsid bash -c 'sh -i >& /dev/tcp/" "bash -i >& /dev/tcp/" "bash -c 'sh -i >& /dev/tcp/" "bash -i > /dev/tcp/" "sh -i >& /dev/udp/"; do
      sed -i "\|$pattern|d" /etc/rc.local
    done
    echo "Cleaned /etc/rc.local (backup at /etc/rc.local.backup)"
  else
    echo "[*] /etc/rc.local not found."
  fi
}

##############################
# 15. Remove Capabilities    #
##############################
remove_capabilities() {
  echo "[*] Removing capabilities from binaries..."
  for bin in perl ruby php python python3 node; do
    if command -v "$bin" >/dev/null; then
      path=$(command -v "$bin")
      if [ -f "$path" ]; then
        if getcap "$path" &>/dev/null; then
          sudo setcap -r "$path" && echo "Removed capabilities from $path"
        else
          echo "No capabilities set on $path"
        fi
      fi
    fi
  done
}

##############################
# 16. Generator Persistence  #
##############################
scan_generator_persistence() {
  echo "[*] Scanning generator directories for malicious patterns..."
  for dir in /etc/systemd/system-generators /usr/lib/systemd/system-generators /run/systemd/system-generators /run/systemd/generator; do
    if [ -d "$dir" ]; then
      find "$dir" -type f 2>/dev/null | while read -r file; do
        for pattern in "/bin/bash -c 'sh -i >& /dev/tcp/" "setsid nohup bash -c 'sh -i >& /dev/tcp/" "nohup setsid bash -c 'sh -i >& /dev/tcp/" "bash -i >& /dev/tcp/" "bash -c 'sh -i >& /dev/tcp/" "bash -i > /dev/tcp/" "sh -i >& /dev/udp/"; do
          if grep -q "$pattern" "$file"; then
            echo "[!] Found pattern in $file: $pattern"
            read -p "Remove this line from $file? (y/n): " ans
            if [[ "$ans" =~ ^[Yy]$ ]]; then
              sed -i "\|$pattern|d" "$file"
              echo "Removed pattern from $file"
            fi
          fi
        done
      done
    fi
  done
}

##############################
# 17. Package Manager Pers.  #
##############################
check_pkg_persistence() {
  echo "[*] Checking package manager persistence..."
  if [[ "$OS" == "Ubuntu" ]]; then
    for file in /etc/apt/apt.conf.d/*; do
      if [ -f "$file" ]; then
        grep -q "/bin/bash -c 'sh -i" "$file" && echo "[!] Suspicious pattern in APT file: $file"
      fi
    done
  elif [[ "$OS" == "CentOS" ]]; then
    for file in /etc/yum/pluginconf.d/*; do
      if [ -f "$file" ]; then
        grep -q "/bin/bash -c 'sh -i" "$file" && echo "[!] Suspicious pattern in YUM plugin file: $file"
      fi
    done
  fi
}

##############################
# 18. MOTD Removal           #
##############################
remove_motd() {
  if [ -d /etc/update-motd.d ]; then
    ls -l /etc/update-motd.d/
    read -p "Remove all MOTD scripts? (y/n): " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
      sudo rm -rf /etc/update-motd.d/*
      echo "[*] MOTD scripts removed."
    else
      echo "[*] Skipping MOTD removal."
    fi
  else
    echo "[*] MOTD directory not found."
  fi
}

##############################
# 19. Malicious Package Scan #
##############################
detect_malicious_packages() {
  echo "[*] Checking installed package files for malicious patterns..."
  if command -v dpkg-query >/dev/null 2>&1; then
    for pkg in $(dpkg-query -W -f='${Package}\n'); do
      pkg_file=$(dpkg-query -L "$pkg" | grep -E '\.sh$' | head -n 1)
      if [ -n "$pkg_file" ] && [ -f "$pkg_file" ]; then
        for pattern in "/bin/bash -c 'sh -i" "setsid nohup bash -c 'sh -i" "bash -i >& /dev/tcp"; do
          if grep -q "$pattern" "$pkg_file"; then
            echo "[!] Suspicious pattern in package $pkg: $pkg_file"
            read -p "Remove malicious file $pkg_file? (y/n): " ans
            if [[ "$ans" =~ ^[Yy]$ ]]; then
              sudo rm -f "$pkg_file"
              echo "Removed $pkg_file"
            fi
          fi
        done
      fi
    done
  elif command -v rpm >/dev/null 2>&1; then
    for pkg in $(rpm -qa); do
      rpm -ql "$pkg" | while read -r pkg_file; do
        if [ -f "$pkg_file" ]; then
          for pattern in "/bin/bash -c 'sh -i" "setsid nohup bash -c 'sh -i" "bash -i >& /dev/tcp"; do
            if grep -q "$pattern" "$pkg_file"; then
              echo "[!] Suspicious pattern in package $pkg: $pkg_file"
              read -p "Remove malicious file $pkg_file? (y/n): " ans
              if [[ "$ans" =~ ^[Yy]$ ]]; then
                sudo rm -f "$pkg_file"
                echo "Removed $pkg_file"
              fi
            fi
          done
        fi
      done
    done
  else
    echo "[*] No package manager detected."
  fi
}

##############################
# 20. LD_PRELOAD Check       #
##############################
check_ld_preload() {
  echo "[*] Checking for LD_PRELOAD persistence..."
  for file in /etc/environment /etc/profile ~/.bashrc ~/.zshrc; do
    if [ -f "$file" ]; then
      if grep -q 'LD_PRELOAD' "$file"; then
        echo "[!] LD_PRELOAD found in $file:"
        grep 'LD_PRELOAD' "$file"
      fi
    fi
  done
  echo "[*] Checking running processes for LD_PRELOAD..."
  for pid in $(ps -e -o pid=); do
    if grep -q 'LD_PRELOAD' /proc/$pid/environ 2>/dev/null; then
      echo "[!] LD_PRELOAD set in process $pid:"
      tr '\0' '\n' < /proc/$pid/environ | grep 'LD_PRELOAD'
    fi
  done
}

##############################
# 21. Scan init.d            #
##############################
scan_initd() {
  initd_dir="/etc/init.d"
  if [ -d "$initd_dir" ]; then
    for file in "$initd_dir"/*; do
      if [ -f "$file" ]; then
        for pattern in "bash -i >& /dev/tcp" "nc -e /bin/bash"; do
          if grep -iq "$pattern" "$file"; then
            echo "[!] Suspicious string in $file: $pattern"
            read -p "Remove this line from $file? (y/n): " ans
            if [[ "$ans" =~ ^[Yy]$ ]]; then
              sed -i "\|$pattern|d" "$file"
              echo "Removed suspicious line from $file"
            fi
          fi
        done
      fi
    done
  else
    echo "[*] /etc/init.d directory not found."
  fi
}

##############################
# 22. Run All Detections     #
##############################
run_all_detections() {
  echo "=== Running All Detections ==="
  remove_at
  remove_cron
  remove_git
  handle_xdg
  detect_web_shells
  run_udev
  list_authorized_keys
  detect_passwd_backdoor
  reinstall_pam
  remove_bind_shells
  kill_reverse_shells
  remove_shell_profiles
  remove_rc_local
  remove_capabilities
  scan_generator_persistence
  check_pkg_persistence
  remove_motd
  detect_malicious_packages
  check_ld_preload
  scan_initd
  echo "=== All Detections Completed ==="
}

##############################
# Main Interactive Menu      #
##############################
main_menu() {
  echo "=============================="
  echo " Backdoor Detection & Removal"
  echo " OS Detected: $OS"
  echo "=============================="
  echo "1) Remove AT service"
  echo "2) Remove Cron service"
  echo "3) Remove Git & persistence artifacts"
  echo "4) Handle XDG persistence"
  echo "5) Detect Web Shells (default: /var/www)"
  echo "6) Run Udev Persistence Detection"
  echo "7) List/Remove Authorized SSH Keys"
  echo "8) Detect /etc/passwd backdoor entries"
  echo "9) Reinstall PAM"
  echo "10) Remove Bind Shell processes"
  echo "11) Kill Reverse Shell processes"
  echo "12) Clean Shell Profile entries"
  echo "13) Clean /etc/rc.local"
  echo "14) Remove Capabilities from binaries"
  echo "15) Scan Generator Persistence"
  echo "16) Check Package Manager Persistence"
  echo "17) Remove MOTD scripts"
  echo "18) Detect Malicious Package Files"
  echo "19) Check LD_PRELOAD persistence"
  echo "20) Scan init.d for malicious strings"
  echo "21) Run ALL detections"
  echo "0) Exit"
  echo "=============================="
  read -p "Enter your choice: " choice
}

##############################
# Main Execution Loop        #
##############################
identify_os
while true; do
  main_menu
  case $choice in
    1) remove_at ;;
    2) remove_cron ;;
    3) remove_git ;;
    4) handle_xdg ;;
    5) 
       read -p "Enter directory to scan for web shells (default: /var/www): " wd
       detect_web_shells "${wd:-/var/www}"
       ;;
    6) run_udev ;;
    7) remove_authorized_keys ;;
    8) detect_passwd_backdoor ;;
    9) reinstall_pam ;;
    10) remove_bind_shells ;;
    11) kill_reverse_shells ;;
    12) remove_shell_profiles ;;
    13) remove_rc_local ;;
    14) remove_capabilities ;;
    15) scan_generator_persistence ;;
    16) check_pkg_persistence ;;
    17) remove_motd ;;
    18) detect_malicious_packages ;;
    19) check_ld_preload ;;
    20) scan_initd ;;
    21) run_all_detections ;;
    0) echo "Exiting."; exit 0 ;;
    *) echo "Invalid option. Please choose again." ;;
  esac
  echo "Press Enter to continue..."
  read
done
