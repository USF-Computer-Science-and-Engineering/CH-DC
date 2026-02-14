#!/bin/sh
# ============================================================================
# generate_hashes.sh — CCDC Script Integrity Hash Generator
# ============================================================================
# Run this ONCE after downloading/cloning the scripts repo at the start of
# the competition. It recursively finds all .sh files from the current
# directory and creates a .sha256 hash file alongside each one.
#
# The individual scripts (user_admin.sh, ssh_lockdown.sh, user_watchdog.sh) will
# check these hash files at startup to detect Red Team tampering.
#
# Usage:
#   cd /path/to/scripts-repo
#   sudo sh generate_hashes.sh
#
# To regenerate after editing a script:
#   Just re-run this script from the same directory.
# ============================================================================

# ── Colors ──
if [ -t 1 ]; then
    R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; B='\033[1m'; N='\033[0m'
else
    R=''; G=''; Y=''; C=''; B=''; N=''
fi

printf "${C}${B}══════════════════════════════════════════════════════════════${N}\n"
printf "${C}${B}  CCDC Script Integrity — Hash Generator${N}\n"
printf "${C}${B}══════════════════════════════════════════════════════════════${N}\n"
echo ""

# Work from the directory where this script lives
SCRIPT_DIR=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
cd "$SCRIPT_DIR" || exit 1

printf "${C}[*] Scanning for .sh files in: %s${N}\n" "$SCRIPT_DIR"
echo ""

count=0
failed=0

# Find all .sh files recursively, excluding this generator script itself
find "$SCRIPT_DIR" -type f -name "*.sh" ! -name "generate_hashes.sh" | sort | while read -r script; do
    # Compute SHA-256 hash
    if command -v sha256sum >/dev/null 2>&1; then
        hash=$(sha256sum "$script" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        hash=$(shasum -a 256 "$script" | awk '{print $1}')
    else
        printf "${R}[✗] No sha256sum or shasum found! Cannot generate hashes.${N}\n"
        exit 1
    fi

    # Save hash to <script>.sha256
    hash_file="${script}.sha256"
    echo "$hash  $(basename "$script")" > "$hash_file"

    # Show relative path for cleaner output
    rel_path=$(echo "$script" | sed "s|^${SCRIPT_DIR}/||")
    printf "${G}[✓] %s${N}\n" "$rel_path"
    printf "    → %s\n" "$hash"
done

echo ""
printf "${G}${B}[✓] Hash generation complete.${N}\n"
printf "${Y}[!] If you edit any script, re-run this to update its hash.${N}\n"
echo ""
