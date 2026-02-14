#!/bin/bash

RESET='\033[0m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'

if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}[!] This script requires root privileges${RESET}"
    exit 1
fi

if [ -z "$1" ]; then
    if [ -f "/var/www/html/wordpress/wp-config.php" ]; then
        WP_ROOT="/var/www/html/wordpress"
    elif [ -f "/var/www/wordpress/wp-config.php" ]; then
        WP_ROOT="/var/www/wordpress"
    elif [ -f "/var/www/html/wp-config.php" ]; then
        WP_ROOT="/var/www/html"
    elif [ -f "./wp-config.php" ]; then
        WP_ROOT="."
    else
        echo -e "${RED}[!] Could not auto-detect WordPress. Please provide path: $0 /path/to/wordpress${RESET}"
        exit 1
    fi
else
    WP_ROOT="$1"
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/root/wp-backup-${TIMESTAMP}"
QUARANTINE_DIR="/root/wp-quarantine-${TIMESTAMP}"

echo -e "${CYAN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════╗
║     WordPress Hardening & Remediation Tool            ║
║          CCDC Blue Team Defense Suite                 ║
║           🛡️  Lock It Down Mode 🛡️                    ║
╚═══════════════════════════════════════════════════════╝
EOF
echo -e "${RESET}\n"

if [ ! -f "$WP_ROOT/wp-config.php" ]; then
    echo -e "${RED}[!] wp-config.php not found at: $WP_ROOT${RESET}"
    exit 1
fi

echo -e "${GREEN}[*] Starting hardening at: $(date)${RESET}"
echo -e "${GREEN}[*] WordPress root: $WP_ROOT${RESET}"
echo -e "${BLUE}[*] Backup directory: $BACKUP_DIR${RESET}"
echo -e "${MAGENTA}[*] Quarantine directory: $QUARANTINE_DIR${RESET}\n"

mkdir -p "$BACKUP_DIR" "$QUARANTINE_DIR"

quarantine_file() {
    local file="$1"
    local reason="$2"
    if [ -f "$file" ]; then
        echo -e "${YELLOW}  [QUARANTINE] $file - Reason: $reason${RESET}"
        cp "$file" "$QUARANTINE_DIR/" 2>/dev/null
        echo "$file - $reason" >> "$QUARANTINE_DIR/quarantine_log.txt"
    fi
}

echo -e "${RED}╔═══════════════════════════════════════════════════════╗${RESET}"
echo -e "${RED}║              PHASE 1: BACKUP & DETECTION              ║${RESET}"
echo -e "${RED}╚═══════════════════════════════════════════════════════╝${RESET}\n"

echo -e "${YELLOW}[1] Creating Full Backup${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
cp -r "$WP_ROOT" "$BACKUP_DIR/wordpress-backup" 2>/dev/null
echo -e "${GREEN}[✓] Backup created at: $BACKUP_DIR${RESET}"

echo -e "\n${YELLOW}[2] Scanning for Backdoors${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

UPLOADS_PHP=$(find "$WP_ROOT/wp-content/uploads" -type f \( -name "*.php" -o -name "*.phtml" -o -name "*.php*" \) 2>/dev/null)
if [ -n "$UPLOADS_PHP" ]; then
    echo -e "${RED}[!] CRITICAL: PHP files in uploads directory${RESET}"
    echo "$UPLOADS_PHP" | while read -r bad_file; do
        quarantine_file "$bad_file" "PHP in uploads directory"
        rm -f "$bad_file"
        echo -e "${GREEN}  [REMOVED] $bad_file${RESET}"
    done
fi

SUSP_EXT=$(find "$WP_ROOT/wp-content" -type f \( -name "*.bak" -o -name "*.old" -o -name "*.tmp" -o -name "*.suspected" \) 2>/dev/null)
if [ -n "$SUSP_EXT" ]; then
    echo -e "${RED}[!] Suspicious file extensions found${RESET}"
    echo "$SUSP_EXT" | while read -r susp_file; do
        if head -1 "$susp_file" 2>/dev/null | grep -q "<?php"; then
            quarantine_file "$susp_file" "Suspicious extension with PHP code"
            rm -f "$susp_file"
            echo -e "${GREEN}  [REMOVED] $susp_file${RESET}"
        fi
    done
fi

HIDDEN_FILES=$(find "$WP_ROOT/wp-content" -name ".*" -type f ! -name ".htaccess" 2>/dev/null)
if [ -n "$HIDDEN_FILES" ]; then
    echo -e "${RED}[!] Hidden files found${RESET}"
    echo "$HIDDEN_FILES" | while read -r hidden; do
        quarantine_file "$hidden" "Hidden file"
        rm -f "$hidden"
        echo -e "${GREEN}  [REMOVED] $hidden${RESET}"
    done
fi

echo -e "\n${RED}╔═══════════════════════════════════════════════════════╗${RESET}"
echo -e "${RED}║           PHASE 2: CORE FILE REMEDIATION              ║${RESET}"
echo -e "${RED}╚═══════════════════════════════════════════════════════╝${RESET}\n"

echo -e "${YELLOW}[3] Cleaning wp-config.php${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

cp "$WP_ROOT/wp-config.php" "$BACKUP_DIR/wp-config.php.bak"

if grep -qE "(eval|base64_decode|system|exec|shell_exec|assert)" "$WP_ROOT/wp-config.php"; then
    echo -e "${RED}[!] Malicious code detected in wp-config.php${RESET}"
    
    grep -vE "^\s*(eval|base64_decode|system|exec|shell_exec|@error_reporting)" "$WP_ROOT/wp-config.php" > "$WP_ROOT/wp-config.php.clean"
    
    sed -i '/^<?php$/,/^\/\*\*/!{/^\s*\$[a-zA-Z_]/d}' "$WP_ROOT/wp-config.php.clean"
    
    mv "$WP_ROOT/wp-config.php.clean" "$WP_ROOT/wp-config.php"
    echo -e "${GREEN}[✓] wp-config.php cleaned${RESET}"
else
    echo -e "${GREEN}[✓] wp-config.php is clean${RESET}"
fi

if ! grep -q "DISALLOW_FILE_EDIT" "$WP_ROOT/wp-config.php"; then
    sed -i "/<?php/a \\\n\ndefine('DISALLOW_FILE_EDIT', true);\ndefine('DISALLOW_FILE_MODS', true);\ndefine('FORCE_SSL_ADMIN', true);" "$WP_ROOT/wp-config.php"
    echo -e "${GREEN}[✓] Added security constants to wp-config.php${RESET}"
fi

echo -e "\n${YELLOW}[4] Securing .htaccess${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

cp "$WP_ROOT/.htaccess" "$BACKUP_DIR/.htaccess.bak" 2>/dev/null

if grep -qE "(auto_prepend_file|auto_append_file)" "$WP_ROOT/.htaccess" 2>/dev/null; then
    echo -e "${RED}[!] Removing malicious .htaccess directives${RESET}"
    grep -vE "(auto_prepend_file|auto_append_file)" "$WP_ROOT/.htaccess" > "$WP_ROOT/.htaccess.clean"
    mv "$WP_ROOT/.htaccess.clean" "$WP_ROOT/.htaccess"
fi

cat > "$WP_ROOT/.htaccess" << 'HTACCESS'
Options -Indexes

<files wp-config.php>
    order allow,deny
    deny from all
</files>

<files .htaccess>
    order allow,deny
    deny from all
</files>

<Directory wp-content/uploads/>
    <Files *.php>
        deny from all
    </Files>
</Directory>

<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{QUERY_STRING} (\<|%3C).*script.*(\>|%3E) [NC,OR]
    RewriteCond %{QUERY_STRING} GLOBALS(=|\[|\%[0-9A-Z]{0,2}) [OR]
    RewriteCond %{QUERY_STRING} _REQUEST(=|\[|\%[0-9A-Z]{0,2})
    RewriteRule ^(.*)$ - [F,L]
</IfModule>

<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /wordpress/
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /wordpress/index.php [L]
</IfModule>
HTACCESS

echo -e "${GREEN}[✓] .htaccess hardened${RESET}"

echo -e "\n${YELLOW}[5] Checking Plugins${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

MALICIOUS_PLUGINS=("site-optimization" "shell" "backdoor" "c99" "r57" "wso")
for plugin in "${MALICIOUS_PLUGINS[@]}"; do
    if [ -d "$WP_ROOT/wp-content/plugins/$plugin" ]; then
        echo -e "${RED}[!] Removing malicious plugin: $plugin${RESET}"
        cp -r "$WP_ROOT/wp-content/plugins/$plugin" "$QUARANTINE_DIR/"
        rm -rf "$WP_ROOT/wp-content/plugins/$plugin"
        echo -e "${GREEN}  [REMOVED] $plugin${RESET}"
    fi
done

find "$WP_ROOT/wp-content/plugins" -name "*.php" -type f 2>/dev/null | while read -r plugin_file; do
    if grep -qE "eval\(.*base64_decode|system\(\$_POST|exec\(\$_REQUEST" "$plugin_file" 2>/dev/null; then
        echo -e "${RED}[!] Suspicious code in: $plugin_file${RESET}"
        quarantine_file "$plugin_file" "Contains eval/base64/system with user input"
        sed -i 's/.*eval.*base64_decode.*/\/\/ REMOVED BY HARDENING SCRIPT/' "$plugin_file"
        sed -i 's/.*system.*\$_POST.*/\/\/ REMOVED BY HARDENING SCRIPT/' "$plugin_file"
        echo -e "${YELLOW}  [SANITIZED] Commented out malicious code${RESET}"
    fi
done

echo -e "\n${YELLOW}[6] Checking Themes${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

find "$WP_ROOT/wp-content/themes" -name "functions.php" -type f 2>/dev/null | while read -r func_file; do
    if grep -qE "eval\(.*base64_decode|if\(isset\(\$_GET\['|if\(isset\(\$_REQUEST\['" "$func_file" 2>/dev/null; then
        echo -e "${RED}[!] Backdoor detected in: $func_file${RESET}"
        quarantine_file "$func_file" "Theme backdoor"
        
        sed -i '/add_action.*wp_head.*function/,/^}/d' "$func_file"
        sed -i '/eval.*base64_decode/d' "$func_file"
        sed -i '/if.*isset.*\$_GET.*theme_debug/,/^}/d' "$func_file"
        
        echo -e "${GREEN}  [CLEANED] Removed backdoor code${RESET}"
    fi
done

echo -e "\n${YELLOW}[7] Checking mu-plugins${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -d "$WP_ROOT/wp-content/mu-plugins" ]; then
    find "$WP_ROOT/wp-content/mu-plugins" -name "*.php" -type f 2>/dev/null | while read -r mu_file; do
        if grep -qE "(eval|base64_decode|system|exec)" "$mu_file" 2>/dev/null; then
            echo -e "${RED}[!] Removing suspicious mu-plugin: $(basename $mu_file)${RESET}"
            quarantine_file "$mu_file" "Malicious mu-plugin"
            rm -f "$mu_file"
            echo -e "${GREEN}  [REMOVED] $mu_file${RESET}"
        fi
    done
fi

echo -e "\n${RED}╔═══════════════════════════════════════════════════════╗${RESET}"
echo -e "${RED}║              PHASE 3: USER & DATABASE                 ║${RESET}"
echo -e "${RED}╚═══════════════════════════════════════════════════════╝${RESET}\n"

echo -e "${YELLOW}[8] Auditing WordPress Users${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

DB_NAME=$(grep "DB_NAME" "$WP_ROOT/wp-config.php" | cut -d "'" -f 4)
DB_USER=$(grep "DB_USER" "$WP_ROOT/wp-config.php" | cut -d "'" -f 4)
DB_PASS=$(grep "DB_PASSWORD" "$WP_ROOT/wp-config.php" | cut -d "'" -f 4)

if [ -n "$DB_NAME" ]; then
    echo -e "${BLUE}[i] Checking database: $DB_NAME${RESET}"
    
    echo -e "${BLUE}[i] Current admin accounts:${RESET}"
    if [ -n "$DB_PASS" ]; then
        mysql -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" -e "SELECT user_login, user_email, user_registered FROM wp_users WHERE ID IN (SELECT user_id FROM wp_usermeta WHERE meta_key = 'wp_capabilities' AND meta_value LIKE '%administrator%');" 2>/dev/null
        
        echo -e "\n${YELLOW}[!] Removing suspicious admin accounts...${RESET}"
        SUSPICIOUS_ADMINS=("sysadmin" "support" "backup" "test" "admin123" "administrator" "wpadmin")
        for susp_user in "${SUSPICIOUS_ADMINS[@]}"; do
            RESULT=$(mysql -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" -se "SELECT user_login FROM wp_users WHERE user_login = '$susp_user';" 2>/dev/null)
            if [ -n "$RESULT" ]; then
                mysql -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" -e "DELETE FROM wp_users WHERE user_login = '$susp_user';" 2>/dev/null
                mysql -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" -e "DELETE FROM wp_usermeta WHERE user_id NOT IN (SELECT ID FROM wp_users);" 2>/dev/null
                echo -e "${GREEN}  [REMOVED] User: $susp_user${RESET}"
            fi
        done
        
        echo -e "\n${YELLOW}[!] Cleaning database options...${RESET}"
        mysql -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" -e "DELETE FROM wp_options WHERE option_name LIKE '%health_check%' AND option_value LIKE '%<?php%';" 2>/dev/null
        mysql -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" -e "DELETE FROM wp_options WHERE option_value LIKE '%eval%base64%';" 2>/dev/null
        echo -e "${GREEN}[✓] Database cleaned${RESET}"
        
    fi
fi

echo -e "\n${RED}╔═══════════════════════════════════════════════════════╗${RESET}"
echo -e "${RED}║           PHASE 4: FILE PERMISSIONS & OWNERSHIP       ║${RESET}"
echo -e "${RED}╚═══════════════════════════════════════════════════════╝${RESET}\n"

echo -e "${YELLOW}[9] Setting Secure File Permissions${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

chown -R www-data:www-data "$WP_ROOT"
echo -e "${GREEN}[✓] Set ownership to www-data:www-data${RESET}"

find "$WP_ROOT" -type d -exec chmod 755 {} \;
echo -e "${GREEN}[✓] Directories set to 755${RESET}"

find "$WP_ROOT" -type f -exec chmod 644 {} \;
echo -e "${GREEN}[✓] Files set to 644${RESET}"

chmod 600 "$WP_ROOT/wp-config.php"
echo -e "${GREEN}[✓] wp-config.php set to 600${RESET}"

chmod -R 755 "$WP_ROOT/wp-content/uploads"
find "$WP_ROOT/wp-content/uploads" -type f -exec chmod 644 {} \;
echo -e "${GREEN}[✓] Uploads directory secured${RESET}"

echo -e "\n${RED}╔═══════════════════════════════════════════════════════╗${RESET}"
echo -e "${RED}║              PHASE 5: SYSTEM HARDENING                ║${RESET}"
echo -e "${RED}╚═══════════════════════════════════════════════════════╝${RESET}\n"

echo -e "${YELLOW}[10] Removing Malicious Cron Jobs${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

crontab -l 2>/dev/null | grep -v "wordpress\|wp-content\|/var/www" | crontab - 2>/dev/null
echo -e "${GREEN}[✓] Cleaned user crontab${RESET}"

crontab -u www-data -l 2>/dev/null | grep -v "curl\|wget\|php" | crontab -u www-data - 2>/dev/null
echo -e "${GREEN}[✓] Cleaned www-data crontab${RESET}"

find /tmp -name "*wp*" -o -name "*wordpress*" 2>/dev/null | while read -r tmp_file; do
    rm -f "$tmp_file"
    echo -e "${GREEN}  [REMOVED] $tmp_file${RESET}"
done

echo -e "\n${YELLOW}[11] PHP Security Settings${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

cat > "$WP_ROOT/.user.ini" << 'PHPINI'
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source
allow_url_fopen = Off
allow_url_include = Off
display_errors = Off
log_errors = On
PHPINI

echo -e "${GREEN}[✓] PHP security settings configured${RESET}"

echo -e "\n${YELLOW}[12] Installing Security Plugins${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if command -v wp &> /dev/null; then
    cd "$WP_ROOT"
    
    sudo -u www-data wp plugin install wordfence --activate 2>/dev/null && \
        echo -e "${GREEN}[✓] Wordfence Security installed${RESET}"
    
    sudo -u www-data wp plugin install better-wp-security --activate 2>/dev/null && \
        echo -e "${GREEN}[✓] iThemes Security installed${RESET}"
else
    echo -e "${YELLOW}[!] WP-CLI not available - install security plugins manually${RESET}"
fi

echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}║              HARDENING COMPLETE                       ║${RESET}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════╝${RESET}\n"

echo -e "${CYAN}[*] Summary:${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}Backup Location:${RESET}     $BACKUP_DIR"
echo -e "${BLUE}Quarantine Location:${RESET} $QUARANTINE_DIR"
echo -e "${BLUE}Quarantined Files:${RESET}   $(ls -1 $QUARANTINE_DIR 2>/dev/null | wc -l) files"

echo -e "\n${YELLOW}[!] ADDITIONAL MANUAL STEPS:${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1. Change all WordPress admin passwords"
echo "2. Update all plugins and themes to latest versions"
echo "3. Enable 2FA for all admin accounts"
echo "4. Review quarantined files: $QUARANTINE_DIR"
echo "5. Check Apache/Nginx access logs for suspicious activity"
echo "6. Configure Wordfence firewall rules"
echo "7. Set up automated backups"
echo "8. Enable SSL/TLS (install Let's Encrypt)"
echo "9. Disable XML-RPC if not needed: add to .htaccess"
echo "10. Monitor: tail -f /var/log/apache2/access.log"

echo -e "\n${GREEN}[✓] WordPress installation hardened!${RESET}"
echo -e "${MAGENTA}[*] Stay vigilant. Red team never sleeps. 🛡️${RESET}\n"