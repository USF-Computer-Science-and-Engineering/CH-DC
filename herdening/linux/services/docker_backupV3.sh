#!/usr/bin/env bash

if [[ $EUID -ne 0 ]]; then
   echo "[!] This script must be run as root (sudo)"
   exit 1
fi

if ! command -v docker &>/dev/null; then
    echo "[!] Docker is not installed or not in PATH"
    exit 1
fi

HOSTNAME=$(hostname || echo "unknown_host")
TIMESTAMP=$(date +%Y%m%d_%H%M)
BACKUP_ROOT="/root/Docker_Service_Backup_${HOSTNAME}_${TIMESTAMP}"

mkdir -p -m 700 "$BACKUP_ROOT"
echo "--- Starting Docker Service Backup for $HOSTNAME ---"

TARGETS=("dovecot" "postfix" "exim" "exim4" "nginx" "apache" "apache2" "httpd" "mysql" "mysqld" "mariadb" "postgresql" "postgres" "bind" "bind9" "named" "vsftpd" "proftpd" "samba" "smbd" "nmbd" "snmpd" "nfs" "openvpn" "telnetd" "caddy" "gitea" "courier" "unbound" "dnsmasq" "sshd" "php-fpm" "redis" "memcached" "mongod" "elasticsearch" "rabbitmq" "haproxy" "traefik" "envoy" "squid" "tomcat" "jenkins" "grafana" "prometheus" "influxd" "mosquitto" "lighttpd")

SERVICE_CONF_MAP_DIRS=(
    "nginx:/etc/nginx /usr/local/nginx/conf /etc/letsencrypt"
    "apache:/etc/apache2 /etc/httpd /usr/local/apache2/conf"
    "apache2:/etc/apache2 /etc/httpd /usr/local/apache2/conf"
    "httpd:/etc/httpd /etc/apache2 /usr/local/apache2/conf"
    "mysql:/etc/mysql /etc/my.cnf.d /var/lib/mysql/*.cnf"
    "mysqld:/etc/mysql /etc/my.cnf.d"
    "mariadb:/etc/mysql /etc/my.cnf.d"
    "postgresql:/etc/postgresql /var/lib/postgresql/data"
    "postgres:/etc/postgresql /var/lib/postgresql/data /var/lib/pgsql/data"
    "dovecot:/etc/dovecot"
    "postfix:/etc/postfix"
    "exim:/etc/exim /etc/exim4"
    "exim4:/etc/exim4"
    "bind:/etc/bind /etc/named /var/named"
    "bind9:/etc/bind /var/cache/bind"
    "named:/etc/named /var/named"
    "vsftpd:/etc/vsftpd /etc/vsftpd.conf"
    "proftpd:/etc/proftpd"
    "samba:/etc/samba"
    "smbd:/etc/samba"
    "snmpd:/etc/snmp"
    "openvpn:/etc/openvpn"
    "caddy:/etc/caddy /config/caddy"
    "gitea:/etc/gitea /data/gitea"
    "courier:/etc/courier"
    "unbound:/etc/unbound"
    "dnsmasq:/etc/dnsmasq.conf /etc/dnsmasq.d"
    "sshd:/etc/ssh"
    "php-fpm:/etc/php /usr/local/etc/php"
    "redis:/etc/redis /usr/local/etc/redis"
    "memcached:/etc/memcached.conf"
    "mongod:/etc/mongod.conf /etc/mongodb.conf"
    "elasticsearch:/etc/elasticsearch /usr/share/elasticsearch/config"
    "rabbitmq:/etc/rabbitmq"
    "haproxy:/etc/haproxy /usr/local/etc/haproxy"
    "traefik:/etc/traefik"
    "envoy:/etc/envoy"
    "squid:/etc/squid"
    "tomcat:/etc/tomcat /opt/tomcat/conf /usr/local/tomcat/conf"
    "jenkins:/var/jenkins_home /etc/jenkins"
    "grafana:/etc/grafana"
    "prometheus:/etc/prometheus"
    "influxd:/etc/influxdb"
    "mosquitto:/etc/mosquitto /mosquitto/config"
    "lighttpd:/etc/lighttpd"
)

SERVICE_CONF_MAP_FILES=(
    "nginx:/etc/nginx/nginx.conf /etc/nginx/conf.d /etc/nginx/sites-enabled /etc/nginx/sites-available"
    "mysql:/etc/my.cnf /etc/mysql/my.cnf"
    "mysqld:/etc/my.cnf"
    "mariadb:/etc/my.cnf /etc/mysql/my.cnf"
    "postgres:/var/lib/postgresql/data/pg_hba.conf /var/lib/postgresql/data/postgresql.conf /var/lib/pgsql/data/pg_hba.conf /var/lib/pgsql/data/postgresql.conf"
    "postgresql:/var/lib/postgresql/data/pg_hba.conf /var/lib/postgresql/data/postgresql.conf"
    "redis:/etc/redis/redis.conf /usr/local/etc/redis/redis.conf /etc/redis.conf"
    "haproxy:/etc/haproxy/haproxy.cfg /usr/local/etc/haproxy/haproxy.cfg"
    "caddy:/etc/caddy/Caddyfile /config/Caddyfile"
    "squid:/etc/squid/squid.conf"
    "vsftpd:/etc/vsftpd.conf"
    "dnsmasq:/etc/dnsmasq.conf"
    "mongod:/etc/mongod.conf"
    "memcached:/etc/memcached.conf"
)

WEB_DATA_PATHS=("/var/www" "/usr/share/nginx/html" "/srv/www" "/var/www/html" "/usr/local/apache2/htdocs" "/opt/bitnami/nginx/html")

dexec() {
    local cid="$1"
    shift
    docker exec "$cid" sh -c "$*" 2>/dev/null
}

get_conf_dirs() {
    local svc="$1"
    for entry in "${SERVICE_CONF_MAP_DIRS[@]}"; do
        local key="${entry%%:*}"
        local val="${entry#*:}"
        if [[ "$key" == "$svc" ]]; then
            echo "$val"
            return
        fi
    done
}

get_conf_files() {
    local svc="$1"
    for entry in "${SERVICE_CONF_MAP_FILES[@]}"; do
        local key="${entry%%:*}"
        local val="${entry#*:}"
        if [[ "$key" == "$svc" ]]; then
            echo "$val"
            return
        fi
    done
}

detect_services_in_container() {
    local cid="$1"
    local found=()

    local procs
    procs=$(dexec "$cid" "ps aux 2>/dev/null || ps -ef 2>/dev/null || cat /proc/*/comm 2>/dev/null")

    for svc in "${TARGETS[@]}"; do
        if echo "$procs" | grep -qiw "$svc"; then
            found+=("$svc")
        fi
    done

    local extra
    extra=$(dexec "$cid" "ps aux 2>/dev/null || ps -ef 2>/dev/null" | awk 'NR>1 {print $11}' | sed 's|.*/||' | sort -u)
    for proc in $extra; do
        proc_clean=$(echo "$proc" | tr -d '[:' | tr -d ']')
        [ -z "$proc_clean" ] && continue
        MATCHED=0
        for svc in "${TARGETS[@]}"; do
            [[ "$proc_clean" == *"$svc"* ]] && MATCHED=1 && break
        done
        for already in "${found[@]}"; do
            [[ "$proc_clean" == *"$already"* ]] && MATCHED=1 && break
        done
        [ $MATCHED -eq 0 ] && found+=("$proc_clean")
    done

    echo "${found[@]}"
}

backup_service_from_container() {
    local cid="$1"
    local cname="$2"
    local svc="$3"
    local svc_dir="$BACKUP_ROOT/${cname}/services/${svc}"
    mkdir -p "$svc_dir"

    local conf_dirs
    conf_dirs=$(get_conf_dirs "$svc")
    if [ -n "$conf_dirs" ]; then
        for cdir in $conf_dirs; do
            if dexec "$cid" "[ -d '$cdir' ] || [ -f '$cdir' ]" 2>/dev/null; then
                safe=$(echo "$cdir" | tr '/' '_' | sed 's/^_//')
                docker cp "$cid:$cdir" "$svc_dir/${safe}" 2>/dev/null
            fi
        done
    fi

    local conf_files
    conf_files=$(get_conf_files "$svc")
    if [ -n "$conf_files" ]; then
        for cfile in $conf_files; do
            if dexec "$cid" "[ -f '$cfile' ]" 2>/dev/null; then
                safe=$(echo "$cfile" | tr '/' '_' | sed 's/^_//')
                docker cp "$cid:$cfile" "$svc_dir/${safe}" 2>/dev/null
            fi
        done
    fi

    local etc_svc
    etc_svc=$(dexec "$cid" "ls -d /etc/${svc}* 2>/dev/null")
    if [ -n "$etc_svc" ]; then
        for epath in $etc_svc; do
            safe=$(echo "$epath" | tr '/' '_' | sed 's/^_//')
            docker cp "$cid:$epath" "$svc_dir/${safe}" 2>/dev/null
        done
    fi
}

backup_web_content_from_container() {
    local cid="$1"
    local cname="$2"
    local web_dir="$BACKUP_ROOT/${cname}/webroot"
    mkdir -p "$web_dir"

    for wpath in "${WEB_DATA_PATHS[@]}"; do
        if dexec "$cid" "[ -d '$wpath' ]" 2>/dev/null; then
            safe=$(echo "$wpath" | tr '/' '_' | sed 's/^_//')
            docker cp "$cid:$wpath" "$web_dir/${safe}" 2>/dev/null
            echo "    ✓ $wpath"
        fi
    done
}

backup_system_from_container() {
    local cid="$1"
    local cname="$2"
    local sys_dir="$BACKUP_ROOT/${cname}/system"
    mkdir -p "$sys_dir"

    for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/resolv.conf /etc/hosts /etc/hostname; do
        if dexec "$cid" "[ -f '$f' ]" 2>/dev/null; then
            docker cp "$cid:$f" "$sys_dir/" 2>/dev/null
        fi
    done

    dexec "$cid" "cat /etc/os-release 2>/dev/null" > "$sys_dir/os-release.txt"
    dexec "$cid" "env" > "$sys_dir/environment.txt" 2>/dev/null
    dexec "$cid" "ps aux 2>/dev/null || ps -ef 2>/dev/null" > "$sys_dir/processes.txt"
    dexec "$cid" "ss -plunt 2>/dev/null || netstat -plunt 2>/dev/null" > "$sys_dir/ports.txt"
    dexec "$cid" "cat /etc/crontab 2>/dev/null; ls /etc/cron.d/ 2>/dev/null; for u in \$(cut -d: -f1 /etc/passwd 2>/dev/null); do crontab -l -u \$u 2>/dev/null; done" > "$sys_dir/crontabs.txt"
}

backup_auth_from_container() {
    local cid="$1"
    local cname="$2"
    local auth_dir="$BACKUP_ROOT/${cname}/auth"
    mkdir -p "$auth_dir"

    for d in /etc/ssh /etc/pam.d /etc/ssl /etc/sssd /etc/krb5.conf; do
        if dexec "$cid" "[ -e '$d' ]" 2>/dev/null; then
            safe=$(echo "$d" | tr '/' '_' | sed 's/^_//')
            docker cp "$cid:$d" "$auth_dir/${safe}" 2>/dev/null
        fi
    done
}

backup_databases_from_container() {
    local cid="$1"
    local cname="$2"
    local db_dir="$BACKUP_ROOT/${cname}/database_dumps"
    mkdir -p "$db_dir"

    if dexec "$cid" "command -v mysqldump" >/dev/null 2>&1; then
        echo "    [*] Dumping MySQL/MariaDB..."
        dexec "$cid" "mysqldump --all-databases --single-transaction 2>/dev/null || mysqldump --all-databases 2>/dev/null" > "$db_dir/all_databases.sql" 2>/dev/null
        if [ ! -s "$db_dir/all_databases.sql" ]; then
            local mysql_pass
            mysql_pass=$(dexec "$cid" "env | grep MYSQL_ROOT_PASSWORD | cut -d= -f2-")
            [ -n "$mysql_pass" ] && dexec "$cid" "mysqldump --all-databases -p'${mysql_pass}' --single-transaction" > "$db_dir/all_databases.sql" 2>/dev/null
        fi
        [ -s "$db_dir/all_databases.sql" ] && echo "    ✓ MySQL dump complete"
    fi

    if dexec "$cid" "command -v pg_dumpall" >/dev/null 2>&1; then
        echo "    [*] Dumping PostgreSQL..."
        dexec "$cid" "su - postgres -c 'pg_dumpall' 2>/dev/null || pg_dumpall -U postgres 2>/dev/null" > "$db_dir/pg_dumpall.sql" 2>/dev/null
        [ -s "$db_dir/pg_dumpall.sql" ] && echo "    ✓ PostgreSQL dump complete"
    fi

    if dexec "$cid" "command -v redis-cli" >/dev/null 2>&1; then
        echo "    [*] Dumping Redis..."
        dexec "$cid" "redis-cli BGSAVE 2>/dev/null && sleep 2 && cat /data/dump.rdb 2>/dev/null || cat /var/lib/redis/dump.rdb 2>/dev/null" > "$db_dir/redis_dump.rdb" 2>/dev/null
        [ -s "$db_dir/redis_dump.rdb" ] && echo "    ✓ Redis dump complete"
    fi

    if dexec "$cid" "command -v mongodump" >/dev/null 2>&1; then
        echo "    [*] Dumping MongoDB..."
        dexec "$cid" "mongodump --archive 2>/dev/null" > "$db_dir/mongo_dump.archive" 2>/dev/null
        [ -s "$db_dir/mongo_dump.archive" ] && echo "    ✓ MongoDB dump complete"
    fi
}

RUNNING_CONTAINERS=$(docker ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
if [ -z "$RUNNING_CONTAINERS" ]; then
    echo "[!] No running containers found"
    exit 0
fi

echo "$RUNNING_CONTAINERS" | while IFS=' ' read -r cid cname; do
    echo -e "\n============================================"
    echo "[*] Container: $cname ($cid)"
    echo "============================================"

    CDIR="$BACKUP_ROOT/${cname}"
    mkdir -p "$CDIR"

    docker inspect "$cid" > "$CDIR/inspect.json" 2>/dev/null

    echo "  [*] Backing up system info..."
    backup_system_from_container "$cid" "$cname"

    echo "  [*] Backing up auth data..."
    backup_auth_from_container "$cid" "$cname"

    echo "  [*] Detecting services..."
    SERVICES_FOUND=$(detect_services_in_container "$cid")

    if [ -z "$SERVICES_FOUND" ]; then
        echo "    No known services detected via process list"
        IMG=$(docker inspect --format '{{.Config.Image}}' "$cid" 2>/dev/null)
        for svc in "${TARGETS[@]}"; do
            if echo "$IMG" | grep -qi "$svc"; then
                SERVICES_FOUND="$svc"
                echo "    Detected $svc from image name: $IMG"
                break
            fi
        done
    fi

    if [ -n "$SERVICES_FOUND" ]; then
        for svc in $SERVICES_FOUND; do
            echo "    [*] Backing up service: $svc"
            backup_service_from_container "$cid" "$cname" "$svc"
        done
    fi

    echo "  [*] Checking for web content..."
    backup_web_content_from_container "$cid" "$cname"

    echo "  [*] Checking for databases..."
    backup_databases_from_container "$cid" "$cname"

    echo "  ✓ Container $cname complete"
done

mkdir -p "$BACKUP_ROOT/_host_context"
docker ps -a --no-trunc > "$BACKUP_ROOT/_host_context/all_containers.txt" 2>/dev/null
docker images --no-trunc > "$BACKUP_ROOT/_host_context/all_images.txt" 2>/dev/null
docker network ls > "$BACKUP_ROOT/_host_context/all_networks.txt" 2>/dev/null
docker volume ls > "$BACKUP_ROOT/_host_context/all_volumes.txt" 2>/dev/null

echo -e "\n--- VERIFICATION REPORT ---"
for cdir in "$BACKUP_ROOT"/*/; do
    cname=$(basename "$cdir")
    [[ "$cname" == "_host_context" ]] && continue
    svc_dir="$cdir/services"
    if [ -d "$svc_dir" ] && [ "$(ls -A "$svc_dir" 2>/dev/null)" ]; then
        svc_list=$(ls "$svc_dir" | tr '\n' ', ' | sed 's/,$//')
        count=$(find "$svc_dir" -type f 2>/dev/null | wc -l)
        echo -e "[\e[32m OK \e[0m] $cname → services: $svc_list ($count files)"
    else
        echo -e "[\e[33m WARN \e[0m] $cname → no service configs found"
    fi
    if [ -d "$cdir/database_dumps" ] && [ "$(find "$cdir/database_dumps" -type f -size +0 2>/dev/null)" ]; then
        echo -e "[\e[32m OK \e[0m] $cname → database dumps present"
    fi
    if [ -d "$cdir/webroot" ] && [ "$(ls -A "$cdir/webroot" 2>/dev/null)" ]; then
        echo -e "[\e[32m OK \e[0m] $cname → web content backed up"
    fi
done

chmod -R 600 "$BACKUP_ROOT"
chmod 700 "$BACKUP_ROOT"
echo -e "\n--- Docker Service Backup Complete: $BACKUP_ROOT ---"
