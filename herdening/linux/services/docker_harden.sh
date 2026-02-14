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

if ! command -v docker &> /dev/null; then
    echo -e "${RED}[!] Docker is not installed${RESET}"
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/root/docker-backup-${TIMESTAMP}"
QUARANTINE_DIR="/root/docker-quarantine-${TIMESTAMP}"

echo -e "${CYAN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════╗
║     Docker Hardening & Security Lockdown Tool         ║
║          CCDC Blue Team Defense Suite                 ║
║           🔒 Container Fortress Mode 🔒               ║
╚═══════════════════════════════════════════════════════╝
EOF
echo -e "${RESET}\n"

echo -e "${GREEN}[*] Starting hardening at: $(date)${RESET}\n"

mkdir -p "$BACKUP_DIR" "$QUARANTINE_DIR"

echo -e "${RED}╔═══════════════════════════════════════════════════════╗${RESET}"
echo -e "${RED}║           PHASE 1: THREAT IDENTIFICATION              ║${RESET}"
echo -e "${RED}╚═══════════════════════════════════════════════════════╝${RESET}\n"

echo -e "${YELLOW}[1] Identifying Dangerous Containers${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

CONTAINERS=$(docker ps -q)
DANGEROUS_CONTAINERS=()

for container in $CONTAINERS; do
    CONTAINER_NAME=$(docker inspect --format='{{.Name}}' "$container" | tr -d '/')
    
    PRIVILEGED=$(docker inspect --format='{{.HostConfig.Privileged}}' "$container")
    
    DOCKER_SOCK=$(docker inspect --format='{{range .Mounts}}{{.Source}}{{"\n"}}{{end}}' "$container" | grep -E "docker\.sock")
    
    CAPS=$(docker inspect --format='{{.HostConfig.CapAdd}}' "$container")
    
    NETWORK=$(docker inspect --format='{{.HostConfig.NetworkMode}}' "$container")
    
    if [ "$PRIVILEGED" == "true" ] || [ -n "$DOCKER_SOCK" ] || [[ "$CAPS" == *"SYS_ADMIN"* ]] || [ "$NETWORK" == "host" ]; then
        echo -e "${RED}[!] DANGEROUS: $CONTAINER_NAME ($container)${RESET}"
        [ "$PRIVILEGED" == "true" ] && echo -e "  └─ Privileged mode enabled"
        [ -n "$DOCKER_SOCK" ] && echo -e "  └─ Docker socket mounted"
        [[ "$CAPS" == *"SYS_ADMIN"* ]] && echo -e "  └─ SYS_ADMIN capability"
        [ "$NETWORK" == "host" ] && echo -e "  └─ Host network mode"
        
        DANGEROUS_CONTAINERS+=("$container")
    fi
done

echo -e "\n${YELLOW}[2] Scanning for Reverse Shells${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

SHELL_CONTAINERS=()

for container in $CONTAINERS; do
    CONTAINER_NAME=$(docker inspect --format='{{.Name}}' "$container" | tr -d '/')
    
    SHELLS=$(docker exec "$container" sh -c 'ps aux' 2>/dev/null | grep -iE "(nc.*-e|/dev/tcp|bash.*-i|sh.*-i|python.*socket|socat)")
    
    if [ -n "$SHELLS" ]; then
        echo -e "${RED}[!] REVERSE SHELL DETECTED: $CONTAINER_NAME${RESET}"
        echo "$SHELLS"
        SHELL_CONTAINERS+=("$container")
    fi
done

echo -e "\n${RED}╔═══════════════════════════════════════════════════════╗${RESET}"
echo -e "${RED}║              PHASE 2: CONTAINER REMEDIATION           ║${RESET}"
echo -e "${RED}╚═══════════════════════════════════════════════════════╝${RESET}\n"

echo -e "${YELLOW}[3] Stopping Dangerous Containers${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

for container in "${DANGEROUS_CONTAINERS[@]}"; do
    CONTAINER_NAME=$(docker inspect --format='{{.Name}}' "$container" | tr -d '/')
    
    echo -e "${BLUE}[i] Backing up container: $CONTAINER_NAME${RESET}"
    docker export "$container" > "$BACKUP_DIR/${CONTAINER_NAME}.tar" 2>/dev/null
    
    echo -e "${YELLOW}[!] Stopping: $CONTAINER_NAME${RESET}"
    docker stop "$container" > /dev/null 2>&1
    
    read -p "Remove container $CONTAINER_NAME permanently? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker rm "$container" > /dev/null 2>&1
        echo -e "${GREEN}[✓] Removed: $CONTAINER_NAME${RESET}"
    fi
done

echo -e "\n${YELLOW}[4] Killing Reverse Shell Processes${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

for container in "${SHELL_CONTAINERS[@]}"; do
    CONTAINER_NAME=$(docker inspect --format='{{.Name}}' "$container" | tr -d '/')
    
    echo -e "${YELLOW}[!] Killing suspicious processes in: $CONTAINER_NAME${RESET}"
    
    docker exec "$container" sh -c 'pkill -9 nc' 2>/dev/null
    docker exec "$container" sh -c 'pkill -9 netcat' 2>/dev/null
    docker exec "$container" sh -c 'pkill -9 socat' 2>/dev/null
    
    docker exec "$container" sh -c 'ps aux | grep -E "bash.*-i|sh.*-i" | grep -v grep | awk "{print \$2}" | xargs -r kill -9' 2>/dev/null
    
    echo -e "${GREEN}[✓] Processes terminated${RESET}"
done

echo -e "\n${YELLOW}[5] Scanning for Malicious Images${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

DANGLING=$(docker images -f "dangling=true" -q)
if [ -n "$DANGLING" ]; then
    echo -e "${YELLOW}[!] Removing dangling images...${RESET}"
    docker rmi $DANGLING 2>/dev/null
    echo -e "${GREEN}[✓] Dangling images removed${RESET}"
fi

echo -e "${BLUE}[i] Images created in last 24 hours:${RESET}"
docker images --format "{{.Repository}}:{{.Tag}} - {{.CreatedAt}}" | grep "$(date +%Y-%m-%d)"

echo -e "\n${RED}╔═══════════════════════════════════════════════════════╗${RESET}"
echo -e "${RED}║           PHASE 3: DOCKER DAEMON HARDENING            ║${RESET}"
echo -e "${RED}╚═══════════════════════════════════════════════════════╝${RESET}\n"

echo -e "${YELLOW}[6] Hardening Docker Daemon Configuration${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -f /etc/docker/daemon.json ]; then
    cp /etc/docker/daemon.json "$BACKUP_DIR/daemon.json.bak"
fi

cat > /etc/docker/daemon.json << 'DOCKERCFG'
{
  "icc": false,
  "userns-remap": "default",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true
}
DOCKERCFG

echo -e "${GREEN}[✓] Docker daemon config hardened${RESET}"

echo -e "${BLUE}[i] Restarting Docker daemon...${RESET}"
systemctl restart docker
sleep 3
echo -e "${GREEN}[✓] Docker daemon restarted${RESET}"

echo -e "\n${YELLOW}[7] Securing Docker Socket${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -S /var/run/docker.sock ]; then
    CURRENT_PERMS=$(stat -c "%a" /var/run/docker.sock)
    echo -e "${BLUE}[i] Current socket permissions: $CURRENT_PERMS${RESET}"
    
    chmod 660 /var/run/docker.sock
    chown root:docker /var/run/docker.sock
    echo -e "${GREEN}[✓] Socket permissions set to 660${RESET}"
fi

if netstat -an | grep -q "0.0.0.0:2375"; then
    echo -e "${RED}[!] WARNING: Docker API exposed on 2375${RESET}"
    echo -e "${YELLOW}[!] Disable by removing -H tcp://0.0.0.0:2375 from Docker daemon${RESET}"
fi

echo -e "\n${YELLOW}[8] Restricting Docker Group Membership${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo -e "${BLUE}[i] Current docker group members:${RESET}"
getent group docker

echo -e "${YELLOW}[!] Remove unnecessary users from docker group:${RESET}"
echo "    usermod -G [other_groups] [username]"

echo -e "\n${RED}╔═══════════════════════════════════════════════════════╗${RESET}"
echo -e "${RED}║              PHASE 4: NETWORK HARDENING               ║${RESET}"
echo -e "${RED}╚═══════════════════════════════════════════════════════╝${RESET}\n"

echo -e "${YELLOW}[9] Auditing Docker Networks${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

docker network ls

HOST_CONTAINERS=$(docker ps --filter "network=host" --format "{{.Names}}")
if [ -n "$HOST_CONTAINERS" ]; then
    echo -e "${RED}[!] Containers on host network:${RESET}"
    echo "$HOST_CONTAINERS"
    echo -e "${YELLOW}[!] Consider moving to bridge network${RESET}"
fi

echo -e "\n${YELLOW}[10] Creating Isolated Network${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if ! docker network ls | grep -q "isolated"; then
    docker network create \
        --driver bridge \
        --subnet=172.20.0.0/16 \
        --opt "com.docker.network.bridge.name"="docker_isolated" \
        isolated
    echo -e "${GREEN}[✓] Created isolated network${RESET}"
fi

echo -e "\n${RED}╔═══════════════════════════════════════════════════════╗${RESET}"
echo -e "${RED}║           PHASE 5: PERSISTENCE REMOVAL                ║${RESET}"
echo -e "${RED}╚═══════════════════════════════════════════════════════╝${RESET}\n"

echo -e "${YELLOW}[11] Checking Docker Compose Files${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

find / -name "docker-compose.yml" -o -name "docker-compose.yaml" 2>/dev/null | while read -r compose_file; do
    echo -e "${BLUE}[i] Found: $compose_file${RESET}"
    
    cp "$compose_file" "$BACKUP_DIR/$(basename $compose_file).bak"
    
    if grep -qE "(privileged.*true|/var/run/docker.sock|cap_add.*SYS_ADMIN|network_mode.*host)" "$compose_file"; then
        echo -e "${RED}[!] Contains dangerous configurations${RESET}"
        grep -nE "(privileged|docker.sock|SYS_ADMIN|network_mode.*host)" "$compose_file"
        
        sed -i 's/privileged:.*/privileged: false/' "$compose_file"
        
        sed -i 's|^\s*- /var/run/docker.sock|# REMOVED: - /var/run/docker.sock|' "$compose_file"
        
        echo -e "${GREEN}[✓] Sanitized compose file${RESET}"
    fi
done

echo -e "\n${YELLOW}[12] Removing Malicious Systemd Services${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

systemctl list-units --type=service --state=running | grep -i docker | while read -r line; do
    SERVICE=$(echo "$line" | awk '{print $1}')
    if [[ "$SERVICE" != "docker.service" ]] && [[ "$SERVICE" != "docker.socket" ]]; then
        echo -e "${YELLOW}[!] Suspicious service: $SERVICE${RESET}"
        read -p "Disable service $SERVICE? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            systemctl stop "$SERVICE"
            systemctl disable "$SERVICE"
            echo -e "${GREEN}[✓] Disabled: $SERVICE${RESET}"
        fi
    fi
done

echo -e "\n${RED}╔═══════════════════════════════════════════════════════╗${RESET}"
echo -e "${RED}║           PHASE 6: SECURITY MONITORING                ║${RESET}"
echo -e "${RED}╚═══════════════════════════════════════════════════════╝${RESET}\n"

echo -e "${YELLOW}[13] Enabling Docker Content Trust${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

cat >> /etc/environment << 'DCT'
DOCKER_CONTENT_TRUST=1
DCT

echo -e "${GREEN}[✓] Docker Content Trust enabled${RESET}"
echo -e "${YELLOW}[!] Restart shell or run: export DOCKER_CONTENT_TRUST=1${RESET}"

echo -e "\n${YELLOW}[14] Setting Up Audit Logging${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if ! command -v auditctl &> /dev/null; then
    echo -e "${YELLOW}[!] Installing auditd...${RESET}"
    apt-get install -y auditd 2>/dev/null || yum install -y audit 2>/dev/null
fi

cat > /etc/audit/rules.d/docker.rules << 'AUDITRULES'
-w /usr/bin/docker -p wa -k docker
-w /var/lib/docker -p wa -k docker
-w /etc/docker -p wa -k docker
-w /lib/systemd/system/docker.service -p wa -k docker
-w /lib/systemd/system/docker.socket -p wa -k docker
-w /etc/default/docker -p wa -k docker
-w /etc/docker/daemon.json -p wa -k docker
-w /usr/bin/containerd -p wa -k docker
-w /usr/bin/runc -p wa -k docker
AUDITRULES

service auditd restart 2>/dev/null
echo -e "${GREEN}[✓] Docker audit logging configured${RESET}"

echo -e "\n${YELLOW}[15] Creating Security Baseline${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

cat > "$BACKUP_DIR/security-baseline.txt" << BASELINE
Docker Security Baseline - $(date)
═══════════════════════════════════════════

RUNNING CONTAINERS:
$(docker ps --format "{{.ID}} - {{.Names}} - {{.Image}}")

IMAGES:
$(docker images --format "{{.Repository}}:{{.Tag}} - {{.ID}}")

NETWORKS:
$(docker network ls)

VOLUMES:
$(docker volume ls)

DOCKER VERSION:
$(docker version --format '{{.Server.Version}}')

DAEMON CONFIG:
$(cat /etc/docker/daemon.json 2>/dev/null || echo "Default configuration")
BASELINE

echo -e "${GREEN}[✓] Baseline saved to: $BACKUP_DIR/security-baseline.txt${RESET}"

echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}║              HARDENING COMPLETE                       ║${RESET}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════╝${RESET}\n"

echo -e "${CYAN}[*] Summary:${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}Backup Location:${RESET}     $BACKUP_DIR"
echo -e "${BLUE}Quarantine Location:${RESET} $QUARANTINE_DIR"
echo -e "${BLUE}Dangerous Containers:${RESET} ${#DANGEROUS_CONTAINERS[@]}"
echo -e "${BLUE}Shell Containers:${RESET}     ${#SHELL_CONTAINERS[@]}"

echo -e "\n${YELLOW}[!] ADDITIONAL MANUAL STEPS:${RESET}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1. Review quarantined containers in: $BACKUP_DIR"
echo "2. Scan all images with 'docker scan <image>'"
echo "3. Implement AppArmor/SELinux profiles"
echo "4. Set up secrets management (HashiCorp Vault)"
echo "5. Enable user namespace remapping"
echo "6. Configure resource limits (CPU/Memory)"
echo "7. Set up vulnerability scanning (Trivy/Clair)"
echo "8. Monitor Docker events: docker events &"
echo "9. Review audit logs: ausearch -k docker"
echo "10. Implement network policies and firewalls"

echo -e "\n${GREEN}[✓] Docker environment hardened!${RESET}"
echo -e "${CYAN}[*] Monitor containers: watch -n 2 'docker ps'${RESET}"
echo -e "${MAGENTA}[*] Stay vigilant. Red team never sleeps. 🔒${RESET}\n"