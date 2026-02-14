#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[i]${NC} $1"; }

banner() {
    echo ""
    echo "=========================================="
    echo "  GONCAT EMERGENCY ACCESS DEPLOYMENT"
    echo "=========================================="
    echo ""
}

check_and_install_dependencies() {
    log "Checking dependencies..."
    
    local needs_update=0
    
    if ! command -v git &> /dev/null; then
        warn "Git not found, will install"
        needs_update=1
    else
        log "Git is installed"
    fi
    
    if ! command -v go &> /dev/null; then
        warn "Go not found, will install"
        needs_update=1
    else
        log "Go is installed ($(go version))"
    fi
    
    if ! command -v make &> /dev/null; then
        warn "Make not found, will install"
        needs_update=1
    else
        log "Make is installed"
    fi
    
    if [ $needs_update -eq 1 ]; then
        log "Installing missing dependencies..."
        
        if command -v apt-get &> /dev/null; then
            log "Using apt (Debian/Ubuntu)..."
            sudo apt-get update -qq
            
            if ! command -v git &> /dev/null; then
                sudo apt-get install -y git
                log "Git installed"
            fi
            
            if ! command -v go &> /dev/null; then
                sudo apt-get install -y golang-go
                log "Go installed"
            fi
            
            if ! command -v make &> /dev/null; then
                sudo apt-get install -y build-essential
                log "Make installed (via build-essential)"
            fi
            
        elif command -v yum &> /dev/null; then
            log "Using yum (RHEL/CentOS)..."
            
            if ! command -v git &> /dev/null; then
                sudo yum install -y git
                log "Git installed"
            fi
            
            if ! command -v go &> /dev/null; then
                sudo yum install -y golang
                log "Go installed"
            fi
            
            if ! command -v make &> /dev/null; then
                sudo yum groupinstall -y "Development Tools"
                log "Make installed (via Development Tools)"
            fi
            
        elif command -v dnf &> /dev/null; then
            log "Using dnf (Fedora/RHEL 8+)..."
            
            if ! command -v git &> /dev/null; then
                sudo dnf install -y git
                log "Git installed"
            fi
            
            if ! command -v go &> /dev/null; then
                sudo dnf install -y golang
                log "Go installed"
            fi
            
            if ! command -v make &> /dev/null; then
                sudo dnf groupinstall -y "Development Tools"
                log "Make installed (via Development Tools)"
            fi
            
        else
            error "Unable to detect package manager. Please install git, golang-go, and make manually."
        fi
        
        if ! command -v git &> /dev/null; then
            error "Git installation failed"
        fi
        
        if ! command -v go &> /dev/null; then
            error "Go installation failed"
        fi
        
        if ! command -v make &> /dev/null; then
            error "Make installation failed"
        fi
        
        log "All dependencies installed successfully"
    else
        log "All dependencies already installed"
    fi
}

banner

check_and_install_dependencies

if [ "$PWD" != "/root/goncat" ]; then
    log "Setting up goncat in /root/goncat..."
    
    cd /root
    
    if [ ! -d "/root/goncat" ]; then
        log "Cloning goncat repository..."
        git clone https://github.com/DominicBreuker/goncat || error "Failed to clone goncat"
    fi
    
    cd /root/goncat
    log "Building goncat..."
    make build || error "Failed to build goncat"
fi

if [ ! -f "/root/goncat/dist/goncat.elf" ]; then
    error "Goncat binary not found at /root/goncat/dist/goncat.elf"
fi

log "Goncat binary ready at /root/goncat/dist/goncat.elf"

log "Setting up SSH keys..."

if [ ! -f "/root/.ssh/id_ed25519" ]; then
    log "Generating SSH key pair..."
    ssh-keygen -t ed25519 -f /root/.ssh/id_ed25519 -N "" || error "Failed to generate SSH key"
    log "SSH key generated at /root/.ssh/id_ed25519"
else
    log "SSH key already exists at /root/.ssh/id_ed25519"
fi

echo ""
read -p "Enter target IP address: " REMOTE_HOST

if [ -z "$REMOTE_HOST" ]; then
    error "No IP address provided"
fi

read -p "Enter SSH username [root]: " REMOTE_USER
REMOTE_USER=${REMOTE_USER:-root}

log "Copying SSH key to $REMOTE_USER@$REMOTE_HOST..."
ssh-copy-id -i /root/.ssh/id_ed25519.pub $REMOTE_USER@$REMOTE_HOST || error "Failed to copy SSH key"

log "SSH key copied successfully"

echo ""
info "Set a shared password for goncat encryption"
info "You'll need this password to connect to the bind shell"
echo ""

while true; do
    read -sp "Enter password: " SHARED_KEY
    echo
    read -sp "Confirm password: " SHARED_KEY2
    echo
    
    if [ "$SHARED_KEY" = "$SHARED_KEY2" ]; then
        if [ -z "$SHARED_KEY" ]; then
            warn "Password cannot be empty"
            continue
        fi
        break
    else
        warn "Passwords do not match, try again"
    fi
done

log "Password set"

BIND_PORT="12345"
SERVICE_NAME="goncat-emergency"
GONCAT_LOCAL="/root/goncat/dist/goncat.elf"
GONCAT_REMOTE="/usr/local/bin/goncat"

log "Deploying goncat to $REMOTE_HOST..."

scp -q "$GONCAT_LOCAL" $REMOTE_USER@$REMOTE_HOST:/tmp/goncat || error "Failed to copy binary"

ssh $REMOTE_USER@$REMOTE_HOST "
    sudo chattr -i $GONCAT_REMOTE 2>/dev/null || true
    
    sudo mv /tmp/goncat $GONCAT_REMOTE
    sudo chmod +x $GONCAT_REMOTE
    sudo chown root:root $GONCAT_REMOTE
    
    sudo chattr +i $GONCAT_REMOTE
" || error "Failed to install binary"

log "Binary deployed and protected with chattr +i"

log "Creating systemd service..."

ssh $REMOTE_USER@$REMOTE_HOST "sudo chattr -i /etc/systemd/system/${SERVICE_NAME}.service 2>/dev/null || true"

ssh $REMOTE_USER@$REMOTE_HOST "sudo cat > /etc/systemd/system/${SERVICE_NAME}.service << 'EOFSERVICE'
[Unit]
Description=Goncat Emergency Bind Shell
After=network.target
Documentation=https://github.com/DominicBreuker/goncat

[Service]
Type=simple
ExecStart=$GONCAT_REMOTE slave listen 'tcp://*:$BIND_PORT' --ssl --key $SHARED_KEY
Restart=always
RestartSec=10
User=root

NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOFSERVICE
" || error "Failed to create service"

ssh $REMOTE_USER@$REMOTE_HOST "
    sudo chattr +i /etc/systemd/system/${SERVICE_NAME}.service
" || warn "Failed to protect service file"

log "Service created and protected with chattr +i"

log "Starting service..."

ssh $REMOTE_USER@$REMOTE_HOST "
    sudo pkill goncat 2>/dev/null || true
    
    sudo systemctl daemon-reload
    sudo systemctl enable ${SERVICE_NAME}
    sudo systemctl start ${SERVICE_NAME}
" || error "Failed to start service"

sleep 2

if ssh $REMOTE_USER@$REMOTE_HOST "sudo systemctl is-active ${SERVICE_NAME}" | grep -q "active"; then
    log "Service is running!"
else
    error "Service failed to start. Check: ssh $REMOTE_USER@$REMOTE_HOST 'sudo journalctl -u ${SERVICE_NAME} -n 50'"
fi

if ssh $REMOTE_USER@$REMOTE_HOST "sudo ss -tlnp | grep :$BIND_PORT" &>/dev/null; then
    log "Port $BIND_PORT is listening"
else
    warn "Port $BIND_PORT not listening - check firewall"
fi

echo ""
log "Testing connection..."
info "You should get a shell. Type 'exit' to return."
info "If connection hangs, press Ctrl+C and check firewall rules."
echo ""
sleep 2

$GONCAT_LOCAL master connect tcp://$REMOTE_HOST:$BIND_PORT --exec /bin/bash --ssl --key "$SHARED_KEY" --pty

echo ""
echo "=========================================="
echo "  DEPLOYMENT COMPLETE"
echo "=========================================="
echo ""
echo "Target:      $REMOTE_HOST"
echo "Port:        $BIND_PORT"
echo "Service:     ${SERVICE_NAME}.service"
echo ""
echo "PROTECTION:"
echo "  Binary:      $GONCAT_REMOTE (chattr +i)"
echo "  Service:     /etc/systemd/system/${SERVICE_NAME}.service (chattr +i)"
echo ""
echo "CONNECT COMMAND:"
echo "  /root/goncat/dist/goncat.elf master connect tcp://$REMOTE_HOST:$BIND_PORT --exec /bin/bash --ssl --key 'YOUR_PASSWORD' --pty"
echo ""
echo "SERVICE COMMANDS:"
echo "  Status:  ssh $REMOTE_USER@$REMOTE_HOST 'sudo systemctl status ${SERVICE_NAME}'"
echo "  Stop:    ssh $REMOTE_USER@$REMOTE_HOST 'sudo systemctl stop ${SERVICE_NAME}'"
echo "  Restart: ssh $REMOTE_USER@$REMOTE_HOST 'sudo systemctl restart ${SERVICE_NAME}'"
echo "  Logs:    ssh $REMOTE_USER@$REMOTE_HOST 'sudo journalctl -u ${SERVICE_NAME} -f'"
echo ""
echo "TO REMOVE PROTECTION (if needed):"
echo "  Binary:  ssh $REMOTE_USER@$REMOTE_HOST 'sudo chattr -i $GONCAT_REMOTE'"
echo "  Service: ssh $REMOTE_USER@$REMOTE_HOST 'sudo chattr -i /etc/systemd/system/${SERVICE_NAME}.service'"
echo ""
echo "CLEANUP (removes everything):"
echo "  ssh $REMOTE_USER@$REMOTE_HOST 'sudo chattr -i $GONCAT_REMOTE /etc/systemd/system/${SERVICE_NAME}.service && sudo systemctl stop ${SERVICE_NAME} && sudo systemctl disable ${SERVICE_NAME} && sudo rm /etc/systemd/system/${SERVICE_NAME}.service $GONCAT_REMOTE && sudo systemctl daemon-reload'"
echo ""

log "Done! Your emergency access is now deployed and protected."
