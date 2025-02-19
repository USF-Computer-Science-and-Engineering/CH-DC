#!/bin/bash
# USAGE:
#   sudo ./restart_services.sh service1 service2 ...
#
# This script checks if the given services are running and attempts
# to restart them if they are not. It supports multiple service management
# systems: systemctl, service (SysVinit/BSD), initctl (Upstart), rc-service (OpenRC),
# sv (runit), launchctl (macOS), and SMF (Solaris).

# Define color variables for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'  # No Color

# Ensure the script is run with root privileges
if [ "$(id -u)" -ne 0 ]; then
  echo -e "${RED}This script must be run as root${NC}" >&2
  exit 1
fi

# Determine which service management tool is available
if command -v systemctl &>/dev/null; then
  SERVICE_CMD="systemctl"
elif command -v service &>/dev/null; then
  SERVICE_CMD="service"
elif command -v initctl &>/dev/null; then
  SERVICE_CMD="initctl"
elif command -v rc-service &>/dev/null; then
  SERVICE_CMD="openrc"
elif command -v sv &>/dev/null; then
  SERVICE_CMD="runit"
elif command -v launchctl &>/dev/null; then
  SERVICE_CMD="launchctl"
elif command -v svcs &>/dev/null && command -v svcadm &>/dev/null; then
  SERVICE_CMD="smf"
else
  echo -e "${RED}No supported service management tool found (systemctl, service, initctl, rc-service, sv, launchctl, or SMF). Exiting.${NC}"
  exit 1
fi

echo -e "Using service manager: ${GREEN}$SERVICE_CMD${NC}"

# Declare an associative array to store each service's last reported state.
# Possible states: "up", "down", or "failed"
declare -A service_state

# Function to check the service status
check_service_status() {
  local service="$1"
  case "$SERVICE_CMD" in
    systemctl)
      systemctl is-active --quiet "$service"
      return $?
      ;;
    service)
      service "$service" status &>/dev/null
      return $?
      ;;
    initctl)
      initctl status "$service" 2>/dev/null | grep -q "start/running"
      return $?
      ;;
    openrc)
      rc-service "$service" status &>/dev/null
      return $?
      ;;
    runit)
      sv status "$service" 2>/dev/null | grep -q "up"
      return $?
      ;;
    launchctl)
      launchctl list | grep -q "$service"
      return $?
      ;;
    smf)
      svcs "$service" 2>/dev/null | grep -q "online"
      return $?
      ;;
    *)
      return 1
      ;;
  esac
}

# Function to restart the service.
# All stderr output is redirected to /dev/null to suppress automatic error messages.
restart_service() {
  local service="$1"
  case "$SERVICE_CMD" in
    systemctl)
      systemctl restart "$service" 2>/dev/null
      return $?
      ;;
    service)
      service "$service" restart 2>/dev/null
      return $?
      ;;
    initctl)
      initctl restart "$service" 2>/dev/null
      return $?
      ;;
    openrc)
      rc-service "$service" restart 2>/dev/null
      return $?
      ;;
    runit)
      sv restart "$service" 2>/dev/null
      return $?
      ;;
    launchctl)
      launchctl kickstart -k "$service" 2>/dev/null
      return $?
      ;;
    smf)
      svcadm restart "$service" 2>/dev/null
      return $?
      ;;
    *)
      return 1
      ;;
  esac
}

# Main loop to continuously check services every 30 seconds.
while true; do
  for service in "$@"; do
    check_service_status "$service"
    status=$?
    if [ $status -eq 0 ]; then
      # Service is up.
      if [[ "${service_state[$service]}" != "up" ]]; then
        if [[ "${service_state[$service]}" == "down" || "${service_state[$service]}" == "failed" ]]; then
          echo -e "${GREEN}Service '$service' is up again.${NC}"
        else
          echo -e "${GREEN}Service '$service' is running.${NC}"
        fi
        service_state[$service]="up"
      fi
    else
      # Service is down.
      if [[ "${service_state[$service]}" != "down" && "${service_state[$service]}" != "failed" ]]; then
        echo -e "${RED}Service '$service' is down. Attempting to restart...${NC}"
        service_state[$service]="down"
      fi
      restart_service "$service"
      sleep 2
      check_service_status "$service"
      if [ $? -eq 0 ]; then
        if [[ "${service_state[$service]}" != "up" ]]; then
          echo -e "${GREEN}Service '$service' is up again after restart.${NC}"
        fi
        service_state[$service]="up"
      else
        if [[ "${service_state[$service]}" != "failed" ]]; then
          echo -e "${YELLOW}Failed to restart service '$service'. It can't be restarted.${NC}"
        fi
        service_state[$service]="failed"
      fi
    fi
  done
  sleep 10
done
