#!/bin/bash

# USAGE
# sudo ./restart_services.sh httpd sshd apache2
# Ensure the script is run with root privileges
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root" >&2
  exit 1
fi

while true; do
  for service in "$@"; do
    systemctl is-active --quiet "$service"
    status=$?

    if [ $status -ne 0 ]; then
      echo "Service $service is stopped. Attempting to restart..."
      systemctl restart "$service"
      restart_status=$?

      if [ $restart_status -eq 0 ]; then
        echo "Service $service restarted successfully."
      else
        echo "Failed to restart service $service."
      fi
    else
      echo "Service $service is already running."
    fi
  done

  sleep 30
done

