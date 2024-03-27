#!/bin/bash

# Function to detect package manager and install ClamAV
install_clamav() {
    if command -v apt-get >/dev/null; then
        echo "Using apt-get to install ClamAV..."
        sudo apt-get update
        sudo apt-get install -y clamav clamav-daemon
    elif command -v yum >/dev/null; then
        echo "Using yum to install ClamAV..."
        sudo yum clean all
        sudo yum install -y clamav-server clamav-data clamav-update clamav-filesystem clamav clamav-scanner-systemd clamav-devel clamav-lib clamav-server-systemd
    elif command -v dnf >/dev/null; then
        echo "Using dnf to install ClamAV..."
        sudo dnf install -y clamav clamav-update
    else
        echo "Unsupported package manager. Exiting."
        exit 1
    fi
}

# Function to update virus database
update_virus_database() {
    echo "Updating virus database..."
    sudo systemctl stop clamav-freshclam
    sudo freshclam
    sudo systemctl start clamav-freshclam
}

# Function to configure ClamAV to disable data submission
configure_clamav() {
    echo "Configuring ClamAV to disable data submission..."
    if [ -f /etc/clamav/freshclam.conf ]; then
        sudo sed -i '/^#DataSubmissionEnabled/d' /etc/clamav/freshclam.conf
        sudo sed -i '/^DataSubmissionEnabled/d' /etc/clamav/freshclam.conf
        echo "DataSubmissionEnabled no" | sudo tee -a /etc/clamav/freshclam.conf > /dev/null
    else
        echo "ClamAV configuration file not found."
    fi
}

# Function to create a systemd service and timer for regular scans
create_scan_service_and_timer() {
    echo "Creating ClamAV scan service and timer..."

    # Create a bash script for scanning
    sudo bash -c 'cat <<EOF >/usr/local/bin/clamav_scan.sh
#!/bin/bash
# ClamAV scan script
clamscan -r / --exclude-dir="^/sys" --exclude-dir="^/proc" --exclude-dir="^/dev"
EOF'
    sudo chmod +x /usr/local/bin/clamav_scan.sh

    # Create the systemd service file
    sudo bash -c 'cat <<EOF >/etc/systemd/system/clamav_scan.service
[Unit]
Description=ClamAV Scan

[Service]
Type=simple
ExecStart=/usr/local/bin/clamav_scan.sh
EOF'

    # Create the systemd timer file
    sudo bash -c 'cat <<EOF >/etc/systemd/system/clamav_scan.timer
[Unit]
Description=Runs ClamAV Scan every 10 minutes

[Timer]
OnBootSec=10min
OnUnitActiveSec=10min
Unit=clamav_scan.service

[Install]
WantedBy=timers.target
EOF'

    # Reload systemd to recognize new service and timer
    sudo systemctl daemon-reload

    # Enable and start the timer
    sudo systemctl enable clamav_scan.timer
    sudo systemctl start clamav_scan.timer

    echo "ClamAV scan service and timer created and started."
}

# Main script execution
echo "Starting ClamAV installation..."
install_clamav
update_virus_database
configure_clamav
create_scan_service_and_timer
echo "ClamAV installation and configuration completed."
