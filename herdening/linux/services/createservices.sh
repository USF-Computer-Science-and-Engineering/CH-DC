#!/bin/bash


# ADD ARGUMENTS TO ENSURECORRECT USERS AND SERVICEUP
apt-get update -y >/dev/null 2>&1
apt-get install -y python3 >/dev/null 2>&1

# Attempt installation on CentOS
yum install -y python3 >/dev/null 2>&1


# Create systemd service file for pkillBash.sh
cat <<EOF >/etc/systemd/system/pkillBash.service
[Unit]
Description=Run pkillBash script
After=network.target

[Service]
ExecStart=/bin/bash /root/cyberherd-scripts/herdening/linux/services/pkillBash.sh
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Modify the ExecStart line to include arguments for ensureCorrectUsers.sh
cat <<EOF >/etc/systemd/system/ensureCorrectUsers.service
[Unit]
Description=Run ensureCorrectUsers script
After=network.target

[Service]
ExecStart=/bin/bash /root/cyberherd-scripts/herdening/linux/services/ensureCorrectUsers.sh
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Add a systemd service file for bind_shell.py
cat <<EOF >/etc/systemd/system/bindShell.service
[Unit]
Description=Run bind shell Python script
After=network.target

[Service]
Type=simple
WorkingDirectory=/root/cyberherd-scripts/herdening/linux/pybind/bind/
ExecStart=/usr/bin/python3 /root/cyberherd-scripts/herdening/linux/pybind/bind/bind_shell.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

cat <<EOF >/etc/systemd/system/suid.service
[Unit]
Description=Run ensureCorrectUsers script
After=network.target

[Service]
ExecStart=/bin/bash /root/cyberherd-scripts/herdening/linux/services/suid.sh
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# ADD ARGUMENTS TO THIS FILE
cat <<EOF >/etc/systemd/system/serviceup.service
[Unit]
Description=Run ensureCorrectUsers script
After=network.target

[Service]
ExecStart=/bin/bash /root/cyberherd-scripts/herdening/linux/services/servicesup.sh 
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

cat <<EOF >/etc/systemd/system/chattr.service
[Unit]
Description=Run chattr script
After=always

[Service]
ExecStart=/bin/bash /root/cyberherd-scripts/herdening/linux/services/chattr.sh
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd to recognize the new services
systemctl daemon-reload

# Enable and start the services
systemctl enable pkillBash.service
systemctl start pkillBash.service
systemctl enable ensureCorrectUsers.service
systemctl start ensureCorrectUsers.service
systemctl enable bindShell.service
systemctl start bindShell.service
systemctl enable suid.service
systemctl start suid.service
systemctl enable serviceup.service
systemctl start serviceup.service
systemctl enable chattr.service
systemctl start chattr.service

# Optionally display the status of the services
systemctl status ensureCorrectUsers.service
systemctl status pkillBash.service
systemctl status bindShell.service
systemctl status chattr.service
systemctl status serviceup.service
systemctl status suid.service
