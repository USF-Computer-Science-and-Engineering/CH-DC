#!/bin/bash

cp fileperms.txt /root/fileperms.txt
## Set SSH Client Alive Count Max to Zero

uname -a | grep -i ubuntu && sudo bash utils/ubuntu_harden.sh
uname -a | grep -i centos && sudo bash utils/centos_harden.sh
uname -a | grep -i debian && sudo bash utils/debian_harden.sh
uname -a | grep -i fedora && sudo bash utils/fedora_harden.sh
uname -a | grep -i openbsd && sudo bash utils/openbsd_harden.sh
