#!/bin/bash

toadd=(
    "alias atmux='tmux a -t threathunt'"
    "alias ctmux='bash /root/CH-DC/herdening/linux/ThreatHunting/tmux.sh'"
)



for i in "${toadd[@]}"; do
    echo "$i" >> ~/.bashrc || echo "$i" >> ~/.zshrc 
done
