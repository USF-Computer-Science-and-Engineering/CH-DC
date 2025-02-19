#!/bin/bash

SESSION_NAME=threathunt

SCRIPTS=(
    "/root/CH-DC/herdening/linux/services/chattr.sh"
    "/root/CH-DC/herdening/linux/services/ensureCorrectUsers.sh"
    "/root/CH-DC/herdening/linux/services/firewall.sh"
)

SCRIPTS2=(
    "/root/CH-DC/herdening/linux/ThreatHunting/grazingMonitor.sh"
    "/root/CH-DC/herdening/linux/ThreatHunting/socket.sh"
    "/root/CH-DC/herdening/linux/ThreatHunting/pspy.sh"
    "/root/CH-DC/herdening/linux/ThreatHunting/suid.sh"

)

SCRIPTS3=(
    "/root/CH-DC/herdening/linux/ThreatHunting/checksystemd.sh"
    "/root/CH-DC/herdening/linux/ThreatHunting/backdoorfinder.sh"

)


tmux has-session -t $SESSION_NAME 2>/dev/null

if [ $? != 0 ]; then
    echo "Creating new tmux session: '$SESSION_NAME'"

    tmux new-session -d -s $SESSION_NAME

    tmux split-window -h
    tmux split-window -v
    tmux select-pane -t 0
    tmux split-window -v

    for i in {0..2}; do
        tmux send-keys -t $i "bash ${SCRIPTS[i]}" C-m
    done

    tmux send-keys -t 3 "bash /root/CH-DC/herdening/linux/services/servicesup.sh $1 $2 $3" C-m

    tmux new-window

    tmux split-window -h
    tmux split-window -v
    tmux select-pane -t 0
    tmux split-window -v

    for i in {0..3}; do
        tmux send-keys -t $i "bash ${SCRIPTS2[i]}" C-m
    done   
    
    tmux new-window

    for i in {0..1}; do
        tmux send-keys -t $i "bash ${SCRIPTS3[i]}" C-m
    done
     

else
    echo "Session '$SESSION_NAME' already exists."
fi