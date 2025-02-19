#!/bin/bash

# sudo passwd blackteam_adm and then set up a password for black to test it.
############################ NOTE: THIS SCRIPT MAKES USERS THAT SHOULD NOT BE HERE. DO NOT USE THESE LISTS FOR CCDC REFERENCE, USE THE LISTS IN CONTEXT.SH FOR REFERENCE.
if [ $(whoami) != "root" ]; then
    echo "Script must be run as root"
    exit 1
fi

# Definitions

###################################################### SCORECHECK USER #################################################
DONOTTOUCH=(
blackteam_adm
)
###################################################### SCORECHECK USER #################################################

###################################################### ADMINS #################################################
administratorGroup=(
elara.boss
sarah.lee
lisa.brown
michael.davis
emily.chen
tom.harris
bob.johnson
david.kim
rachel.patel
dave.grohl
kate.skye
leo.zenith
jack.rover
sudo
root
adm
syslog
bad.actor
barry.bonds
badman.batman
beter.briffin
)

echo "List of administrators:"
for admin in "${administratorGroup[@]}"; do
echo "$admin"
done

##################################################### PIPING BASH HISTORY TO /DEV/NULL ###############################
# Redirect the content of .bash_history to /dev/null
cat /dev/null > ~/.bash_history

# Optional: Clear the in-memory history for the current session
history -c

###################################################### NORMAL USERS #################################################
normalUsers=(
lucy.nova
xavier.blackhole
ophelia.redding
marcus.atlas
yara.nebula
parker.posey
maya.star
zachary.comet
quinn.jovi
nina.eclipse
alice.bowie
ruby.rose
owen.mars
bob.dylan
samantha.stephens
parker.jupiter
carol.rivers
taurus.tucker
rachel.venus
emily.waters
una.veda
ruby.starlight
frank.zappa
ava.stardust
samantha.aurora
grace.slick
benny.spacey
sophia.constellation
harry.potter
celine.cosmos
tessa.nova
ivy.lee
dave.marsden
thomas.spacestation
kate.bush
emma.nova
una.moonbase
luna.lovegood
frank.astro
victor.meteor
mars.patel
grace.luna
wendy.starship
neptune.williams
henry.orbit
ivy.starling
daemon
bin
sys
sync
games
man
lp
mail
news
uucp
proxy
www-data
backup
list
irc
gnats
nobody
systemd-network
systemd-resolve
systemd-timesync
messagebus
syslog
_apt
tss
uuidd
tcpdump
rtkit
avahi-autoipd
usbmux
dnsmasq
cups-pk-helper
speech-dispatcher
avahi
kernoops
saned
nm-openvpn
hplip
whoopsie
colord
geoclue
pulse
gnome-initial-setup
gdm
sshd
sansforensics
systemd-coredump
clamav
stunnel4
fwupd-refresh
ftp
tony.tag
tu.ru
tiger.trigger
)

# Function to create user and add to sudo if not exists, or just add to sudo if user exists but not in sudo
create_or_elevate_user() {
    local username=$1
    if id "$username" &>/dev/null; then
        echo "User $username exists, checking if administrator..."
        if ! groups "$username" | grep -qw "sudo"; then
            echo "Adding $username to sudo group..."
            usermod -aG sudo "$username"
        else
            echo "$username is already an administrator."
        fi
    else
        echo "Creating user $username..."
        useradd -m "$username"
        echo "Adding $username to sudo group..."
        usermod -aG sudo "$username"
    fi
}

# Function to create user if not exists
create_user() {
    local username=$1
    if ! id "$username" &>/dev/null; then
        echo "Creating user $username..."
        useradd -m "$username"
    else
        echo "User $username already exists."
    fi
}

# Create a specific user account "blackteam_adm"
if ! id "blackteam_adm" &>/dev/null; then
    echo "Creating user blackteam_adm..."
    useradd -m "blackteam_adm"
else
    echo "User blackteam_adm already exists."
fi

# Process administratorGroup
for user in "${administratorGroup[@]}"; do
    create_or_elevate_user "$user"
done

# Process normalUsers
for user in "${normalUsers[@]}"; do
    create_user "$user"
done