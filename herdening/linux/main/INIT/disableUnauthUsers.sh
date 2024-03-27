#!/bin/bash
# Goal of this script is to find users that are unauthorized, with a login shell.
valid_shells=(/bin/bash /bin/sh /usr/bin/zsh /usr/bin/fish /usr/bin/bash /usr/bin/sh /bin/rbash /usr/bin/rbash)

# Script can take 3 arguements (ie bash deleteUnauthorizedLoginShellUsers.sh root root1 root2)
predefined_users=(
$1
$2
$3
seccdc_black
postgres
root
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
)

while IFS=: read -r username _ _ _ _ _ shell; do
    for valid_shell in "${valid_shells[@]}"; do
        if [[ "$shell" == "$valid_shell" ]]; then
            if ! printf '%s\n' "${predefined_users[@]}" | grep -qx "$username"; then
                echo "User '$username' is NOT in the predefined list but has a valid shell: $shell"
                pkill -KILL -u $username
                usermod -s /usr/sbin/nologin $username || usermod -s /sbin/nologin $username
            fi
            break
        fi
    done
done < /etc/passwd
