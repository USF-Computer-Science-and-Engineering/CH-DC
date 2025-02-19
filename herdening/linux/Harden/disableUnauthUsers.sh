#!/bin/bash
# Goal of this script is to find users that are unauthorized, with a login shell.
valid_shells=(/bin/bash /bin/sh /usr/bin/zsh /usr/bin/fish /usr/bin/bash /usr/bin/sh /bin/rbash /usr/bin/rbash)

# Script can take 3 arguements (ie bash deleteUnauthorizedLoginShellUsers.sh root root1 root2)
predefined_users=(
$1
$2
$3
blackteam_adm
root
postgres
jeremy.rover # admin users
maxwell.starling
jack.harris
emily.chen
william.wilson
melissa.chen
john.taylor
laura.harris
alan.chen
anna.wilson
matthew.taylor
danielle.wilson # normal users
ashley.lee
alan.taylor
dave.harris
tom.harris
christine.wilson
tony.taylor
amy.wilson
tiffany.harris
emily.lee
heather.chen
mark.wilson
amy.wilson
jeff.taylor
sarah.taylor
alan.harris
tiffany.wilson
terry.chen
amy.taylor
chris.harris
james.taylor
rachel.harris
kathleen.chen
julie.wilson
michael.chen
emily.lee
sharon.harris
rachel.wilson
terry.wilson
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
