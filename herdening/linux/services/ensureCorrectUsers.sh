#!/bin/bash

# The usage of this script, is a repeating loop that ensures the required users exist with admin access.
while true; do
    ###################################################### SCORECHECK USER #################################################
    DONOTTOUCH=(
    blackteam_adm
    )
    ###################################################### SCORECHECK USER #################################################

s
    ###################################################### Delete users ###################################################
    valid_shells=(/bin/bash /bin/sh /usr/bin/zsh /usr/bin/fish)

    predefined_users=(
    $1
    $2
    $3
    root
    blackteam_adm
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
                    pkill --signal SIGKILL -u $username
                    userdel -r $username || deluser $username --remove-home
                fi
                break
            fi
        done
    done < /etc/passwd

    ###################################################### ADMINS #################################################
    administratorGroup=( 
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
    root
    )

    for admin in "${administratorGroup[@]}"; do
        if ! id "$admin" &>/dev/null; then
            useradd -m "$admin"
            echo "User $admin created."
        fi

        if ! id "$admin" | grep -qw sudo; then
            usermod -aG sudo "$admin"
            echo "$admin added to sudo group."
        fi
    done


    ###################################################### NORMAL USERS #################################################
    normalUsers=( 
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

    ############################## ADDING AND REMOVING ADMINISTRATORS

    echo "######Ensuring normal users exist and are not part of the sudo group#####"
    for user in "${normalUsers[@]}"; do
        if ! id "$user" &>/dev/null; then
            useradd -m "$user"
            echo "User $user created."
        fi
        if id "$user" | grep -qw 'sudo'; then
            gpasswd -d "$user" sudo
            echo "Removed $user from the sudo group."
        fi
    done

    sleep 30
done
