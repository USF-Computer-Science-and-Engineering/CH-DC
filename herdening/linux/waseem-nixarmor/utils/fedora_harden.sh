#!/bin/bash


sys_upgrades() {
    yum -y update
    yum -y upgrade
    yum -y autoremove
}

unattended_upg() {
    yum -y install yum-cron
    chkconfig --level 345 yum-cron on
    service yum-cron start
}

disable_root() {
    passwd -l root
    # sudo passwd -l root
}

set_av() {
    yum -y install chkrootkit clamav
    chkrootkit
    freshclam
    clamscan -ir --exclude-dir=^/sys --exclude-dir=^/dev --exclude-dir=^/proc /
    sudo systemctl start clamav-freshclam
}

user_pass_expirations() {
    perl -npe 's/PASS_MAX_DAYS\s+99999/PASS_MAX_DAYS 180/' -i /etc/login.defs
    perl -npe 's/PASS_MIN_DAYS\s+0/PASS_MIN_DAYS 1/g' -i /etc/login.defs
    perl -npe 's/PASS_WARN_AGE\s+7/PASS_WARN_AGE 14/g' -i /etc/login.defs
}

remove_atd() {
    yum -y remove at
    # less layers equals more security
}

permission_narrowing() {
    chmod 700 /root
    chmod 700 /var/log/audit
    chmod 740 /etc/rc.d/init.d/iptables
    chmod 740 /sbin/iptables
    chmod -R 700 /etc/skel
    chmod 600 /etc/rsyslog.conf
    chmod 640 /etc/security/access.conf
    chmod 600 /etc/sysctl.conf
}

disable_avahi(){
    systemctl stop avahi-daemon.socket avahi-daemon.service
    systemctl disable avahi-daemon.socket avahi-daemon.service
}

disable_postfix() {
    systemctl stop postfix
    systemctl disable postfix
}


fix_file_permissions() {
    cat /root/fileperms.txt | bash 2>/dev/null
}


harden_php(){
    for i in $(find / -name php.ini 2>/dev/null); do 
	    perl -npe 's/display_errors\s+=\s+On/display_errors = Off/' -i $i;
	    perl -npe 's/log_errors\s+=\s+Off/log_errors = On/' -i $i;
	    perl -npe 's/file_uploads\s+=\s+On/file_uploads = Off/' -i $i;
	    perl -npe 's/allow_url_fopen\s+=\s+On/allow_url_fopen = Off/' -i $i;
	    perl -npe 's/allow_url_include\s+=\s+On/allow_url_include = Off/' -i $i;
	    perl -npe 's/sql.safe_mode\s+=\s+Off/sql.safe_mode = On/' -i $i;
	    perl -npe 's/magic_quotes_gpc\s+=\s+On/magic_quotes_gpc = Off/' -i $i;
	    perl -npe 's/max_execution_time\s+=\s+30/max_execution_time = 30/' -i $i;
	    perl -npe 's/max_input_time\s+=\s+60/max_input_time = 30/' -i $i;
	    perl -npe 's/memory_limit\s+=\s+-1/memory_limit = 40M/' -i $i;
	    perl -npe 's/magic_quotes_gpc\s+=\s+On/magic_quotes_gpc = Off/' -i $i;
        perl -npe 's/disable_functions\s+=.*/disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,eval,system,shell_exec,passthru,exec,popen,proc_open,proc_close,proc_terminate,proc_get_status,ini_set,phpinfo,show_source,symlink,link,dl,popen,curl_exec,curl_multi_exec,parse_ini_file,parse_ini_string,assert,pcntl_exec/' -i $i;
done
}

harden_apache(){
    for i in $(find / -name security.conf 2>/dev/null); do 
        perl -npe 's/ServerTokens\s+OS/ServerTokens Prod/' -i $i;
        perl -npe 's/ServerSignature\s+On/ServerSignature Off/' -i $i;
done
    systemctl restart apache2
}

kernel_tuning() {
    sysctl kernel.randomize_va_space=1
    sysctl kernel.kptr_restrict=1
    sysctl -w fs.protected_hardlinks=1
    sysctl -w fs.protected_symlinks=1
    sysctl -w fs.suid_dumpable=0
    sysctl net.ipv6.conf.all.disable_ipv6=1
    sysctl net.ipv6.conf.default.disable_ipv6=1
    sysctl net.ipv6.conf.lo.disable_ipv6=1
    sysctl net.ipv6.conf.all.rp_filter=1
    sysctl net.ipv4.conf.all.rp_filter=1
    sysctl net.ipv4.conf.all.accept_source_route=0
    sysctl net.ipv4.icmp_echo_ignore_broadcasts=1
    sysctl net.ipv4.conf.all.log_martians=1
    sysctl net.ipv4.conf.default.log_martians=1
    sysctl -w net.ipv4.conf.all.accept_redirects=0
    sysctl -w net.ipv6.conf.all.accept_redirects=0
    sysctl -w net.ipv4.conf.all.send_redirects=0
    sysctl kernel.sysrq=0
    sysctl net.ipv4.tcp_timestamps=0
    sysctl net.ipv4.tcp_syncookies=1
    sysctl net.ipv4.icmp_ignore_bogus_error_responses=1
    sysctl net.ipv4.tcp_syn_retries=2
    sysctl net.ipv4.tcp_synack_retries=2
    sysctl net.ipv4.tcp_max_syn_backlog=2048
    sysctl net.ipv4.tcp_rfc1337=1
    sysctl -p
}

main() {
    sys_upgrades
    unattended_upg
    set_av
    remove_atd
    harden_php
    harden_apache
    disable_avahi
    disable_postfix
    kernel_tuning
    fix_file_permissions
    permission_narrowing
}

main "$@"
