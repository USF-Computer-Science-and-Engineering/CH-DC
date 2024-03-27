#!/bin/bash

sys_upgrades() {
    apt-get --yes --force-yes update
    apt-get --yes --force-yes upgrade
    apt-get --yes --force-yes autoremove
    apt-get --yes --force-yes autoclean
}

unattended_upg() {
    apt-get --yes --force-yes install unattended-upgrades
    dpkg-reconfigure -plow unattended-upgrades
}


user_pass_expirations() {
    perl -npe 's/PASS_MAX_DAYS\s+99999/PASS_MAX_DAYS 180/' -i /etc/login.defs
    perl -npe 's/PASS_MIN_DAYS\s+0/PASS_MIN_DAYS 1/g' -i /etc/login.defs
    perl -npe 's/PASS_WARN_AGE\s+7/PASS_WARN_AGE 14/g' -i /etc/login.defs
}

disable_root() {
    passwd -l root
}

purge_telnet() {
    apt-get --yes purge telnet
}

purge_nfs() {
    apt-get --yes purge nfs-kernel-server nfs-common portmap rpcbind autofs
}

purge_whoopsie() {
    apt-get --yes purge whoopsie
}

set_av() {
    apt-get --yes install chkrootkit clamav
    chkrootkit
    freshclam
    clamscan -ir --exclude-dir=^/sys --exclude-dir=^/dev --exclude-dir=^/proc / &
    sudo systemctl start clamav-freshclam
    }

disable_compilers() {
    chmod 000 /usr/bin/byacc
    chmod 000 /usr/bin/yacc
    chmod 000 /usr/bin/bcc
    chmod 000 /usr/bin/kgcc
    chmod 000 /usr/bin/cc
    chmod 000 /usr/bin/gcc
    chmod 000 /usr/bin/*c++
    chmod 000 /usr/bin/*g++
    # 755 to bring them back online
}

function enable_ufw()
{
	echo -e "\nFirewall Lockdown"
	command -v ufw >/dev/null
	if [ $? -eq 0 ];then
		echo "UFW found enableing firewall."
		ufw enable > /dev/null
	else
		error "UFW not installed."
		read -p "[?] Would you like to install ufw? [y/n] " -n 1 -r
		echo
		if [[ $REPLY =~ ^[Yy]$ ]]
		then
			apt-get install -y ufw
			ufw enable > /dev/null
			echo "UFW is now enabled."
		fi
	fi
}


purge_atd() {
    apt-get --yes purge at
}

disable_avahi() {
    update-rc.d avahi-daemon disable
}

process_accounting() {
    apt-get --yes --force-yes install acct
    cd /
    touch /var/log/wtmp
    cd
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
    sudo systemctl restart apache2
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
    harden_php
    harden_apache
    purge_telnet
    purge_nfs
    purge_whoopsie
    set_av
    process_accounting
    purge_atd
    disable_avahi
    kernel_tuning
    fix_file_permissions
    disable_compilers
}

main "$@"
