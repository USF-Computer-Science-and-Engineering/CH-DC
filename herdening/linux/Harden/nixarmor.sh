#!/bin/bash

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


fix_file_permissions() {
    cat /root/CH-DC/herdening/linux/Harden/fileperms.txt | bash 2>/dev/null
}


main() {
    harden_php
    harden_apache
    disable_compilers
    fix_file_permissions
}

main "$@"

