
import getpass
import ssh2
import argparse

from pssh.clients import ParallelSSHClient
from pssh.exceptions import AuthenticationException, ConnectionErrorException, Timeout


def handler(client, cmd, stdin=[]):
    try:
        output = client.run_command(cmd, stop_on_errors=False)

        for host in output:
            if not host.exception:
                for x in stdin:
                    host.stdin.write(x + "\n")
                    host.stdin.flush()

                print(f"Ran '{cmd}' on: {host.host}")
                for x in host.stderr:
                    print(x)
            else:
                print(f"Failed to run on {cmd} {host.host} - {host.exception}")

    except Exception as e:
       print("really bad if this hits") 


def init_hosts(client):
    passwd = getpass.getpass("Enter the new passphrase for all users (except for logging blackteam_adm): ")

    handler(client, 'apt install git tmux wget vim -y || yum install git tmux wget vim -y')
    handler(client, 'bash /root/CH-DC/herdening/linux/ThreatHunting/alias.sh')
    handler(client, 'bash /root/CH-DC/herdening/linux/Harden/configureSSH.sh')
    handler(client, 'bash /root/CH-DC/herdening/linux/Harden/credentialRotate.sh', stdin=[passwd, "\n\n\n\n\n\n\n",])

def passwd(client):
    passwd = getpass.getpass("Enter the new passphrase for all users (except for logging blackteam_adm): ")
    handler(client, 'bash /root/CH-DC/herdening/linux/Harden/credentialRotate.sh', stdin=[passwd, "\n\n\n\n\n\n\n",])


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('hosts')
    parser.add_argument('func')
    parser.add_argument('-u', '--user')
    parser.add_argument('-p', '--password', required=False)

    args = parser.parse_args()

    try:
        with open(args.hosts, "r") as f:
            hosts = f.read().splitlines()
    except Exception as e:
        print(f"Failed to read {hosts}, {e}")

    if not args.password:
        getpass.getpass(f"{args.user}'s Password: ")

    client = ParallelSSHClient(hosts, user=args.user, password=args.password)


    if "init" in args.func.lower():
        init_hosts(client)
    elif "passwd" in args.func.lower():
        passwd(client)


main()