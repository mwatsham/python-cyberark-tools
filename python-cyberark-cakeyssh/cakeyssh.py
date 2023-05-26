#!/usr/bin/env python3
# Program: cakeyssh
# Summary: Retrieve a CyberArk SSH secret for a specified account and SSH to specified target host
#          using retrieved SSH key.
# Refs:    Inspiration for interactive SSH session -
#          https://github.com/paramiko/paramiko/blob/main/demos/interactive.py
import socket
from io import StringIO
import getpass
import paramiko
import requests
# Suppress "InsecureRequestWarning: Unverified HTTPS request is being made to host" warning
requests.packages.urllib3.disable_warnings()

CYBERARK_FQDN = "vault.example.com"
SSH_KEY_TYPE = "RSA"
LOGIN_PATH = "PasswordVault/API/auth/RADIUS/Logon"
ACCOUNTS_PATH = "PasswordVault/api/Accounts"


# Function: posix_shell
# Handles interactive SSH session
def _posix_shell(chan):
    import select
    import termios
    import sys
    import tty
    import socket
    from paramiko.util import u

    # Capture tty attributes for current terminal session.
    oldtty = termios.tcgetattr(sys.stdin)
    try:
        # Change the mode of the file descriptor `stdin` to 'raw'.
        # Remapping of interrupt signals
        tty.setraw(sys.stdin.fileno())

        # Change the mode of file descriptor 'stdin' to 'cbreak'.
        # Disable echo and fetch user input.
        tty.setcbreak(sys.stdin.fileno())

        # Set a timeout on blocking read/write operations.
        # chan.settimeout(0.0) is equivalent to chan.setblocking(0).
        # setblocking(0) means the channel is set to non-blocking mode. If a `recv` call doesn’t
        # find any data, or if a `send` call can’t immediately dispose of the data, an error exception is raised.
        chan.settimeout(0.0)

        while True:
            # Interface to the Unix select() system call. The first three arguments are iterables of ‘waitable objects’.
            # `rlist`: wait until ready for reading, `wlist`: wait until ready for writing `xlist`: wait for
            # an “exceptional condition”. The return value is a triple of lists of objects that are ready.
            r, w, e = select.select([chan, sys.stdin], [], [])

            # If `chan` file object is ready for read
            if chan in r:
                try:
                    x = u(chan.recv(1024))
                    if len(x) == 0:
                        sys.stdout.write("\r\n*** End of Session, TTFN!\r\n")
                        break
                    sys.stdout.write(x)
                    sys.stdout.flush()
                except socket.timeout:
                    pass
            if sys.stdin in r:
                x = sys.stdin.read(1)
                if len(x) == 0:
                    break
                chan.send(x)

    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, oldtty)


def _parse_args():
    import argparse

    parser = argparse.ArgumentParser(
        prog='cakeyssh',
        description="Retrieve SSH Key and create SSH pem file",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument(
        "username",
        help="Username of CyberArk account entry")
    parser.add_argument(
        "address",
        help="Address of CyberArk account entry")
    parser.add_argument(
        "safe",
        help="Name of CyberArk Safe containing account entry")
    parser.add_argument(
        "hostname",
        help="Hostname of SSH host")
    parser.add_argument(
        "--cyberark-fqdn",
        help="FQDN of CyberArk instance",
        default=CYBERARK_FQDN)
    parser.add_argument(
        "--ssh-key-type",
        help="SSH key type",
        choices=['RSA', 'DSS', 'ECDSA', 'Ed25519'],
        default=SSH_KEY_TYPE)

    return parser.parse_args()


def _retrieve_session_token(username, password, url):

    try:
        session_response = requests.post(
            url,
            data={'Username': username, 'Password': password},
            verify=False)
    except requests.exceptions.RequestException as e:
        raise SystemExit(f'Failed to retrieve CyberArk account ID: {e}')

    return session_response.json()


def _retrieve_account_id(account_name, account_address, safe, url, session_token):

    try:
        accounts_response = requests.get(
            url,
            headers={'Authorization': session_token},
            params={'search': account_name, 'filter': f'safeName eq {safe}'},
            verify=False)
    except requests.exceptions.RequestException as e:
        raise SystemExit(f'Failed to retrieve CyberArk account ID: {e}')

    matched_id = ''
    try:
        matched = accounts_response.json()
        for account in matched['value']:
            if account['address'] == account_address:
                matched_id = account['id']
        if not matched_id:
            raise ValueError(f'Username: {account_name}, Address: {account_address}')
    except ValueError as e:
        raise SystemExit(f'Account search error: Specified account "{e}" not found')

    return matched_id


def _retrieve_ssh_key(url, session_token):
    # Send the request to retrieve the SSH key
    try:
        ssh_retrieval_response = requests.post(
            url,
            headers={'Authorization': session_token},
            verify=False)
    except requests.exceptions.RequestException as e:
        raise SystemExit(f'Failed to retrieve SSH key: {e}')

    ssh_key = ssh_retrieval_response.text + '\n'

    return ssh_key


# Execute when the module is not initialized from an import statement.
if __name__ == '__main__':
    args = _parse_args()

    # CyberArk REST API endpoint for retrieving session token
    login_url = f'https://{args.cyberark_fqdn}/{LOGIN_PATH}'
    # CyberArk REST API endpoint for retrieving an SSH key
    get_accounts_url = f'https://{args.cyberark_fqdn}/{ACCOUNTS_PATH}'

    try:
        api_username = str(input('Enter CyberArk API username: '))
        api_password = str(getpass.getpass(prompt='Enter CyberArk API password: ', stream=None))
        if not api_username:
            raise ValueError('empty username')
        if not api_password:
            raise ValueError('empty password')
    except ValueError as error:
        raise SystemExit(f'Input Error: {error}')
    except Exception as error:
        raise SystemExit(f'Error: {error}')

    # Retrieve CyberArk session token
    cyberark_session_token = _retrieve_session_token(api_username, api_password, login_url)

    # Retrieve CyberArk account id number for specified `username`
    cyberark_account_id = _retrieve_account_id(args.username, args.address, args.safe, get_accounts_url, cyberark_session_token)

    ssh_retrieval_url = f'{get_accounts_url}/{cyberark_account_id}/Secret/Retrieve'

    # Retrieve SSH key secret for specified `username` account and create a in-memory file-like object.
    private_key = StringIO(_retrieve_ssh_key(ssh_retrieval_url, cyberark_session_token))

    ssh = paramiko.SSHClient()

    # Set SSH key type based on specified type
    if args.ssh_key_type == 'RSA':
        key = paramiko.RSAKey.from_private_key(private_key)
    elif args.ssh_key_type == 'DSS':
        key = paramiko.DSSKey.from_private_key(private_key)
    elif args.ssh_key_type == 'ECDSA':
        key = paramiko.ECDSAKey.from_private_key(private_key)
    elif args.ssh_key_type == 'Ed25519':
        key = paramiko.Ed25519Key.from_private_key(private_key)

    # Automatically adds the hostname and new host key to the local HostKeys
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Initiate SSH connection
    try:
        ssh.connect(hostname=args.hostname, username=args.username, pkey=key)
    except TimeoutError as e:
        raise SystemExit(f'SSH connection timed-out: {e}')
    except socket.gaierror as e:
        raise SystemExit(f'Unable to resolve target host name: {e}')
    except paramiko.ssh_exception.AuthenticationException as e:
        raise SystemExit(f'Target host authentication error: {e}')

    # Get a Channel object which is used for data transfer.
    chan = ssh.get_transport().open_session()
    # Request a pseudo-terminal from the server.
    chan.get_pty()


    # Create interactive SSH shell
    chan.invoke_shell()
    _posix_shell(chan)

    ssh.close()
