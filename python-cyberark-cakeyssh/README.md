# cakeyssh
## Summary
Retrieve a CyberArk SSH secret for a specified account and create an interactive SSH session to a specified target host.

## Example usage
```
cakeyssh.py \
  <CyberArk account name for SSH secret> \
  <Address of CyberArk account entry> \
  <CyberArk safe name> \
  <Target hostname/IP> \
  --cyberark-fqdn=<FQDN of CyberArk instance> \ 
  --ssh-key-type=['RSA', 'DSS', 'ECDSA', 'Ed25519']
```
```
$ cakeyssh.py my-ssh-user my-entry-address my-safe my.host.com --cyberark-fqdn=vault.example.com
Enter CyberArk API username:
Enter CyberArk API password:
```
# Refs
* Inspiration for interactive SSH session - https://github.com/paramiko/paramiko/blob/main/demos/interactive.py
