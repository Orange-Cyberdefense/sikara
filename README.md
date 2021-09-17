# Sikara - Active Directory Hunting #


## Intro ##

Sikara has been developed in order to ease and assist the compromise of an Active Directory environment.

The idea behind the tool is to centralize and automate a certain number of tasks and checks in order to, in the best case, compromise a Domain Admin account.
Instead of starting from scratch and developing every request with the Python's lib Impacket, I chose to use basic tools that are available on every basic Kali distribution. 


## Features ##

- Unauthenticated (anonymous) domain users enumeration over RPC 
	
- Domain information gathering (domain name, account lockout policy, list of nested domain admins)

- Password spraying

- SMB servers scanning

- Admin rights enumeration

- Built-in local admin password reuse hunting

- SAM and LSA dumping


## Installation ##

```
python3 -m pip install -r requirements.txt
```

Sikara works with **rich** Python library for terminal formatting.
Also, it works with other tools (requirement check at launch).Make sure the following are available : **rpcclient**, **smbclient**, **polenum**, **ldapsearch**, **nmap**, **crackmapexec**.

For now, the call to **crackmapexec** is hardcoded and I used `cme`. Indeed, `crackmapexec` is the old version for me and `cme` is the newly installed one.
Make sure `cme` is the latest version with lsassy module available.


## Usage ##

```
Usage: sikara.py dc-ip [options]

Options:
  -h, --help      show this help message and exit
  -u USERS        File containing the list of users if automatic users
                  enumeration failed.
  -p PASSWORD     Password to test for password spray. Default: test login as
                  password.
  -d DOMAIN       Domain name if different from default domain on DC.
  -t TARGETS      Subnet to target when enumerating user's rights on machines.
                  Default: subnet /24 of the DC.
  -f TARGETSFILE  File containing targets to enumerate user's rights on
                  machines (one per line). Default: subnet /24 of the DC.
```	

Sikara first tries to enumerate domain users through anonymous RPC connection to the domain controller. If it fails, it uses the embedded file **common_users.txt** for the further password spray. This file contains generic account names that have been regularly found throughout internal pentests. The user can provide a file containing domain users instead of trying anonymous enumeration.

The tool checks for previous password sprays and prevents locking out all domain accounts, according to the domain lockout policy it has retrieved. It then performs a password spray, either with login as password (default) or with the password provided with `-p PASSWORD` option.

Preparing the next phase, the tool enumerates SMB hosts on the /24 subnetwork of the domain controller (default) or on the subnetwork given with `-t TARGETS` option. The hosts are gathered inside *targets.txt* file. As it can take some time, `-f TARGETSFILE` option is available if you previously ran the tool and want to skip that check.

If any valid user is found, the tool enumerates its admin rights on the previous scope. 

If any admin right is found on the SMB hosts, the tool dumps the built-in local administrator account hashes. For now, only **built-in administator account (RID 500)** is dumped (won't work if the account is disabled).

The tool then checks for any password reuse on SMB hosts and then dumps cached domain credentials with lsassy module, hunting for domain admins.