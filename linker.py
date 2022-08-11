#!/usr/bin/env python3
import os
import re
import argparse

from time import time
from binascii import unhexlify
from operator import attrgetter
from decimal import getcontext, Decimal

tab = " "*4
hashesRegex = re.compile("((?P<domain>[^\\\\]+)\\\\)?(?P<accName>[^:\$]+)(?P<machine>\$)?:\d+:[a-fA-F0-9]{32}:(?P<ntHash>[a-fA-F0-9]{32}):::(\s*\(status=(?P<accStatus>Dis|En)abled\))?")

class Account(object):
	def __init__(self, name, ntHash, status=True, domain=""):
		self.name = name
		self.ntHash = ntHash
		self.status = status
		self.domain = domain
		self.password = None

	def findPassword(self, cracked):
		if(self.ntHash in cracked):
			self.password = cracked[self.ntHash]
			if(self.password.startswith("$HEX[") and self.password.endswith("]")):
				self.password = unhexlify(self.password[5:-1]).decode("latin-1")

		return self.password is not None
	
	def __repr__(self):
		return "{}".format(self.name)

	def __str__(self):
		return "{}".format(self.name)
		
def getContent(dump, cracked, **kwargs):
	with open(dump,'r') as f:
		accounts = set()
		content = set(f.read().split("\n"))
		for line in content:
			if(not line):
				continue
			match = hashesRegex.match(line)
			if(not match):
				if(kwargs["verbose"]):
					print("Error parsing: {}".format(line))
				continue
			else:
				accName = None
				ntHash = None
				accStatus = True
				domain = ""
				machine = False
				if(match.group("accName")):
					accName = match.group("accName")
				
				if(match.group("machine")):
					if(kwargs["verbose"]):
						print("Skipping machine account: {}".format(accName))
					continue
				
				if(match.group("ntHash")):
					ntHash = match.group("ntHash").lower()
				if(match.group("accStatus") == "Dis"):
					accStatus = False
				if(match.group("domain")):
					domain = match.group("domain").upper()

				accounts.add(Account(name=accName, ntHash=ntHash, status=accStatus, domain=domain))

		f.close()

	with open(cracked,'r') as f:
		crackedDict = {}
		content = set(f.read().split("\n"))
		for line in content:
			if(not line):
				continue
			h, p = line.split(":",1)
			if(not h.lower() in crackedDict):
				crackedDict[h.lower()] = p
		f.close()

	return accounts, crackedDict

def correlation(accounts, crackedDict, **kwargs):
	enabledAcc = set()
	disabledAcc = set()
	uncrackedEnAcc = set()
	uncrackedDisAcc = set()
	passwordCount = {}

	for account in accounts:
		if(kwargs["showMatchingDomain"] and (not account.domain or not account.domain in kwargs["showMatchingDomain"])):
			continue

		if(account.findPassword(crackedDict)):
			if(kwargs["showStats"]):
				if(not account.password in passwordCount):
					passwordCount[account.password] = 0

				passwordCount[account.password] += 1

			if(account.status):
				enabledAcc.add(account)
			else:
				disabledAcc.add(account)
		elif(kwargs["showStats"] or kwargs["showUncracked"]):
			if(account.status):
				uncrackedEnAcc.add(account)
			else:
				uncrackedDisAcc.add(account)
	
	return enabledAcc, disabledAcc, uncrackedEnAcc, uncrackedDisAcc, passwordCount

def findAccountsWithPassword(accounts, password, **kwargs):
	result = set()

	for account in accounts:
		if(account.password == password):
			result.add(account)

	return sorting(result, key=lambda x: x.name, **kwargs)

def findAccountsWithNTHash(accounts, ntHash, **kwargs):
	result = set()

	for account in accounts:
		if(account.ntHash == ntHash):
			result.add(account)

	return sorting(result, key=lambda x: x.name, **kwargs)

def showResults(enabledAcc, disabledAcc, uncrackedEnAcc, uncrackedDisAcc, passwordCount, **kwargs):
	if(kwargs["highlightOnly"]):
		showOnlyEnabled = len([account for account in enabledAcc if ((kwargs["highlightUser"] and account.name.lower() in kwargs["highlightUser"]) or (kwargs["showMatchingPassword"] and  account.password in kwargs["showMatchingPassword"]) or (kwargs["showMatchingNTHash"] and  account.ntHash in kwargs["showMatchingNTHash"]))])
		if(kwargs["showDisabled"]):
			showOnlyDisabled = len([account for account in disabledAcc if ((kwargs["highlightUser"] and account.name.lower() in kwargs["highlightUser"]) or (kwargs["showMatchingPassword"] and  account.password in kwargs["showMatchingPassword"]) or (kwargs["showMatchingNTHash"] and  account.ntHash in kwargs["showMatchingNTHash"]))])
		if(kwargs["showUncracked"]):
			showOnlyUncrackedEnabled = len([account for account in uncrackedEnAcc if ((kwargs["highlightUser"] and account.name.lower() in kwargs["highlightUser"]) or (kwargs["showMatchingPassword"] and  account.password in kwargs["showMatchingPassword"]) or (kwargs["showMatchingNTHash"] and  account.ntHash in kwargs["showMatchingNTHash"]))])
			if(kwargs["showDisabled"]):
				showOnlyUncrackedDisabled = len([account for account in uncrackedDisAcc if ((kwargs["highlightUser"] and account.name.lower() in kwargs["highlightUser"]) or (kwargs["showMatchingPassword"] and  account.password in kwargs["showMatchingPassword"]) or (kwargs["showMatchingNTHash"] and  account.ntHash in kwargs["showMatchingNTHash"]))])

	if(kwargs["highlightOnly"]):
		print("Enabled accounts ({}/{}):".format(showOnlyEnabled, len(enabledAcc)))
	else:
		print("Enabled accounts ({}):".format(len(enabledAcc)))
	for account in sorting(enabledAcc, key=attrgetter('domain', 'name'), **kwargs):
		if(not kwargs["highlightOnly"] or (
			(kwargs["highlightUser"] and account.name.lower() in kwargs["highlightUser"]) or
			(kwargs["showMatchingPassword"] and  account.password in kwargs["showMatchingPassword"]) or 
			(kwargs["showMatchingNTHash"] and  account.ntHash in kwargs["showMatchingNTHash"]))):
			print(formatResult(account, **kwargs))
		
	print("")

	if(kwargs["showDisabled"]):
		if(kwargs["highlightOnly"]):
			print("Disabled accounts ({}/{}):".format(showOnlyDisabled, len(disabledAcc)))
		else:
			print("Disabled accounts ({}):".format(len(disabledAcc)))
		for account in sorting(disabledAcc, key=attrgetter('domain', 'name'), **kwargs):
			if(not kwargs["highlightOnly"] or (
				(kwargs["highlightUser"] and account.name.lower() in kwargs["highlightUser"]) or
				(kwargs["showMatchingPassword"] and  account.password in kwargs["showMatchingPassword"]) or 
				(kwargs["showMatchingNTHash"] and  account.ntHash in kwargs["showMatchingNTHash"]))):
				print(formatResult(account, **kwargs))
	
		print("")

	if(kwargs["showUncracked"]):
		if(kwargs["highlightOnly"]):
			print("Uncracked enabled accounts ({}/{}):".format(showOnlyUncrackedEnabled, len(uncrackedEnAcc)))
		else:
			print("Uncracked enabled accounts ({}):".format(len(uncrackedEnAcc)))
		for account in sorting(uncrackedEnAcc, key=attrgetter('domain', 'name'), **kwargs):
			if(not kwargs["highlightOnly"] or (
				(kwargs["highlightUser"] and account.name.lower() in kwargs["highlightUser"]) or
				(kwargs["showMatchingPassword"] and  account.password in kwargs["showMatchingPassword"]) or 
				(kwargs["showMatchingNTHash"] and  account.ntHash in kwargs["showMatchingNTHash"]))):
				print(formatResult(account, **kwargs))

		print("")

		if(kwargs["showDisabled"]):
			if(kwargs["highlightOnly"]):
				print("Uncracked disabled accounts ({}/{}):".format(showOnlyUncrackedDisabled, len(uncrackedDisAcc)))
			else:
				print("Uncracked disabled accounts ({}):".format(len(uncrackedDisAcc)))
			for account in sorting(uncrackedDisAcc, key=attrgetter('domain', 'name'), **kwargs):
				if(not kwargs["highlightOnly"] or (
					(kwargs["highlightUser"] and account.name.lower() in kwargs["highlightUser"]) or
					(kwargs["showMatchingPassword"] and  account.password in kwargs["showMatchingPassword"]) or 
					(kwargs["showMatchingNTHash"] and  account.ntHash in kwargs["showMatchingNTHash"]))):
					print(formatResult(account, **kwargs))
		
			print("")

	if(kwargs["showMatchingPassword"]):
		accounts = enabledAcc.copy()
		
		if(kwargs["showDisabled"]):
			accounts = accounts.union(disabledAcc)
		
		for password in sorting(kwargs["showMatchingPassword"], **kwargs):
			result = findAccountsWithPassword(accounts, password, **kwargs)
			if(result):
				print("Accounts with password {}".format(password))
				for account in result:
					r = formatResult(account, False, **kwargs)
					if(r):
						print(r)
			else:
				if(kwargs["showDisabled"]):
					print("No account found with password {}".format(password))
				else:
					print("No enabled account found with password {}".format(password))

			print("")

	if(kwargs["showMatchingNTHash"]):
		accounts = enabledAcc.union(disabledAcc, uncrackedEnAcc, uncrackedDisAcc)
		
		for ntHash in sorting(kwargs["showMatchingNTHash"], **kwargs):
			result = findAccountsWithNTHash(accounts, ntHash, **kwargs)
			if(result):
				print("Accounts with NTHash {}".format(ntHash))
				for account in result:
					r = formatResult(account, False, **kwargs)
					if(r):
						print(r)
			else:
				print("No account found with NTHash {}".format(ntHash))

			print("")

	if(kwargs["showStats"]):
		getcontext().prec = 4
		nbEnabled = Decimal(len(enabledAcc))
		nbDisabled = Decimal(len(disabledAcc))
		nbUncrackedEnabled = Decimal(len(uncrackedEnAcc))
		nbUncrackedDisabled = Decimal(len(uncrackedDisAcc))
		nbUncracked = Decimal(len(uncrackedEnAcc) + len(uncrackedDisAcc))
		nbCracked = nbEnabled+nbDisabled
		totalEnabled = nbEnabled+nbUncrackedEnabled
		totalDisabled = nbDisabled+nbUncrackedDisabled
		total = nbEnabled+nbDisabled+nbUncracked

		if(total > 0):
			pCracked = Decimal((nbEnabled/total)*100)
			pCrackedEnabled = Decimal((nbEnabled/totalEnabled)*100)
			pCrackedDisabled = Decimal((nbDisabled/totalDisabled)*100)
			pDisCracked = Decimal((nbDisabled/total)*100)
			pTotalCracked = Decimal(((nbEnabled+nbDisabled)/total)*100)

			print("Statistics:")
			print("{tab}Enabled Accounts".format(tab=tab))
			print("{tab}Number of enabled (en):{padding}{percent}".format(tab=tab*2, padding=" "*(70-27-len(tab)-len(str(nbEnabled))), percent=nbEnabled))
			print("{tab}Number of uncracked enabled (ue):{padding}{percent}".format(tab=tab*2, padding=" "*(70-37-len(tab)-len(str(nbUncrackedEnabled))), percent=nbUncrackedEnabled))
			print("{tab}Total of enabled (te=en+ue):{padding}{percent}".format(tab=tab*2, padding=" "*(70-32-len(tab)-len(str(totalEnabled))), percent=totalEnabled))
			print("{tab}Percentage of cracked (en/te):{padding}{percent}%".format(tab=tab*2, padding=" "*(70-34-len(tab)-len(str(pCrackedEnabled))-1), percent=pCrackedEnabled))
			print("")
			print("{tab}Disabled Accounts".format(tab=tab))
			print("{tab}Number of disabled (dis):{padding}{percent}".format(tab=tab*2, padding=" "*(70-29-len(tab)-len(str(nbDisabled))), percent=nbDisabled))
			print("{tab}Number of uncracked disabled (ud):{padding}{percent}".format(tab=tab*2, padding=" "*(70-38-len(tab)-len(str(nbUncrackedDisabled))), percent=nbUncrackedDisabled))
			print("{tab}Total of disabled (td=dis+ud):{padding}{percent}".format(tab=tab*2, padding=" "*(70-34-len(tab)-len(str(totalDisabled))), percent=totalDisabled))
			print("{tab}Percentage of cracked (dis/td):{padding}{percent}%".format(tab=tab*2, padding=" "*(70-35-len(tab)-len(str(pCrackedDisabled))-1), percent=pCrackedDisabled))
			print("")
			print("{tab}Every Account".format(tab=tab))
			print("{tab}Number of cracked (c=en+dis):{padding}{percent}".format(tab=tab*2, padding=" "*(70-33-len(tab)-len(str(nbCracked))), percent=nbCracked))
			print("{tab}Number of uncracked (uc=ue+ud):{padding}{percent}".format(tab=tab*2, padding=" "*(70-35-len(tab)-len(str(nbUncracked))), percent=nbUncracked))
			print("{tab}Total (t=c+uc):{padding}{percent}".format(tab=tab*2, padding=" "*(70-19-len(tab)-len(str(total))), percent=total))
			print("{tab}Percentage of cracked (en/t):{padding}{percent}%".format(tab=tab*2, padding=" "*(70-33-len(tab)-len(str(pCracked))-1), percent=pCracked))
			print("{tab}Percentage of cracked (dis/t):{padding}{percent}%".format(tab=tab*2, padding=" "*(70-34-len(tab)-len(str(pDisCracked))-1), percent=pDisCracked))
			print("{tab}Percentage of cracked ((en+dis)/t):{padding}{percent}%".format(tab=tab*2, padding=" "*(70-39-len(tab)-len(str(pTotalCracked))-1), percent=pTotalCracked))
			print("")
			print("{tab}Password count:".format(tab=tab))

			for k, v in dict(sorting(passwordCount.items(), key=lambda x: x[1], reverse=True, **kwargs)).items():
				if(v > 1):
					print("{tab}{password}{padding}{value}".format(tab=tab*2, password=k, padding=" "*(70-len(tab*2) - len(k) - len(str(v))), value=v))

			print("")
		else:
			print("Can't show stats if the total number of accounts is 0...")

def formatResult(account, showPassword=True, **kwargs):
	p = ""
	result = ""
	if(kwargs["showDomain"] and account.domain):
		p += account.domain
		p += "\\"
	
	p += account.name

	if(kwargs["showNTHash"]):
		p += ":"
		p += account.ntHash
		p += ":"

	if(showPassword and account.password):
		if(kwargs["highlightUser"] and account.name.lower() in kwargs["highlightUser"]):
			if(account.status):
				result = "\033[92m{tab}{accInfo}{padding}{password}\033[00m".format(tab=tab, accInfo=p, padding=" "*(100 - len(tab) - len(p) - len(account.password)), password=account.password)
			else:
				result = "\033[91m{tab}{accInfo}{padding}{password}\033[00m".format(tab=tab, accInfo=p, padding=" "*(100 - len(tab) - len(p) - len(account.password)), password=account.password)
		elif(kwargs["showMatchingPassword"] and  account.password in kwargs["showMatchingPassword"]):
			if(account.status):
				result = "\033[93m{tab}{accInfo}{padding}{password}\033[00m".format(tab=tab, accInfo=p, padding=" "*(100 - len(tab) - len(p) - len(account.password)), password=account.password)
			else:
				result = "\033[91m{tab}{accInfo}{padding}{password}\033[00m".format(tab=tab, accInfo=p, padding=" "*(100 - len(tab) - len(p) - len(account.password)), password=account.password)
		elif(kwargs["showMatchingNTHash"] and  account.ntHash in kwargs["showMatchingNTHash"]):
			if(account.status):
				result = "\033[93m{tab}{accInfo}{padding}{password}\033[00m".format(tab=tab, accInfo=p, padding=" "*(100 - len(tab) - len(p) - len(account.password)), password=account.password)
			else:
				result = "\033[91m{tab}{accInfo}{padding}{password}\033[00m".format(tab=tab, accInfo=p, padding=" "*(100 - len(tab) - len(p) - len(account.password)), password=account.password)
		else:
			result = "{tab}{accInfo}{padding}{password}".format(tab=tab, accInfo=p, padding=" "*(100 - len(tab) - len(p) - len(account.password)), password=account.password)
	else:
		if(kwargs["highlightUser"] and account.name.lower() in kwargs["highlightUser"]):
			if(account.status and account.password):
				result = "\033[92m{tab}{accInfo}\033[00m".format(tab=tab, accInfo=p)
			else:
				result = "\033[91m{tab}{accInfo}\033[00m".format(tab=tab, accInfo=p)
		elif(kwargs["showMatchingPassword"] and account.password in kwargs["showMatchingPassword"]):
			if(account.status and account.password):
				result = "\033[92m{tab}{accInfo}\033[00m".format(tab=tab, accInfo=p)
			else:
				result = "\033[91m{tab}{accInfo}\033[00m".format(tab=tab, accInfo=p)
		elif(kwargs["showMatchingNTHash"] and account.ntHash in kwargs["showMatchingNTHash"]):
			if(account.status):
				result = "\033[92m{tab}{accInfo}\033[00m".format(tab=tab, accInfo=p)
			else:
				result = "\033[91m{tab}{accInfo}\033[00m".format(tab=tab, accInfo=p)
		else:
			result = "{tab}{accInfo}".format(tab=tab, accInfo=p)

	return result

def sorting(var, key=None, reverse=False, **kwargs):
	if(kwargs["performance"]):
		return var
	else:
		return sorted(var, key=key, reverse=reverse)


if __name__=='__main__':
	parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument(metavar="dump_file", dest="dump", help="Dump file.\nLine format : [DOMAIN\\]USERNAME:USERID:LM:NT::: (status=(Dis|En)abled)", type=str)
	parser.add_argument(metavar="cracked_file", dest="cracked", help="Cracked hash file.", type=str)
	parser.add_argument("-a", "--all", dest="all", help="Show everything.", action="store_true")
	parser.add_argument("-v", "--verbose", dest="verbose", help="Verbose mode.", action="store_true")
	parser.add_argument("-i", "--disabled", dest="showDisabled", help="Show disabled in the result.\nDefault status is 'enabled' if not present in hashes file.", action="store_true")
	parser.add_argument("-u", "--uncracked", dest="showUncracked", help="Show uncracked accounts in the result.", action="store_true")
	parser.add_argument("-n", "--nthash", dest="showNTHash", help="Show NTHash in the result.", action="store_true")
	parser.add_argument("-d", "--showdomain", dest="showDomain", help="Show domain in the result.", action="store_true")
	parser.add_argument("-s", "--stats", dest="showStats", help="Show statistics in the result.", action="store_true")
	parser.add_argument("-D", "--domain", dest="showMatchingDomain", help="Show only matching domain  (can be one domain or a file splitted by newline).", type=str.upper, default=None)
	parser.add_argument("-P", "--password", dest="showMatchingPassword", help="Show matching password in the result. (can be one password or a file splitted by newline)", type=str, default=None)
	parser.add_argument("-N", "--hash", dest="showMatchingNTHash", help="Show matching hash in the result (can be one hash or a file splitted by newline).", type=str.lower,default=None)
	parser.add_argument("-U", "--user", dest="highlightUser", help="Highlight matching user in the result (can be one user or a file splitted by newline).", type=str.lower,default=None)
	parser.add_argument("-H", "--highlight-only", dest="highlightOnly", help="Show only highlists results (requires showMatchingDomain, showMatchingPassword, showMatchingNTHash or highlightUser).", action="store_true")
	parser.add_argument("-p", "--performance", dest="performance", help="Need more performance? This will NOT sort the results.", action="store_true")
	parser.add_argument("-t", "--time", dest="time", help="Print the elasped time to run the script.", action="store_true")
	args = parser.parse_args()

	if(args.time or args.verbose):
		startTime = Decimal(time())

	if(args.showMatchingDomain):
		if(os.path.isfile(args.showMatchingDomain)):
			with open(args.showMatchingDomain, 'r') as f:
				args.showMatchingDomain = f.read().split("\n")
		else:
			args.showMatchingDomain = [args.showMatchingDomain]

	if(args.showMatchingPassword):
		if(os.path.isfile(args.showMatchingPassword)):
			with open(args.showMatchingPassword, 'r') as f:
				args.showMatchingPassword = f.read().split("\n")
		else:
			args.showMatchingPassword = [args.showMatchingPassword]

	if(args.showMatchingNTHash):
		if(os.path.isfile(args.showMatchingNTHash)):
			with open(args.showMatchingNTHash, 'r') as f:
				args.showMatchingNTHash = f.read().split("\n")
		else:
			args.showMatchingNTHash = [args.showMatchingNTHash]

	if(args.highlightUser):
		if(os.path.isfile(args.highlightUser)):
			with open(args.highlightUser, 'r') as f:
				args.highlightUser = f.read().split("\n")
		else:
			args.highlightUser = [args.highlightUser]

	if(args.highlightOnly):
		if(args.showMatchingDomain or args.showMatchingPassword or args.showMatchingNTHash or args.highlightUser):
			args.highlightOnly = True
		else:
			args.highlightOnly = False


	if(args.all):
		args.showDisabled = True
		args.showUncracked = True
		args.showNTHash = True
		args.showDomain = True
		args.showStats = True

	if(args.dump and (not os.path.exists(args.dump) or not os.path.isfile(args.dump))):
		raise FileNotFoundError("{} was not found.".format(args.dump))
	if(args.cracked and (not os.path.exists(args.cracked) or not os.path.isfile(args.cracked))):
		raise FileNotFoundError("{} was not found.".format(args.cracked))

	(enabledAcc, disabledAcc, uncrackedEnAcc, uncrackedDisAcc, passwordCount) = correlation(*getContent(**vars(args)), **vars(args))
	showResults(enabledAcc, disabledAcc, uncrackedEnAcc, uncrackedDisAcc, passwordCount, **vars(args))

	if(args.time or args.verbose):
		endTime = Decimal(time())

		print("Elasped time: {}s".format(endTime-startTime))
