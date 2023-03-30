#!/usr/bin/env python3
import os
import re
from sys import maxsize as INT_MAXSIZE
import argparse
import decimal

from time import time
from binascii import unhexlify
from operator import attrgetter

tab = " "*4
hashesRegex = re.compile("((?P<domain>[^\\\\]+)\\\\)?(?P<accName>[^:\$]+)(?P<machine>\$)?:\d+:[a-fA-F0-9]{32}:(?P<ntHash>[a-fA-F0-9]{32}):::(\s*\(status=(?P<accStatus>Dis|En)abled\))?")

class Account(object):
	def __init__(self, name, ntHash, status=True, domain=""):
		self.name = name.lower()
		self.ntHash = ntHash.lower()
		self.status = status
		self.domain = domain.upper()
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
					ntHash = match.group("ntHash")
				if(match.group("accStatus") == "Dis"):
					accStatus = False
				if(match.group("domain")):
					domain = match.group("domain")

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

		crackedDict['31d6cfe0d16ae931b73c59d7e0c089c0'] = '[Empty Password]'

	return accounts, crackedDict

def correlation(accounts, crackedDict, **kwargs):
	enabledAcc = set()
	disabledAcc = set()
	uncrackedEnAcc = set()
	uncrackedDisAcc = set()
	passwordCount = dict()

	for account in accounts:
		if((kwargs["showMatchingDomain"] and (not account.domain or not kwargs["showMatchingDomain"].match(account.domain))) and
			(kwargs["showMatchingDomainsFile"] and (not account.domain or not account.domain in kwargs["showMatchingDomainsFile"]))):
			continue

		if(account.findPassword(crackedDict)):
			if(kwargs["showStats"]):
				if(not account.password in passwordCount):
					passwordCount[account.password] = {True:0, False:0}

				passwordCount[account.password][account.status] += 1

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
	isRegex = type(ntHash) == re.Pattern
	for account in accounts:
		if((isRegex and ntHash.match(account.ntHash)) or account.ntHash == ntHash):
			result.add(account)

	return sorting(result, key=lambda x: x.name, **kwargs)

def showResults(enabledAcc, disabledAcc, uncrackedEnAcc, uncrackedDisAcc, passwordCount, **kwargs):
	showOnlyEnabled = 0
	showOnlyDisabled = 0
	showOnlyUncrackedEnabled = 0
	showOnlyUncrackedDisabled = 0
	if(kwargs["highlightOnly"]):
		showOnlyEnabled = len([account for account in enabledAcc if ((kwargs["highlightUser"] and kwargs["highlightUser"].match(account.name)) or (kwargs["highlightUsersFile"] and account.name in kwargs["highlightUsersFile"]) or (kwargs["showMatchingPassword"] and  account.password in kwargs["showMatchingPassword"]) or (kwargs["showMatchingNTHash"] and  kwargs["showMatchingNTHash"].match(account.ntHash)) or (kwargs["showMatchingNTHashesFile"] and account.ntHash in kwargs["showMatchingNTHashesFile"]))])
		if(kwargs["showDisabled"]):
			showOnlyDisabled = len([account for account in disabledAcc if ((kwargs["highlightUser"] and kwargs["highlightUser"].match(account.name)) or (kwargs["highlightUsersFile"] and account.name in kwargs["highlightUsersFile"]) or (kwargs["showMatchingPassword"] and  account.password in kwargs["showMatchingPassword"]) or (kwargs["showMatchingNTHash"] and  kwargs["showMatchingNTHash"].match(account.ntHash)) or (kwargs["showMatchingNTHashesFile"] and account.ntHash in kwargs["showMatchingNTHashesFile"]))])
		if(kwargs["showUncracked"]):
			showOnlyUncrackedEnabled = len([account for account in uncrackedEnAcc if ((kwargs["highlightUser"] and kwargs["highlightUser"].match(account.name)) or (kwargs["highlightUsersFile"] and account.name in kwargs["highlightUsersFile"]) or (kwargs["showMatchingPassword"] and  account.password in kwargs["showMatchingPassword"]) or (kwargs["showMatchingNTHash"] and  kwargs["showMatchingNTHash"].match(account.ntHash)) or (kwargs["showMatchingNTHashesFile"] and account.ntHash in kwargs["showMatchingNTHashesFile"]))])
			if(kwargs["showDisabled"]):
				showOnlyUncrackedDisabled = len([account for account in uncrackedDisAcc if ((kwargs["highlightUser"] and kwargs["highlightUser"].match(account.name)) or (kwargs["highlightUsersFile"] and account.name in kwargs["highlightUsersFile"]) or (kwargs["showMatchingPassword"] and  account.password in kwargs["showMatchingPassword"]) or (kwargs["showMatchingNTHash"] and  kwargs["showMatchingNTHash"].match(account.ntHash)) or (kwargs["showMatchingNTHashesFile"] and account.ntHash in kwargs["showMatchingNTHashesFile"]))])
	
	showEnabledAccounts(enabledAcc, showOnlyEnabled, **kwargs)
	showDisabledAccounts(disabledAcc, showOnlyDisabled, **kwargs)
	showUncrackedAccounts(uncrackedEnAcc, showOnlyUncrackedEnabled, uncrackedDisAcc, showOnlyUncrackedDisabled, **kwargs)
	showMatchingPassword(enabledAcc, disabledAcc, **kwargs)
	showMatchingNTHash(enabledAcc, disabledAcc, uncrackedEnAcc, uncrackedDisAcc, **kwargs)
	showMatchingNTHashesFile(enabledAcc, disabledAcc, uncrackedEnAcc, uncrackedDisAcc, **kwargs)
	showPasswordReuse(enabledAcc, disabledAcc, passwordCount, **kwargs)
	statistics(enabledAcc, disabledAcc, uncrackedEnAcc, uncrackedDisAcc, passwordCount, **kwargs)

def showEnabledAccounts(enabledAcc, showOnlyEnabled, **kwargs):
	if(kwargs["highlightOnly"]):
		print("Enabled accounts ({}/{}):".format(showOnlyEnabled, len(enabledAcc)))
	else:
		print("Enabled accounts ({}):".format(len(enabledAcc)))
	for account in sorting(enabledAcc, key=attrgetter('domain', 'name'), **kwargs):
		if(not kwargs["highlightOnly"] or (
			(kwargs["highlightUser"] and kwargs["highlightUser"].match(account.name)) or
			(kwargs["highlightUsersFile"] and account.name in kwargs["highlightUsersFile"]) or
			(kwargs["showMatchingPassword"] and  account.password in kwargs["showMatchingPassword"]) or 
			(kwargs["showMatchingNTHash"] and  kwargs["showMatchingNTHash"].match(account.ntHash)) or 
			(kwargs["showMatchingNTHashesFile"] and account.ntHash in kwargs["showMatchingNTHashesFile"]))):
			print(formatResult(account, **kwargs))
		
	print("")

def showDisabledAccounts(disabledAcc, showOnlyDisabled, **kwargs):
	if(kwargs["showDisabled"]):
		if(kwargs["highlightOnly"]):
			print("Disabled accounts ({}/{}):".format(showOnlyDisabled, len(disabledAcc)))
		else:
			print("Disabled accounts ({}):".format(len(disabledAcc)))
		for account in sorting(disabledAcc, key=attrgetter('domain', 'name'), **kwargs):
			if(not kwargs["highlightOnly"] or (
				(kwargs["highlightUser"] and kwargs["highlightUser"].match(account.name)) or
				(kwargs["highlightUsersFile"] and account.name in kwargs["highlightUsersFile"]) or
				(kwargs["showMatchingPassword"] and  account.password in kwargs["showMatchingPassword"]) or 
				(kwargs["showMatchingNTHash"] and  kwargs["showMatchingNTHash"].match(account.ntHash)) or 
				(kwargs["showMatchingNTHashesFile"] and account.ntHash in kwargs["showMatchingNTHashesFile"]))):
				print(formatResult(account, **kwargs))
	
		print("")

def showUncrackedAccounts(uncrackedEnAcc, showOnlyUncrackedEnabled, uncrackedDisAcc, showOnlyUncrackedDisabled, **kwargs):
	if(kwargs["showUncracked"]):
		if(kwargs["highlightOnly"]):
			print("Uncracked enabled accounts ({}/{}):".format(showOnlyUncrackedEnabled, len(uncrackedEnAcc)))
		else:
			print("Uncracked enabled accounts ({}):".format(len(uncrackedEnAcc)))
		for account in sorting(uncrackedEnAcc, key=attrgetter('domain', 'name'), **kwargs):
			if(not kwargs["highlightOnly"] or (
				(kwargs["highlightUser"] and kwargs["highlightUser"].match(account.name)) or
				(kwargs["highlightUsersFile"] and account.name in kwargs["highlightUsersFile"]) or
				(kwargs["showMatchingPassword"] and  account.password in kwargs["showMatchingPassword"]) or 
				(kwargs["showMatchingNTHash"] and  kwargs["showMatchingNTHash"].match(account.ntHash)) or 
				(kwargs["showMatchingNTHashesFile"] and account.ntHash in kwargs["showMatchingNTHashesFile"]))):
				print(formatResult(account, **kwargs))

		print("")

		if(kwargs["showDisabled"]):
			if(kwargs["highlightOnly"]):
				print("Uncracked disabled accounts ({}/{}):".format(showOnlyUncrackedDisabled, len(uncrackedDisAcc)))
			else:
				print("Uncracked disabled accounts ({}):".format(len(uncrackedDisAcc)))
			for account in sorting(uncrackedDisAcc, key=attrgetter('domain', 'name'), **kwargs):
				if(not kwargs["highlightOnly"] or (
					(kwargs["highlightUser"] and kwargs["highlightUser"].match(account.name)) or
					(kwargs["highlightUsersFile"] and account.name in kwargs["highlightUsersFile"]) or
					(kwargs["showMatchingPassword"] and  account.password in kwargs["showMatchingPassword"]) or 
					(kwargs["showMatchingNTHash"] and  kwargs["showMatchingNTHash"].match(account.ntHash)) or 
					(kwargs["showMatchingNTHashesFile"] and account.ntHash in kwargs["showMatchingNTHashesFile"]))):
					print(formatResult(account, **kwargs))
		
			print("")

def showMatchingPassword(enabledAcc, disabledAcc, **kwargs):
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

def showMatchingNTHash(enabledAcc, disabledAcc, uncrackedEnAcc, uncrackedDisAcc, **kwargs):
	if(kwargs["showMatchingNTHash"]):
		accounts = enabledAcc.union(disabledAcc, uncrackedEnAcc, uncrackedDisAcc)
		
		result = findAccountsWithNTHash(accounts, kwargs["showMatchingNTHash"], **kwargs)
		if(result):
			print("Accounts matching NTHash {}".format(kwargs["showMatchingNTHash"].pattern))
			for account in result:
				r = formatResult(account, True, **kwargs)
				if(r):
					print(r)
		else:
			print("No account found matching NTHash {}".format(kwargs["showMatchingNTHash"]))

		print("")

def showMatchingNTHashesFile(enabledAcc, disabledAcc, uncrackedEnAcc, uncrackedDisAcc, **kwargs):
	if(kwargs["showMatchingNTHashesFile"]):
		accounts = enabledAcc.union(disabledAcc, uncrackedEnAcc, uncrackedDisAcc)
		
		for ntHash in sorting(kwargs["showMatchingNTHashesFile"], **kwargs):
			result = findAccountsWithNTHash(accounts, ntHash, **kwargs)
			if(result):
				print("Accounts with NTHash {}".format(ntHash))
				for account in result:
					r = formatResult(account, True, **kwargs)
					if(r):
						print(r)
			else:
				print("No account found with NTHash {}".format(ntHash))

			print("")

def showPasswordReuse(enabledAcc, disabledAcc, passwordCount, **kwargs):
	if(kwargs["showPasswordReuse"] and kwargs["showPasswordReuse"] > 1):
		accounts = enabledAcc.copy()
		
		if(kwargs["showDisabled"]):
			accounts = accounts.union(disabledAcc)
		
		for password, count in dict(sorting(passwordCount.items(), key=lambda x: x[1][True] + x[1][False], reverse=True, **kwargs)).items():
			if(((kwargs["showDisabled"] and count[True] + count[False] > 1) or (not kwargs["showDisabled"] and count[True] > 1)) and (kwargs["showPasswordReuse"] == -1 or count[True] + count[False] <= kwargs["showPasswordReuse"])):
				result = findAccountsWithPassword(accounts, password, **kwargs)
				if(result):
					print("Possible password reuse for password {}".format(password))
					for account in result:
						r = formatResult(account, False, showPasswordReusePassword=password, **kwargs)
						if(r):
							print(r)
				else:
					if(kwargs["showDisabled"]):
						print("No account found with password {}".format(password))
					else:
						print("No enabled account found with password {}".format(password))

				print("")

def statistics(enabledAcc, disabledAcc, uncrackedEnAcc, uncrackedDisAcc, passwordCount, **kwargs):
	if(kwargs["showStats"]):
		spacing = 55
		nbEnabled = decimal.Decimal(len(enabledAcc))
		nbDisabled = decimal.Decimal(len(disabledAcc))
		nbUncrackedEnabled = decimal.Decimal(len(uncrackedEnAcc))
		nbUncrackedDisabled = decimal.Decimal(len(uncrackedDisAcc))
		nbUncracked = decimal.Decimal(len(uncrackedEnAcc) + len(uncrackedDisAcc))
		nbCracked = nbEnabled+nbDisabled
		totalEnabled = nbEnabled+nbUncrackedEnabled
		totalDisabled = nbDisabled+nbUncrackedDisabled
		total = nbEnabled+nbDisabled+nbUncracked

		if(total > 0):
			decimal.getcontext().prec = 4
			pCracked = decimal.Decimal((nbEnabled/total)*100)
			pCrackedEnabled = decimal.Decimal((nbEnabled/totalEnabled)*100) if totalEnabled != 0 else 0
			pCrackedDisabled = decimal.Decimal((nbDisabled/totalDisabled)*100) if totalDisabled != 0 else 0
			pDisCracked = decimal.Decimal((nbDisabled/total)*100)
			pTotalCracked = decimal.Decimal(((nbEnabled+nbDisabled)/total)*100)

			print("Statistics:")
			print("{tab}Enabled Accounts".format(tab=tab))
			print("{tab}Number of cracked enabled (en):{padding}{percent}".format(tab=tab*2, padding=" "*(spacing-35-len(tab)-len(str(nbEnabled))), percent=nbEnabled))
			print("{tab}Number of uncracked enabled (ue):{padding}{percent}".format(tab=tab*2, padding=" "*(spacing-37-len(tab)-len(str(nbUncrackedEnabled))), percent=nbUncrackedEnabled))
			print("{tab}Total of enabled (te=en+ue):{padding}{percent}".format(tab=tab*2, padding=" "*(spacing-32-len(tab)-len(str(totalEnabled))), percent=totalEnabled))
			print("{tab}Percentage of cracked (en/te):{padding}{percent}%".format(tab=tab*2, padding=" "*(spacing-34-len(tab)-len(str(pCrackedEnabled))-1), percent=pCrackedEnabled))
			print("")
			print("{tab}Disabled Accounts".format(tab=tab))
			print("{tab}Number of cracked disabled (dis):{padding}{percent}".format(tab=tab*2, padding=" "*(spacing-37-len(tab)-len(str(nbDisabled))), percent=nbDisabled))
			print("{tab}Number of uncracked disabled (ud):{padding}{percent}".format(tab=tab*2, padding=" "*(spacing-38-len(tab)-len(str(nbUncrackedDisabled))), percent=nbUncrackedDisabled))
			print("{tab}Total of disabled (td=dis+ud):{padding}{percent}".format(tab=tab*2, padding=" "*(spacing-34-len(tab)-len(str(totalDisabled))), percent=totalDisabled))
			print("{tab}Percentage of cracked (dis/td):{padding}{percent}%".format(tab=tab*2, padding=" "*(spacing-35-len(tab)-len(str(pCrackedDisabled))-1), percent=pCrackedDisabled))
			print("")
			print("{tab}Every Account".format(tab=tab))
			print("{tab}Number of cracked (c=en+dis):{padding}{percent}".format(tab=tab*2, padding=" "*(spacing-33-len(tab)-len(str(nbCracked))), percent=nbCracked))
			print("{tab}Number of uncracked (uc=ue+ud):{padding}{percent}".format(tab=tab*2, padding=" "*(spacing-35-len(tab)-len(str(nbUncracked))), percent=nbUncracked))
			print("{tab}Total (t=c+uc):{padding}{percent}".format(tab=tab*2, padding=" "*(spacing-19-len(tab)-len(str(total))), percent=total))
			print("{tab}Percentage of cracked (en/t):{padding}{percent}%".format(tab=tab*2, padding=" "*(spacing-33-len(tab)-len(str(pCracked))-1), percent=pCracked))
			print("{tab}Percentage of cracked (dis/t):{padding}{percent}%".format(tab=tab*2, padding=" "*(spacing-34-len(tab)-len(str(pDisCracked))-1), percent=pDisCracked))
			print("{tab}Percentage of cracked ((en+dis)/t):{padding}{percent}%".format(tab=tab*2, padding=" "*(spacing-39-len(tab)-len(str(pTotalCracked))-1), percent=pTotalCracked))
			print("")
			if(kwargs["showDisabled"]):
				print("{tab}Password count (en/t):".format(tab=tab))
			else:
				print("{tab}Password count:".format(tab=tab))

			for k, v in dict(sorting(passwordCount.items(), key=lambda x: x[1][True] + x[1][False], reverse=True, **kwargs)).items():
				if(kwargs["showDisabled"]):
					if(v[True] + v[False] > 1):
						value = "{}/{}".format(v[True], v[True] + v[False])
					else:
						continue
				else:
					if(v[True] > 1): 
						value = str(v[True])
					else:
						continue
				
				print("{tab}{password}{padding}{value}".format(tab=tab*2, password=k, padding=" "*(spacing-len(tab*2) - len(k) - len(value)), value=value))

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
		if((kwargs["highlightUser"] and kwargs["highlightUser"].match(account.name)) or (kwargs["highlightUsersFile"] and account.name in kwargs["highlightUsersFile"])):
			if(account.status):
				result = "\033[92m{tab}{accInfo}{padding}{password}\033[00m".format(tab=tab, accInfo=p, padding=" "*(100 - len(tab) - len(p) - len(account.password)), password=account.password)
			else:
				result = "\033[91m{tab}{accInfo}{padding}{password}\033[00m".format(tab=tab, accInfo=p, padding=" "*(100 - len(tab) - len(p) - len(account.password)), password=account.password)
		elif(kwargs["showMatchingPassword"] and  account.password in kwargs["showMatchingPassword"]):
			if(account.status):
				result = "\033[93m{tab}{accInfo}{padding}{password}\033[00m".format(tab=tab, accInfo=p, padding=" "*(100 - len(tab) - len(p) - len(account.password)), password=account.password)
			else:
				result = "\033[91m{tab}{accInfo}{padding}{password}\033[00m".format(tab=tab, accInfo=p, padding=" "*(100 - len(tab) - len(p) - len(account.password)), password=account.password)
		elif((kwargs["showMatchingNTHash"] and  kwargs["showMatchingNTHash"].match(account.ntHash)) or (kwargs["showMatchingNTHashesFile"] and account.ntHash in kwargs["showMatchingNTHashesFile"])):
			if(account.status):
				result = "\033[92m{tab}{accInfo}{padding}{password}\033[00m".format(tab=tab, accInfo=p, padding=" "*(100 - len(tab) - len(p) - len(account.password)), password=account.password)
			else:
				result = "\033[91m{tab}{accInfo}{padding}{password}\033[00m".format(tab=tab, accInfo=p, padding=" "*(100 - len(tab) - len(p) - len(account.password)), password=account.password)
		else:
			result = "{tab}{accInfo}{padding}{password}".format(tab=tab, accInfo=p, padding=" "*(100 - len(tab) - len(p) - len(account.password)), password=account.password)
	else:
		if((kwargs["highlightUser"] and kwargs["highlightUser"].match(account.name)) or (kwargs["highlightUsersFile"] and account.name in kwargs["highlightUsersFile"])):
			if(account.status and account.password):
				result = "\033[92m{tab}{accInfo}\033[00m".format(tab=tab, accInfo=p)
			else:
				result = "\033[91m{tab}{accInfo}\033[00m".format(tab=tab, accInfo=p)
		elif(kwargs["showPasswordReuse"] and "showPasswordReusePassword" in kwargs and account.password == kwargs["showPasswordReusePassword"]):
			if(account.status):
				result = "\033[92m{tab}{accInfo}\033[00m".format(tab=tab, accInfo=p)
			else:
				result = "\033[91m{tab}{accInfo}\033[00m".format(tab=tab, accInfo=p)
		elif(kwargs["showMatchingPassword"] and account.password in kwargs["showMatchingPassword"]):
			if(account.status and account.password):
				result = "\033[92m{tab}{accInfo}\033[00m".format(tab=tab, accInfo=p)
			else:
				result = "\033[91m{tab}{accInfo}\033[00m".format(tab=tab, accInfo=p)
		elif((kwargs["showMatchingNTHash"] and kwargs["showMatchingNTHash"].match(account.ntHash)) or (kwargs["showMatchingNTHashesFile"] and account.ntHash in kwargs["showMatchingNTHashesFile"])):
			if(account.status):
				result = "\033[93m{tab}{accInfo}\033[00m".format(tab=tab, accInfo=p)
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
	parser.add_argument("-r", "--password-reuse", dest="showPasswordReuse", help="Show accounts with the same password in result. Use '-r all' to show them all. (If --all is used: default shows password reused twice).", type=str, default=None)
	parser.add_argument("-D", "--domain", dest="showMatchingDomain", help="Show only matching domain  (regex).", type=str.upper, default=None)
	parser.add_argument("--domains-file", dest="showMatchingDomainsFile", help="Show only matching domains by providing a file splitted by newlines.", type=str, default=None)
	parser.add_argument("-P", "--password", dest="showMatchingPassword", help="Show matching password in the result.", type=str, default=None)
	parser.add_argument("--passwords-file", dest="showMatchingPasswordsFile", help="Show matching password in the result by providing a file splitted by newlines.", type=str, default=None)
	parser.add_argument("-N", "--hash", dest="showMatchingNTHash", help="Show matching hash in the result (regex).", type=str.lower,default=None)
	parser.add_argument("--hashes-file", dest="showMatchingNTHashesFile", help="Show matching hash in the result by providing a file splitted by newlines.", type=str.lower,default=None)
	parser.add_argument("-U", "--user", dest="highlightUser", help="Highlight matching user in the result (regex).", type=str.lower,default=None)
	parser.add_argument("--users-file", dest="highlightUsersFile", help="Highlight matching users in the result by providing a file splitted by newlines.", type=str,default=None)
	parser.add_argument("-H", "--highlight-only", dest="highlightOnly", help="Show only highlists results (requires showMatchingDomain, showMatchingPassword, showMatchingNTHash or highlightUser).", action="store_true")
	parser.add_argument("-p", "--performance", dest="performance", help="Need more performance? This will NOT sort the results.", action="store_true")
	parser.add_argument("-t", "--time", dest="time", help="Print the elasped time to run the script.", action="store_true")
	args = parser.parse_args()

	if(args.time or args.verbose):
		startTime = decimal.Decimal(time())

	if(args.showMatchingDomain):
		if(not args.showMatchingDomain.startswith("^")): args.showMatchingDomain = "^" + args.showMatchingDomain
		if(not args.showMatchingDomain.endswith("$")): args.showMatchingDomain += "$"
		args.showMatchingDomain = re.compile(args.showMatchingDomain)

	if(args.showMatchingDomainsFile):
		if(os.path.isfile(args.showMatchingDomainsFile)):
			with open(args.showMatchingDomainsFile, 'r') as f:
				args.showMatchingDomainsFile = f.read().upper().split("\n")
		else:
			raise FileNotFoundError("{} was not found.".format(args.showMatchingDomainsFile))

	if(args.showMatchingPassword):
		args.showMatchingPassword = [args.showMatchingPassword]

	if(args.showMatchingPasswordsFile):
		if(os.path.isfile(args.showMatchingPasswordsFile)):
			with open(args.showMatchingPasswordsFile, 'r') as f:
				if(args.showMatchingPassword):
					args.showMatchingPassword.extend(f.read().split("\n"))
				else:
					args.showMatchingPassword = f.read().split("\n")
			del args.showMatchingPasswordsFile
		else:
			raise FileNotFoundError("{} was not found.".format(args.showMatchingPasswordsFile))

	if(args.showMatchingNTHash):
		if(not args.showMatchingNTHash.startswith("^")): args.showMatchingNTHash = "^" + args.showMatchingNTHash
		if(not args.showMatchingNTHash.endswith("$")): args.showMatchingNTHash += "$"
		args.showMatchingNTHash = re.compile(args.showMatchingNTHash)

	if(args.showMatchingNTHashesFile):
		if(os.path.isfile(args.showMatchingNTHashesFile)):
			with open(args.showMatchingNTHashesFile, 'r') as f:
				args.showMatchingNTHashesFile = f.read().lower().split("\n")
		else:
			raise FileNotFoundError("{} was not found.".format(args.showMatchingNTHashesFile))

	if(args.highlightUser):
		if(not args.highlightUser.startswith("^")): args.highlightUser = "^" + args.highlightUser
		if(not args.highlightUser.endswith("$")): args.highlightUser += "$"
		args.highlightUser = re.compile(args.highlightUser)

	if(args.highlightUsersFile):
		if(os.path.isfile(args.highlightUsersFile)):
			with open(args.highlightUsersFile, 'r') as f:
				args.highlightUsersFile = f.read().lower().split("\n")
		else:
			raise FileNotFoundError("{} was not found.".format(args.highlightUsersFile))

	if(args.highlightOnly):
		if(args.showMatchingDomain or args.showMatchingPassword or args.showMatchingNTHash or args.highlightUser or
			args.showMatchingDomainsFile or args.showMatchingPasswordsFile or args.showMatchingNTHashesFile or args.highlightUsersFile):
			args.highlightOnly = True
		else:
			args.highlightOnly = False

	if(args.showPasswordReuse):
		if(args.showPasswordReuse == "all"):
			args.showPasswordReuse = INT_MAXSIZE
		elif(args.showPasswordReuse.isnumeric()):
			args.showPasswordReuse = int(args.showPasswordReuse)
		else:
			raise ValueError("'{}' is not an integer or 'all'.".format(args.showPasswordReuse))
	else:
		if(args.all): 
			args.showPasswordReuse = INT_MAXSIZE
		else:
			args.showPasswordReuse = False

	if(args.all):
		args.showDisabled = True
		args.showUncracked = True
		args.showNTHash = True
		args.showDomain = True
		args.showStats = True
		args.showPasswordReuse = INT_MAXSIZE if args.showPasswordReuse is None else args.showPasswordReuse

	if(args.dump and (not os.path.exists(args.dump) or not os.path.isfile(args.dump))):
		raise FileNotFoundError("{} was not found.".format(args.dump))
	if(args.cracked and (not os.path.exists(args.cracked) or not os.path.isfile(args.cracked))):
		raise FileNotFoundError("{} was not found.".format(args.cracked))

	(enabledAcc, disabledAcc, uncrackedEnAcc, uncrackedDisAcc, passwordCount) = correlation(*getContent(**vars(args)), **vars(args))
	showResults(enabledAcc, disabledAcc, uncrackedEnAcc, uncrackedDisAcc, passwordCount, **vars(args))

	if(args.time or args.verbose):
		endTime = decimal.Decimal(time())

		print("Elasped time: {}s".format(endTime-startTime))
