#!/usr/bin/env python3
import os
import re
from operator import itemgetter, attrgetter

tab = " "*4
hashesRegex = re.compile("((?P<domain>[^\\\\]+)\\\\)?(?P<accName>[^:\\\\\\$]+)(?P<machine>\\$)?:\\d+:[a-fA-F0-9]{32}:(?P<ntHash>[a-fA-F0-9]{32})::: ?(\\(status=(?P<accStatus>Dis|En)abled)\\)?")

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

		return self.password is not None
	
	def __repr__(self):
		return "{}".format(self.name)

	def __str__(self):
		return "{}".format(self.name)
		
def getContent(hashes, cracked, **kwargs):
	with open(hashes,'r') as f:
		accounts = []
		content = f.read().split("\n")
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
				accStatus = None
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
				if(match.group("accStatus")):
					accStatus = True if match.group("accStatus") == "En" else False
				if(match.group("domain")):
					domain = match.group("domain").upper()

				accounts.append(Account(name=accName, ntHash=ntHash, status=accStatus, domain=domain))

		f.close()

	with open(cracked,'r') as f:
		crackedDict = {}
		content = f.read().split("\n")
		for line in content:
			if(not line):
				continue
			h, p = line.split(":",1)
			if(not h.lower() in crackedDict):
				crackedDict[h.lower()] = p
		f.close()

	return accounts, crackedDict

def correlation(accounts, crackedDict, **kwargs):
	enabledAcc = []
	disabledAcc = []
	uncrackedAcc = []
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
				enabledAcc.append(account)
			else:
				disabledAcc.append(account)
		elif(kwargs["showStats"] or kwargs["showUncracked"]):
			uncrackedAcc.append(account)
	
	return enabledAcc, disabledAcc, uncrackedAcc, passwordCount

def findAccountsWithPassword(accounts, password):
	result = set()

	for account in accounts:
		if(account.password == password):
			result.add(account)

	return result

def findAccountsWithNTHash(accounts, ntHash):
	result = set()

	for account in accounts:
		if(account.ntHash == ntHash):
			result.add(account)

	return result

def showResults(enabledAcc, disabledAcc, uncrackedAcc, passwordCount, **kwargs):
	print("Enabled accounts ({}):".format(len(enabledAcc)))
	for account in sorted(enabledAcc, key=attrgetter('domain', 'name')):
		print(formatResult(account, **kwargs))
		
	print("")

	if(kwargs["showDisabled"]):
		print("Disabled accounts ({}):".format(len(disabledAcc)))
		for account in sorted(disabledAcc, key=attrgetter('domain', 'name')):
			print(formatResult(account, **kwargs))
	
		print("")

	if(kwargs["showUncracked"]):
		print("Uncracked accounts ({}):".format(len(uncrackedAcc)))
		for account in sorted(uncrackedAcc, key=attrgetter('domain', 'name')):
			print(formatResult(account, **kwargs))
	
		print("")

	if(kwargs["showMatchingPassword"]):
		accounts = enabledAcc
		
		if(kwargs["showDisabled"]):
			accounts += disabledAcc
		
		for password in sorted(kwargs["showMatchingPassword"]):
			result = findAccountsWithPassword(accounts, password)
			if(result):
				print("Accounts with password {}".format(password))
				for account in result:
					print(formatResult(account, False, **kwargs))
			else:
				if(kwargs["showDisabled"]):
					print("No account found with password {}".format(password))
				else:
					print("No enabled account found with password {}".format(password))

			print("")

	if(kwargs["showMatchingNTHash"]):
		accounts = enabledAcc + disabledAcc + uncrackedAcc
		
		for ntHash in sorted(kwargs["showMatchingNTHash"]):
			result = findAccountsWithNTHash(accounts, ntHash)
			if(result):
				print("Accounts with NTHash {}".format(ntHash))
				for account in result:
					print(formatResult(account, False, **kwargs))
			else:
				print("No account found with NTHash {}".format(ntHash))

			print("")

	if(kwargs["showStats"]):
		from decimal import getcontext, Decimal
		getcontext().prec = 4
		nbEnabled = Decimal(len(enabledAcc))
		nbDisabled = Decimal(len(disabledAcc))
		nbUncracked = Decimal(len(uncrackedAcc))
		total = nbUncracked+nbEnabled+nbDisabled

		if(total > 0):
			pCracked = Decimal((nbEnabled/total)*100)
			pDisCracked = Decimal((nbDisabled/total)*100)
			pTotalCracked = Decimal(((nbEnabled+nbDisabled)/total)*100)

			print("Statistics:")
			print("{tab}Number of enabled (en):{padding}{percent}".format(tab=tab, padding=" "*(50-23-len(tab)-len(str(nbEnabled))), percent=nbEnabled))
			print("{tab}Number of disabled (dis):{padding}{percent}".format(tab=tab, padding=" "*(50-25-len(tab)-len(str(nbDisabled))), percent=nbDisabled))
			print("{tab}Number of uncracked (uc):{padding}{percent}".format(tab=tab, padding=" "*(50-25-len(tab)-len(str(nbUncracked))), percent=nbUncracked))
			print("{tab}Total (en + dis + un):{padding}{percent}".format(tab=tab, padding=" "*(50-22-len(tab)-len(str(total))), percent=total))
			print("")
			print("{tab}Percentage of cracked (en):{padding}{percent}%".format(tab=tab, padding=" "*(50-27-len(tab)-len(str(pCracked))-1), percent=pCracked))
			print("{tab}Percentage of cracked (dis):{padding}{percent}%".format(tab=tab, padding=" "*(50-28-len(tab)-len(str(pDisCracked))-1), percent=pDisCracked))
			print("{tab}Percentage of cracked (en+dis):{padding}{percent}%".format(tab=tab, padding=" "*(50-31-len(tab)-len(str(pTotalCracked))-1), percent=pTotalCracked))
			print("")
			print("{tab}Password count:".format(tab=tab))
			for k, v in dict(sorted(passwordCount.items(), key=lambda x: x[1], reverse=True)).items():
				if(v > 1):
					print("{tab}{password}{padding}{value}".format(tab=tab*2, password=k, padding=" "*(50-len(tab*2) - len(k) - len(str(v))), value=v))
		else:
			print("Can't show stats if the total number of accounts is 0...")

def formatResult(account, showPassword=True, **kwargs):
	p = ""
	if(kwargs["showDomain"] and account.domain):
		p += account.domain
		p += "\\"
	
	p += account.name

	if(kwargs["showNTHash"]):
		p += ":"
		p += account.ntHash
		p += ":"

	if(showPassword and account.password):
		if(kwargs["highlightUser"] and account.name in kwargs["highlightUser"]):
			if(account.status):
				result = "\033[92m{tab}{accInfo}{padding}{password}\033[00m".format(tab=tab, accInfo=p, padding=" "*(80 - len(tab) - len(p) - len(account.password)), password=account.password)
			else:
				result = "\033[91m{tab}{accInfo}{padding}{password}\033[00m".format(tab=tab, accInfo=p, padding=" "*(80 - len(tab) - len(p) - len(account.password)), password=account.password)
		else:
			result = "{tab}{accInfo}{padding}{password}".format(tab=tab, accInfo=p, padding=" "*(80 - len(tab) - len(p) - len(account.password)), password=account.password)
	else:
		if(kwargs["highlightUser"] and account.name in kwargs["highlightUser"]):
			result = "\033[91m{tab}{accInfo}\033[00m".format(tab=tab, accInfo=p)
		else:
			result = "{tab}{accInfo}".format(tab=tab, accInfo=p)

	return result

if __name__=='__main__':
	import argparse
	parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument("-v", "--verbose", dest="verbose", help="Verbose mode", action="store_true")
	parser.add_argument("-H", "--hashes", dest="hashes", help="Hashes file.\nLine format : [DOMAIN\\]USERNAME:USERID:LM:NT::: (status=(Dis|En)abled)", type=str, required=True)
	parser.add_argument("-c", "--cracked", dest="cracked", help="Cracked hash file.", type=str, required=True)
	parser.add_argument("-D", "--domain", dest="showMatchingDomain", help="Show only matching domain.\nMultiple -d flag can be used.\nExample: -d foo.lan -d bar.lan", type=str.upper, action="append", default=None)
	parser.add_argument("-dis", "--disabled", dest="showDisabled", help="Show disabled in the result.\nDefault status is 'enabled' if not present in hashes file.", action="store_true")
	parser.add_argument("-u", "--uncracked", dest="showUncracked", help="Show uncracked accounts in the result.", action="store_true")
	parser.add_argument("-n", "--nthash", dest="showNTHash", help="Show NTHash in the result.", action="store_true")
	parser.add_argument("-d", "--showdomain", dest="showDomain", help="Show domain in the result.", action="store_true")
	parser.add_argument("-s", "--stats", dest="showStats", help="Show statistics in the result.", action="store_true")
	parser.add_argument("-P", "--password", dest="showMatchingPassword", help="Show matching password in the result.", action="append", type=str, default=None)
	parser.add_argument("-N", "--hash", dest="showMatchingNTHash", help="Show matching hash in the result.", action="append", type=str, default=None)
	parser.add_argument("-U", "--user", dest="highlightUser", help="Highlight matching user in the result.", action="append", type=str, default=None)
	args = parser.parse_args()

	if(args.showMatchingDomain):
		args.showMatchingDomain = set(args.showMatchingDomain)

	if(args.showMatchingPassword):
		args.showMatchingPassword = set(args.showMatchingPassword)

	if(args.showMatchingNTHash):
		args.showMatchingNTHash = set(args.showMatchingNTHash)

	if(args.highlightUser):
		args.highlightUser = set(args.highlightUser)

	if(args.hashes and (not os.path.exists(args.hashes) or not os.path.isfile(args.hashes))):
		raise FileNotFoundError("{} was not found.".format(args.hashes))
	if(args.cracked and (not os.path.exists(args.cracked) or not os.path.isfile(args.cracked))):
		raise FileNotFoundError("{} was not found.".format(args.cracked))

	(enabledAcc, disabledAcc, uncrackedAcc, passwordCount) = correlation(*getContent(**vars(args)), **vars(args))
	showResults(enabledAcc, disabledAcc, uncrackedAcc, passwordCount, **vars(args))
