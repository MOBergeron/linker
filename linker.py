#!/usr/bin/env python3
import os
import re
from sys import maxsize as INT_MAXSIZE
import argparse
import decimal
from collections import defaultdict

from time import time
from operator import attrgetter

from account import Account
from parsers import ntHashRegex
from parsers import SecretsDumpParser, CrackedHashesParser

tab = " "*4


def getContent(dump, cracked, verbose=False):
	parser = SecretsDumpParser(skip_machine_accounts=True)
	accounts = parser.parse_file(dump, verbose=verbose)

	parser = CrackedHashesParser()
	crackedData = parser.parse_file(cracked, verbose=verbose)

	return accounts, crackedData


def group_accounts_by_id(accounts):
	"""Group accounts by id. Each group is sorted: current entry first, then history0, history1, ..."""
	groups = defaultdict(list)
	for acc in accounts:
		groups[acc.id].append(acc)
	for id in groups:
		# Sort: current (entry_index None) first, then history by index
		groups[id].sort(key=lambda a: (a.entry_index is not None, a.entry_index or 0))
	return dict(groups)


def _damerau_levenshtein_distance(a, b):
	"""Damerau-Levenshtein edit distance (insert, delete, substitute, transpose)."""
	if not a:
		return len(b)
	if not b:
		return len(a)
	# d[i][j] = distance between a[:i] and b[:j]; use two rows for space
	# d[-1][*] and d[*][-1] are infinity; row 0 is distances from ""
	prev = list(range(len(b) + 1))
	for i in range(1, len(a) + 1):
		curr = [i] + [0] * len(b)
		for j in range(1, len(b) + 1):
			cost = 0 if a[i - 1] == b[j - 1] else 1
			curr[j] = min(
				curr[j - 1] + 1,
				prev[j] + 1,
				prev[j - 1] + cost,
			)
			if i >= 2 and j >= 2 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
				curr[j] = min(curr[j], prev[j - 2] + 1)
		prev = curr
	return prev[len(b)]


def _evaluate_password_patterns(entries, dl_threshold):
	"""
	entries: list of (entry_label, password) for cracked entries only.
	Returns (is_predictable, pattern_description) or (False, None).
	Uses Damerau-Levenshtein: low average normalized distance = predictable (passwords too similar).
	"""
	if len(entries) < 2:
		return False, None
	passwords = [p for (_, p) in entries]
	pairs = [(passwords[i], passwords[j]) for i in range(len(passwords)) for j in range(i + 1, len(passwords))]
	if not pairs:
		return False, None
	distances = []
	for p1, p2 in pairs:
		d = _damerau_levenshtein_distance(p1, p2)
		max_len = max(len(p1), len(p2)) or 1
		distances.append(d / max_len)
	avg_norm_dist = sum(distances) / len(distances)
	if avg_norm_dist < dl_threshold:
		return True, "predictable password history (avg normalized Damerau-Levenshtein distance {:.2f}, threshold {:.2f})".format(
			avg_norm_dist, dl_threshold
		)
	return False, None


def find_predictable_pattern_accounts(accounts, crackedDict, dl_threshold):
	"""Group by id, resolve passwords, evaluate patterns. Returns list of (account_id, base_name, domain, pattern_desc, entries_with_passwords)."""
	for acc in accounts:
		acc.findPassword(crackedDict)
	groups = group_accounts_by_id(accounts)
	results = []
	for acc_id, acc_list in groups.items():
		if len(acc_list) < 2:
			continue
		entries = []
		for acc in acc_list:
			if acc.password is not None:
				label = "current" if acc.entry_type == Account.ENTRY_CURRENT else "history{}".format(acc.entry_index)
				entries.append((label, acc.password))
		if len(entries) < 2:
			continue
		predictable, desc = _evaluate_password_patterns(entries, dl_threshold=dl_threshold)
		if predictable:
			base_name = acc_list[0].base_name
			domain = acc_list[0].domain
			results.append((acc_id, base_name, domain, desc, entries))
	return results


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
			if(not account.ntHash in passwordCount):
				passwordCount[account.ntHash] = {True:0, False:0}
			passwordCount[account.ntHash][account.status] += 1
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

def _highlight_match(account, kwargs):
	return (
		(kwargs.get("highlightUser") and kwargs["highlightUser"].match(account.name)) or
		(kwargs.get("highlightUsersFile") and account.name in kwargs["highlightUsersFile"]) or
		(kwargs.get("showMatchingPassword") and account.password in kwargs["showMatchingPassword"]) or
		(kwargs.get("showMatchingNTHash") and kwargs["showMatchingNTHash"].match(account.ntHash)) or
		(kwargs.get("showMatchingNTHashesFile") and account.ntHash in kwargs["showMatchingNTHashesFile"])
	)

def showResults(allAccounts, crackedDict, enabledAcc, disabledAcc, uncrackedEnAcc, uncrackedDisAcc, passwordCount, **kwargs):
	showOnlyEnabled = 0
	showOnlyDisabled = 0
	showOnlyUncrackedEnabled = 0
	showOnlyUncrackedDisabled = 0
	if(kwargs["highlightOnly"]):
		showOnlyEnabled = len([a for a in enabledAcc if _highlight_match(a, kwargs)])
		if(kwargs["showDisabled"]):
			showOnlyDisabled = len([a for a in disabledAcc if _highlight_match(a, kwargs)])
		if(kwargs["showUncracked"]):
			showOnlyUncrackedEnabled = len([a for a in uncrackedEnAcc if _highlight_match(a, kwargs)])
			if(kwargs["showDisabled"]):
				showOnlyUncrackedDisabled = len([a for a in uncrackedDisAcc if _highlight_match(a, kwargs)])

	if kwargs.get("includeHistory"):
		enabled_current = {a for a in enabledAcc if a.entry_type == Account.ENTRY_CURRENT}
		enabled_history = {a for a in enabledAcc if a.entry_type == Account.ENTRY_HISTORY}
		disabled_current = {a for a in disabledAcc if a.entry_type == Account.ENTRY_CURRENT}
		disabled_history = {a for a in disabledAcc if a.entry_type == Account.ENTRY_HISTORY}
		showOnlyEnabledCurrent = len([a for a in enabled_current if _highlight_match(a, kwargs)]) if kwargs["highlightOnly"] else 0
		showOnlyEnabledHistory = len([a for a in enabled_history if _highlight_match(a, kwargs)]) if kwargs["highlightOnly"] else 0
		showOnlyDisabledCurrent = len([a for a in disabled_current if _highlight_match(a, kwargs)]) if kwargs["highlightOnly"] else 0
		showOnlyDisabledHistory = len([a for a in disabled_history if _highlight_match(a, kwargs)]) if kwargs["highlightOnly"] else 0
		showEnabledAccounts(enabled_current, showOnlyEnabledCurrent, section_title="Enabled accounts", **kwargs)
		showEnabledAccounts(enabled_history, showOnlyEnabledHistory, section_title="Enabled accounts history", **kwargs)
		showDisabledAccounts(disabled_current, showOnlyDisabledCurrent, section_title="Disabled accounts", **kwargs)
		showDisabledAccounts(disabled_history, showOnlyDisabledHistory, section_title="Disabled accounts history", **kwargs)
	else:
		showEnabledAccounts(enabledAcc, showOnlyEnabled, **kwargs)
		showDisabledAccounts(disabledAcc, showOnlyDisabled, **kwargs)

	if kwargs.get("includeHistory") and kwargs["showUncracked"]:
		uncracked_en_current = {a for a in uncrackedEnAcc if a.entry_type == Account.ENTRY_CURRENT}
		uncracked_en_history = {a for a in uncrackedEnAcc if a.entry_type == Account.ENTRY_HISTORY}
		uncracked_dis_current = {a for a in uncrackedDisAcc if a.entry_type == Account.ENTRY_CURRENT}
		uncracked_dis_history = {a for a in uncrackedDisAcc if a.entry_type == Account.ENTRY_HISTORY}
		showOnlyUncrackedEnCurrent = len([a for a in uncracked_en_current if _highlight_match(a, kwargs)]) if kwargs["highlightOnly"] else 0
		showOnlyUncrackedEnHistory = len([a for a in uncracked_en_history if _highlight_match(a, kwargs)]) if kwargs["highlightOnly"] else 0
		showOnlyUncrackedDisCurrent = len([a for a in uncracked_dis_current if _highlight_match(a, kwargs)]) if kwargs["highlightOnly"] else 0
		showOnlyUncrackedDisHistory = len([a for a in uncracked_dis_history if _highlight_match(a, kwargs)]) if kwargs["highlightOnly"] else 0
		_showUncrackedSection(uncracked_en_current, showOnlyUncrackedEnCurrent, "Uncracked enabled accounts", **kwargs)
		_showUncrackedSection(uncracked_en_history, showOnlyUncrackedEnHistory, "Uncracked enabled accounts history", **kwargs)
		_showUncrackedSection(uncracked_dis_current, showOnlyUncrackedDisCurrent, "Uncracked disabled accounts", **kwargs)
		_showUncrackedSection(uncracked_dis_history, showOnlyUncrackedDisHistory, "Uncracked disabled accounts history", **kwargs)
	else:
		showUncrackedAccounts(uncrackedEnAcc, showOnlyUncrackedEnabled, uncrackedDisAcc, showOnlyUncrackedDisabled, **kwargs)
	showMatchingPassword(enabledAcc, disabledAcc, **kwargs)
	showMatchingNTHash(enabledAcc, disabledAcc, uncrackedEnAcc, uncrackedDisAcc, **kwargs)
	showMatchingNTHashesFile(enabledAcc, disabledAcc, uncrackedEnAcc, uncrackedDisAcc, **kwargs)
	showPasswordReuse(enabledAcc, disabledAcc, uncrackedEnAcc, uncrackedDisAcc, passwordCount, **kwargs)
	showPredictablePatterns(allAccounts, crackedDict, **kwargs)
	statistics(enabledAcc, disabledAcc, uncrackedEnAcc, uncrackedDisAcc, passwordCount, **kwargs)

def showEnabledAccounts(enabledAcc, showOnlyEnabled, section_title=None, **kwargs):
	title = section_title if section_title is not None else "Enabled accounts"
	if(kwargs["highlightOnly"]):
		print("{} ({}/{}):".format(title, showOnlyEnabled, len(enabledAcc)))
	else:
		print("{} ({}):".format(title, len(enabledAcc)))
	for account in sorting(enabledAcc, key=attrgetter('domain', 'name'), **kwargs):
		if(not kwargs["highlightOnly"] or _highlight_match(account, kwargs)):
			print(formatResult(account, **kwargs))
	print("")

def showDisabledAccounts(disabledAcc, showOnlyDisabled, section_title=None, **kwargs):
	title = section_title if section_title is not None else "Disabled accounts"
	show_section = kwargs["showDisabled"] or kwargs.get("includeHistory")
	if show_section:
		if(kwargs["highlightOnly"]):
			print("{} ({}/{}):".format(title, showOnlyDisabled, len(disabledAcc)))
		else:
			print("{} ({}):".format(title, len(disabledAcc)))
		for account in sorting(disabledAcc, key=attrgetter('domain', 'name'), **kwargs):
			if(not kwargs["highlightOnly"] or _highlight_match(account, kwargs)):
				print(formatResult(account, **kwargs))
		print("")

def _showUncrackedSection(acc_set, showOnlyCount, section_title, **kwargs):
	"""Print a single uncracked section (title + account list)."""
	if kwargs["highlightOnly"]:
		print("{} ({}/{}):".format(section_title, showOnlyCount, len(acc_set)))
	else:
		print("{} ({}):".format(section_title, len(acc_set)))
	for account in sorting(acc_set, key=attrgetter('domain', 'name'), **kwargs):
		if not kwargs["highlightOnly"] or _highlight_match(account, kwargs):
			print(formatResult(account, **kwargs))
	print("")


def showUncrackedAccounts(uncrackedEnAcc, showOnlyUncrackedEnabled, uncrackedDisAcc, showOnlyUncrackedDisabled, **kwargs):
	if kwargs["showUncracked"]:
		_showUncrackedSection(uncrackedEnAcc, showOnlyUncrackedEnabled, "Uncracked enabled accounts", **kwargs)
		if kwargs["showDisabled"]:
			_showUncrackedSection(uncrackedDisAcc, showOnlyUncrackedDisabled, "Uncracked disabled accounts", **kwargs)

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

def showPredictablePatterns(allAccounts, crackedDict, **kwargs):
	"""Group accounts by ID, evaluate password history similarity, report predictable patterns."""
	if not kwargs.get("showPredictablePatterns"):
		return
	if not allAccounts or not crackedDict:
		return
	dl_threshold = kwargs.get("dlThreshold", 0.25)
	results = find_predictable_pattern_accounts(allAccounts, crackedDict, dl_threshold)
	if not results:
		print("Predictable password patterns: none detected.")
		print("")
		return
	print("Predictable password patterns ({} account(s)):".format(len(results)))
	for acc_id, base_name, domain, pattern_desc, entries in sorting(results, key=lambda x: (x[2], x[1]), **kwargs):
		display = "{}\\{}".format(domain, base_name) if domain else base_name
		print("{tab}ID {id} ({display}): {desc}".format(tab=tab, id=acc_id, display=display, desc=pattern_desc))
		for label, pwd in entries:
			print("{tab}{tab}{label}: {pwd}".format(tab=tab, label=label, pwd=pwd))
	print("")


def showPasswordReuse(enabledAcc, disabledAcc, uncrackedEnAcc, uncrackedDisAcc, passwordCount, **kwargs):
	if(kwargs["showPasswordReuse"] and kwargs["showPasswordReuse"] > 1):
		accounts = enabledAcc.copy()
		
		if(kwargs["showUncracked"]):
			accounts = accounts.union(uncrackedEnAcc)

		if(kwargs["showDisabled"]):
			accounts = accounts.union(disabledAcc)

			if(kwargs["showUncracked"]):
				accounts = accounts.union(uncrackedDisAcc)

		for password, count in dict(sorting(passwordCount.items(), key=lambda x: x[1][True] + x[1][False], reverse=True, **kwargs)).items():
			if(((kwargs["showDisabled"] and count[True] + count[False] > 1) or (not kwargs["showDisabled"] and count[True] > 1)) and (kwargs["showPasswordReuse"] == -1 or count[True] + count[False] <= kwargs["showPasswordReuse"])):
				if(ntHashRegex.match(password)):
					result = findAccountsWithNTHash(accounts, password, **kwargs)
				else:
					result = findAccountsWithPassword(accounts, password, **kwargs)
				if(result):
					if(ntHashRegex.match(password)):
						print("Possible password reuse for hash {}".format(password))
					else:
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

def _print_stats_block(enabled, disabled, uncracked_en, uncracked_dis, spacing, block_title=None, **kwargs):
	"""Print one stats block (current or historical). Uses only the provided sets; never mixes in other data."""
	nbEnabled = decimal.Decimal(len(enabled))
	nbDisabled = decimal.Decimal(len(disabled))
	nbUncrackedEnabled = decimal.Decimal(len(uncracked_en))
	nbUncrackedDisabled = decimal.Decimal(len(uncracked_dis))
	nbUncracked = nbUncrackedEnabled + nbUncrackedDisabled
	nbCracked = nbEnabled + nbDisabled
	totalEnabled = nbEnabled + nbUncrackedEnabled
	totalDisabled = nbDisabled + nbUncrackedDisabled
	total = nbEnabled + nbDisabled + nbUncracked
	if total <= 0:
		return
	decimal.getcontext().prec = 4
	pCrackedEnabled = decimal.Decimal((nbEnabled / totalEnabled) * 100) if totalEnabled != 0 else 0
	pCrackedDisabled = decimal.Decimal((nbDisabled / totalDisabled) * 100) if totalDisabled != 0 else 0
	pCracked = decimal.Decimal((nbEnabled / total) * 100)
	pDisCracked = decimal.Decimal((nbDisabled / total) * 100)
	pTotalCracked = decimal.Decimal(((nbEnabled + nbDisabled) / total) * 100)
	section = (block_title + "\n") if block_title else ""
	print(section + "{tab}Enabled Accounts".format(tab=tab))
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


def statistics(enabledAcc, disabledAcc, uncrackedEnAcc, uncrackedDisAcc, passwordCount, **kwargs):
	if not kwargs["showStats"]:
		return
	spacing = 55
	# Split by entry type: current-only for main stats, history-only for historical subsection (never mixed)
	enabled_current = {a for a in enabledAcc if a.entry_type == Account.ENTRY_CURRENT}
	disabled_current = {a for a in disabledAcc if a.entry_type == Account.ENTRY_CURRENT}
	uncracked_en_current = {a for a in uncrackedEnAcc if a.entry_type == Account.ENTRY_CURRENT}
	uncracked_dis_current = {a for a in uncrackedDisAcc if a.entry_type == Account.ENTRY_CURRENT}
	enabled_history = {a for a in enabledAcc if a.entry_type == Account.ENTRY_HISTORY}
	disabled_history = {a for a in disabledAcc if a.entry_type == Account.ENTRY_HISTORY}
	uncracked_en_history = {a for a in uncrackedEnAcc if a.entry_type == Account.ENTRY_HISTORY}
	uncracked_dis_history = {a for a in uncrackedDisAcc if a.entry_type == Account.ENTRY_HISTORY}

	total_current = len(enabled_current) + len(disabled_current) + len(uncracked_en_current) + len(uncracked_dis_current)
	if total_current > 0:
		print("Statistics:")
		_print_stats_block(enabled_current, disabled_current, uncracked_en_current, uncracked_dis_current, spacing, **kwargs)
		print("")
		if kwargs["showDisabled"]:
			print("{tab}Password/hash count (en/t):".format(tab=tab))
		else:
			print("{tab}Password/hash count:".format(tab=tab))
		for k, v in dict(sorting(passwordCount.items(), key=lambda x: x[1][True] + x[1][False], reverse=True, **kwargs)).items():
			if kwargs["showDisabled"]:
				if v[True] + v[False] > 1:
					value = "{}/{}".format(v[True], v[True] + v[False])
				else:
					continue
			else:
				if v[True] > 1:
					value = str(v[True])
				else:
					continue
			print("{tab}{isHash}{password}{padding}{value}".format(tab=tab*2, isHash="[hash] " if ntHashRegex.match(k) else "", password=k, padding=" "*(spacing-len(tab*2) - len(k) - len(value) - (len("[hash] ") if ntHashRegex.match(k) else 0)), value=value))
		print("")
	else:
		print("Can't show stats if the total number of accounts is 0...")

	total_history = len(enabled_history) + len(disabled_history) + len(uncracked_en_history) + len(uncracked_dis_history)
	if total_history > 0:
		print("Statistics (historical data only):")
		_print_stats_block(enabled_history, disabled_history, uncracked_en_history, uncracked_dis_history, spacing, **kwargs)
		print("")

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
	parser.add_argument("-pp", "--predictable-patterns", dest="showPredictablePatterns", help="Group accounts by ID, evaluate password history similarity, report users with predictable patterns.", action="store_true")
	parser.add_argument("-dl", "--dl-threshold", dest="dlThreshold", type=float, default=0.25, help="Max avg normalized Damerau-Levenshtein distance below which password history is flagged as predictable; lower = stricter (default: %(default)s).")
	parser.add_argument("-hi", "--history", dest="includeHistory", help="Include historical password entries (entry_history0, entry_history1, ...) in stats: enabled/disabled/uncracked counts, password reuse, statistics. Default: only current entry per account. Predictable-patterns check always uses history.", action="store_true")
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
		args.showPredictablePatterns = True
		args.showPasswordReuse = INT_MAXSIZE if args.showPasswordReuse is None else args.showPasswordReuse

	if(args.dump and (not os.path.exists(args.dump) or not os.path.isfile(args.dump))):
		raise FileNotFoundError("{} was not found.".format(args.dump))
	if(args.cracked and (not os.path.exists(args.cracked) or not os.path.isfile(args.cracked))):
		raise FileNotFoundError("{} was not found.".format(args.cracked))

	allAccounts, crackedDict = getContent(args.dump, args.cracked, args.verbose)
	
	# For stats/correlation: include history only when --history; predictable-patterns always uses full accounts
	accounts_for_stats = allAccounts if args.includeHistory else {a for a in allAccounts if a.entry_type == Account.ENTRY_CURRENT}
	(enabledAcc, disabledAcc, uncrackedEnAcc, uncrackedDisAcc, passwordCount) = correlation(accounts_for_stats, crackedDict, **vars(args))
	showResults(allAccounts, crackedDict, enabledAcc, disabledAcc, uncrackedEnAcc, uncrackedDisAcc, passwordCount, **vars(args))

	if(args.time or args.verbose):
		endTime = decimal.Decimal(time())

		print("Elasped time: {}s".format(endTime-startTime))
