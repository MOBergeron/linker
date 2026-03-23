import re

from linker.account import Account

# Matches _history0, _history1, etc. at end of account name
_history_suffix_re = re.compile(r"_history(\d+)$", re.IGNORECASE)


hashesRegex = re.compile(
	r'((?P<domain>[^\\]+)\\)?(?P<accName>[^:\$]+)(?P<machine>\$)?:(?P<id>\d+):[a-fA-F0-9]{32}:(?P<ntHash>[a-fA-F0-9]{32}):::'
	r'(\s*\(pwdLastSet=(?P<accPwdLastSet>[^\)]+)\))?(\s*\(status=(?P<accStatus>Dis|En)abled\))?'
)
ntHashRegex = re.compile("^([a-fA-F0-9]{32})$")


class SecretsDumpParser(object):
	"""Parses impacket-secretsdump / NTDS extraction output lines."""

	def __init__(self, skip_machine_accounts=True):
		self.skip_machine_accounts = skip_machine_accounts

	def parse_line(self, line, verbose=False):
		"""Parse a single secretsdump line. Returns Account or None if unparseable or skipped."""
		if not line.strip():
			return None
		match = hashesRegex.match(line)
		if not match:
			if verbose:
				print("Error parsing: {}".format(line))
			return None
		accName = match.group("accName") if match.group("accName") else None
		if not accName:
			return None
		if match.group("machine"):
			if verbose:
				print("Skipping machine account: {}".format(accName))
			return None
		id = match.group("id") if match.group("id") else None
		ntHash = match.group("ntHash").lower() if match.group("ntHash") else None
		accStatus = match.group("accStatus") != "Dis"
		domain = (match.group("domain") or "").upper()
		# Detect entry vs history: userpattern_history0, userpattern_history1, etc.
		entry_type = Account.ENTRY_CURRENT
		entry_index = None
		base_name = accName
		hist_match = _history_suffix_re.search(accName)
		if hist_match:
			entry_type = Account.ENTRY_HISTORY
			entry_index = int(hist_match.group(1))
			base_name = accName[:hist_match.start()]
		return Account(
			name=accName, id=id, ntHash=ntHash, status=accStatus, domain=domain,
			entry_type=entry_type, entry_index=entry_index, base_name=base_name
		)

	def parse_stream(self, lines, verbose=False):
		"""Parse an iterable of lines; yields Account objects."""
		for line in lines:
			account = self.parse_line(line, verbose=verbose)
			if account is not None:
				yield account

	def parse_file(self, path, verbose=False):
		"""Parse a dump file and return a set of Account objects."""
		accounts = set()
		with open(path, "r") as f:
			for account in self.parse_stream(f, verbose=verbose):
				accounts.add(account)
		return accounts


class CrackedHashesParser(object):
	"""Parses hash:password cracked output (e.g. from hashcat/john).
	Supports hashcat --username export: username:hash:password and hash:password:username.
	"""

	EMPTY_PASSWORD_NTHASH = "31d6cfe0d16ae931b73c59d7e0c089c0"
	EMPTY_PASSWORD_LABEL = "[Empty Password]"

	def parse_line(self, line, verbose=False):
		"""Parse a single line. Returns (hash, password) or None.
		Accepts: hash:password, username:hash:password, hash:password:username.
		Password may contain colons; only the 32-char hex Nthash is used as key.
		"""
		if not line.strip():
			return None
		parts = line.split(":")
		if len(parts) < 2:
			return None
		# Normal case: hash:password (password may contain colons)
		if len(parts) == 2:
			h, p = parts[0].strip().lower(), parts[1].strip()
			if len(h) == 32 and ntHashRegex.match(h):
				return (h, p)
			return None
		# 3+ parts: username:hash:password or hash:password:username (password may contain colons)
		for i, part in enumerate(parts):
			cand = part.strip().lower()
			if len(cand) == 32 and ntHashRegex.match(cand):
				if i == 0:
					# hash:password:...
					password = ":".join(p.strip() for p in parts[1:])
					return (cand, password)
				if i == 1:
					# username:hash:password
					password = ":".join(p.strip() for p in parts[2:])
					return (cand, password)
				# hash:password:username (hash later in line)
				password = ":".join(p.strip() for p in parts[1:i])
				return (cand, password)
		return None

	def parse_stream(self, lines, verbose=False):
		"""Parse an iterable of lines; yields (hash, password) tuples."""
		for line in lines:
			parsed = self.parse_line(line)
			if parsed is not None:
				yield parsed

	def parse_file(self, path, verbose=False):
		"""Parse a cracked hashes file and return a dict hash -> password."""
		cracked = {}
		with open(path, "r") as f:
			for h, p in self.parse_stream(f):
				if h not in cracked:
					cracked[h] = p
		cracked[self.EMPTY_PASSWORD_NTHASH] = self.EMPTY_PASSWORD_LABEL
		return cracked
