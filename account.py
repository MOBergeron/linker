from binascii import unhexlify


class Account(object):
	ENTRY_CURRENT = "current"
	ENTRY_HISTORY = "history"

	def __init__(self, name, id, ntHash, status=True, domain="", entry_type=None, entry_index=None, base_name=None):
		self.name = name.lower()
		self.id = id
		self.ntHash = ntHash.lower()
		self.status = status
		self.domain = domain.upper()
		self.password = None
		self.entry_type = entry_type or self.ENTRY_CURRENT
		self.entry_index = entry_index  # None for current, 0, 1, 2... for history
		self.base_name = (base_name or name).lower()

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
