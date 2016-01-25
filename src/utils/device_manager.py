import random
import subprocess
import time
from poormanslogging import info, error


def mac_changer(iface_mon):
	import string
	s = "".join(random.sample(string.hexdigits, 12))
	s = (":".join([i + j for i, j in zip(s[::2], s[1::2])])).lower()
	subprocess.call(['ifconfig', iface_mon, 'down'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
	subprocess.call(['macchanger', '-m', s, iface_mon], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
	subprocess.call(['ifconfig', iface_mon, 'up'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
	return s


def check_interfering_processes(kill=True):
	s = subprocess.Popen(['airmon-ng', 'check', 'kill' if kill else None], stdout=subprocess.DEVNULL)
	_, err = s.communicate()
	if err is not None:
		error('Error when killing interfering processes!')
		return False
	return True


def toggle_mode_monitor(iface, setting=True):
	check_interfering_processes(kill=True)
	subprocess.Popen(['airmon-ng', 'start' if setting else 'stop', iface], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
	time.sleep(1)
	mon = is_interface_monitor(iface)
	if setting and mon:
		info("Successfully set {i} in monitor mode.".format(i=iface))
		return iface
	elif not setting and mon:
		e = "Could not disable monitor mode for interface {i}".format(i=iface)
		error(e)
		raise ValueError(e)
	elif setting and not mon:
		e = "Could not set monitor mode for interface {i}!".format(i=iface)
		error(e)
		raise ValueError(e)


def is_interface_monitor(iface):
	grep = subprocess.Popen(['grep', '"Mode:"'], stdout=subprocess.PIPE)
	iwc = subprocess.Popen(['iwconfig', iface], stdout=grep, stderr=subprocess.DEVNULL)
	s = iwc.communicate()[0].decode()
	return "Monitor" in s


def get_gateway():
	import struct
	import socket
	with open('/proc/net/route', 'r') as fh:
		for line in fh:
			fields = line.strip().split()
			if fields[1] != '00000000' or not int(fields[3], 16) & 2:
				continue
			return socket.inet_ntoa(struct.pack("=L", int(fields[2], 16)))


def get_ifaces():
	"""Returns a list of interfaces (reported by airmon-ng) prefixed by the 'prefix' keyword"""
	ang = subprocess.Popen(['airmon-ng'], stdout=subprocess.PIPE)
	sout, serr = ang.communicate()
	i = list(filter(lambda x: x is not '' and not x.startswith("PHY"), sout.decode().split("\n")))
	return list(map(lambda x: x.split("\t")[1], i))


def hardware_setup():
	info("Setting interface to monitor mode")
	iface = get_ifaces()[0]
	iface_mon = toggle_mode_monitor(iface, True)
	return iface_mon
