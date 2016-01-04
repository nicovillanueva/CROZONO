import random
import subprocess
from poormanslogging import info, error, warn


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
	proc = subprocess.Popen(['iwconfig'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

	for line in proc.communicate()[0].decode().split('\n'):
		if 'Mode:Monitor' in line:
			iface_mon = line.split()[0]
			return iface_mon
		else:
			error("Could not set interface in monitor mode!")
			exit()


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
