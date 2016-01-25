"""
Global variables and default config values, all set in one place.
Just import the module somewhere and use it's values.

Values set to None are meant to be overriden. Careful with those.
Backtracking who modifies those can be a pain.
"""

# Interface to be used across functions.
# Meant to be set only once.
INTERFACE = None

# Paths
OS_PATH = None
LOG_FILE = OS_PATH + '/log_temp'

# Attacks timings
AIRODUMP_SCAN_TIME = 30
WEP_AIREPLAY_TIME = 300
WPA_EXPECT_HANDSHAKE_TIME = 180
WPA_AIRCRACK_TIME = 20
EVILGRADE_ATTACK_TIME = 300
WASH_SCAN_TIME = 30
REAVER_TIMEOUT = 60
