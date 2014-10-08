
#=========
# CONTROL
#=========

# (STR) WLAN interface in monitor mode
IFACE = 'mon0'

# (LIST) List of MAC addresses expected within the premises
MAC_LIST = [
    'xx:xx:xx:xx:xx:xx',
    'xx:xx:xx:xx:xx:xx',
    ]

# (INT) RSSI threshold for triggering alerts
RSSI_THRESHOLD = -50

# (INT) Number of seconds between alerts for persistent foreign probes
ALERT_THRESHOLD = 120

# (STR) Path to the database file
LOG_FILE = 'log.db'

# (INT) Determines which probes are stored in the database
# 0 = all probes
# 1 = all foreign probes
# 2 = all probes on the premises
# 3 = all foreign probes on the premises
# 4 = only probes that generate alerts
LOG_LEVEL = 3

#========
# ALERTS
#========

# (BOOL) Enable/Disable alert modules
ALERT_SMS = True

#==================
# ALERT_SMS MODULE
#==================

# (STR) SMTP server hostname and port (TLS required) for sending alerts
SMTP_SERVER = 'smtp.gmail.com:587'

# (STR) Mail server credentials for sending alerts
USERNAME = ''
PASSWORD = ''

# (STR) SMS email address (through cellular service provider) for receiving alerts
PHONE = ''
