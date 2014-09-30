
#=========
# CONTROL
#=========

# (STR) WLAN interface in monitor mode
IFACE = 'mon0'

# (LIST) List of MAC addresses expected within the premises
MAC_LIST = [
    'ee:ee:ee:ee:ee:ee',
    'ff:ff:ff:ff:ff:ff',
    ]

# (INT) RSSi threshold for triggering alerts
RSSI_THRESHOLD = -50

# (INT) Number of seconds between alerts for persistent foreign probes
ALERT_THRESHOLD = 120

# (STR) Path to the log file
LOG_FILE = '/var/log/wuds.log'

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
