#!/usr/bin/env python

# import python modules
from datetime import datetime, timedelta
import socket
import struct
import sys

# import wuds modules
sys.dont_write_bytecode = True
from config import *
from alerts import *

def log(level, message):
    with open(LOG_FILE, 'a') as fp:
        fp.write('[%s] [%s] %s\n' % (str(datetime.now()), LOG_LEVELS[level], message))
        fp.flush()

def packet_handler(pkt):
    rtlen = struct.unpack('h', pkt[2:4])[0]
    ftype = (ord(pkt[rtlen]) >> 2) & 3
    stype = ord(pkt[rtlen]) >> 4
    # check if probe request frame
    if ftype == 0 and stype == 4:
        bssid = pkt[36:42].encode('hex')
        bssid = ':'.join([bssid[x:x+2] for x in xrange(0, len(bssid), 2)])
        # check whitelist for probing MAC address
        if bssid not in MAC_LIST:
            rssi = struct.unpack("b",pkt[:rtlen][-4:-3])[0]
            # check proximity
            if rssi > RSSI_THRESHOLD:
                essid = pkt[52:52+ord(pkt[51])] if ord(pkt[51]) > 0 else '<None>'
                log(2, 'Foreign probe detected. [MAC=%s RSSI=%d SSID=%s]' % (bssid, rssi, essid))
                if bssid not in alerts:
                    alerts[bssid] = datetime.now() - timedelta(minutes=5)
                # send alerts periodically
                if (datetime.now() - alerts[bssid]).seconds > ALERT_THRESHOLD:
                    alerts[bssid] = datetime.now()
                    for var in globals():
                        # find config variables for alert modules
                        if var.startswith('ALERT_') and globals()[var] == True:
                            # dynamically call enabled alert modules
                            if var.lower() in globals():
                                func = globals()[var.lower()]
                                func({'bssid': bssid, 'rssi': rssi, 'essid': essid})
                            log(0, '%s alert triggered. [%s]' % (var[6:], bssid))

# instatiate variables
alerts = {}
LOG_LEVELS = {
    0: 'INFO',
    1: 'ERROR',
    2: 'ALERT',
    }
try:
    log(0, 'WUDS started.')
    # setup the sniffer
    rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    rawSocket.bind((IFACE, 0x0003))
    # load whitelisted MAC addresses
    for mac in MAC_LIST:
        log(0, 'MAC address whitelisted. [%s]' % (mac))
    # start the sniffer
    while True:
        pkt = rawSocket.recvfrom(2048)[0]
        packet_handler(pkt)
# must be first to prevent IOError/socket.error confusion
# socket.error is seen as an IOError exception
except socket.error as e:
    print 'Interface error: %s (%s)' % (e.strerror, IFACE)
    log(1, '%s (%s).' % (e.strerror, IFACE))
# should be encountered first due to the initial log entry
except IOError as e:
    print 'Logging error: %s (%s)' % (e.strerror, LOG_FILE)
    # hard exit to prevent additional call to log() on exit
    sys.exit()
except KeyboardInterrupt:
    pass
log(0, 'WUDS exited.')
