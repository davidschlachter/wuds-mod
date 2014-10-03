from datetime import datetime, timedelta
import json
import socket
import struct
import sys
import traceback
import urllib2

# import wuds modules
sys.dont_write_bytecode = True
from config import *
from alerts import *

# define constants
LOG_LEVELS = {
    0: 'INFO',
    1: 'ERROR',
    2: 'ALERT',
    }

def log(level, message):
    # wuds runs as root and should be able to write anywhere
    with open(LOG_FILE, 'a') as fp:
        fp.write('[%s] [%s] %s\n' % (str(datetime.now()), LOG_LEVELS[level], message))
        fp.flush()

def oui_lookup(mac):
    resp = urllib2.urlopen('https://www.macvendorlookup.com/api/v2/%s' % mac)
    jsonobj = json.load(resp)
    return jsonobj[0]['company']

def call_alerts(**kwargs):
    for var in globals():
        # find config variables for alert modules
        if var.startswith('ALERT_') and globals()[var] == True:
            # dynamically call enabled alert modules
            if var.lower() in globals():
                func = globals()[var.lower()]
                try:
                    func(**kwargs)
                    log(0, '%s alert triggered [%s]' % (var[6:], kwargs['bssid']))
                except:
                    traceback.print_exc()
                    log(1, '%s alert failed [%s]' % (var[6:], kwargs['bssid']))

def packet_handler(pkt):
    rtlen = struct.unpack('h', pkt[2:4])[0]
    ftype = (ord(pkt[rtlen]) >> 2) & 3
    stype = ord(pkt[rtlen]) >> 4
    # check if probe request frame
    if ftype == 0 and stype == 4:
        # parse bssid
        bssid = pkt[36:42].encode('hex')
        bssid = ':'.join([bssid[x:x+2] for x in xrange(0, len(bssid), 2)])
        # check whitelist for probing mac address
        if bssid not in MAC_LIST:
            # parse rssi
            rssi = struct.unpack("b",pkt[:rtlen][-4:-3])[0]
            # check proximity
            if rssi > RSSI_THRESHOLD:
                # parse essid
                essid = pkt[52:52+ord(pkt[51])] if ord(pkt[51]) > 0 else '<None>'
                # get oui for bssid
                if bssid not in ouis:
                    try: ouis[bssid] = oui_lookup(bssid)
                    except: ouis[bssid] = 'Unknown'
                    log(0, 'OUI resolved [%s => %s]' % (bssid, ouis[bssid]))
                oui = ouis[bssid]
                log(2, 'Foreign probe detected [MAC=%s, RSSI=%d, SSID=%s, OUI=%s]' % (bssid, rssi, essid, oui))
                # send alerts periodically
                if bssid not in alerts:
                    alerts[bssid] = datetime.now() - timedelta(minutes=5)
                if (datetime.now() - alerts[bssid]).seconds > ALERT_THRESHOLD:
                    alerts[bssid] = datetime.now()
                    call_alerts(bssid=bssid, rssi=rssi, essid=essid, oui=oui)

log(0, 'WUDS started')
# setup the sniffer
rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
rawSocket.bind((IFACE, 0x0003))
alerts = {}
ouis = {}
# start the sniffer
while True:
    try:
        pkt = rawSocket.recvfrom(2048)[0]
        packet_handler(pkt)
    except KeyboardInterrupt: break
log(0, 'WUDS exited')
