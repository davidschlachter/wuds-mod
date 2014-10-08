from contextlib import closing
from datetime import datetime, timedelta
import json
import socket
import sqlite3
import struct
import sys
import traceback
import urllib2

# import wuds modules
sys.dont_write_bytecode = True
from config import *
from alerts import *

# define constants
LOG_TYPES = {
    0: 'messages',
    1: 'probes',
}
MESSAGE_LEVELS = {
    0: 'INFO',
    1: 'ERROR',
    2: 'ALERT',
    }

def log(log_type, values):
    values = (str(datetime.now()),) + values
    values_str = ','.join('?'*len(values))
    query = 'INSERT INTO %s VALUES (%s)' % (LOG_TYPES[log_type], values_str)
    cur.execute(query, values)
    conn.commit()

def log_message(level, message):
    log(0, (MESSAGE_LEVELS[level], message))

def log_probe(data):
    log(1, data)

def resolve_oui(mac):
    if mac not in ouis:
        try:
            #resp = urllib2.urlopen('https://www.macvendorlookup.com/api/v2/%s' % mac)
            #jsonobj = json.load(resp)
            #ouis[mac] = jsonobj[0]['company']
            resp = urllib2.urlopen('http://api.macvendors.com/%s' % mac)
            ouis[mac] = resp.read()
            log_message(0, 'OUI resolved. [%s => %s]' % (mac, ouis[mac]))
        except Exception as e:
            log_message(1, 'OUI resolution failed. [%s => %s]' % (mac, str(e)))
            return 'Unknown'
    return ouis[mac]

def call_alerts(**kwargs):
    for var in globals():
        # find config variables for alert modules
        if var.startswith('ALERT_') and globals()[var] == True:
            # dynamically call enabled alert modules
            if var.lower() in globals():
                func = globals()[var.lower()]
                try:
                    func(**kwargs)
                    log_message(0, '%s alert triggered. [%s]' % (var[6:], kwargs['bssid']))
                except:
                    traceback.print_exc()
                    log_message(1, '%s alert failed. [%s]' % (var[6:], kwargs['bssid']))

def packet_handler(pkt):
    rtlen = struct.unpack('h', pkt[2:4])[0]
    ftype = (ord(pkt[rtlen]) >> 2) & 3
    stype = ord(pkt[rtlen]) >> 4
    # check if probe request frame
    if ftype == 0 and stype == 4:
        # parse bssid
        bssid = pkt[36:42].encode('hex')
        bssid = ':'.join([bssid[x:x+2] for x in xrange(0, len(bssid), 2)])
        # parse rssi
        rssi = struct.unpack("b",pkt[:rtlen][-4:-3])[0]
        # parse essid
        essid = pkt[52:52+ord(pkt[51])] if ord(pkt[51]) > 0 else '<None>'
        # get oui for bssid
        oui = resolve_oui(bssid)
        # build data tuple
        data = (bssid, rssi, essid, oui)
        # check whitelist for probing mac address
        foreign = False
        if bssid not in MAC_LIST:
            foreign = True
        # check proximity
        on_premises = False
        if rssi > RSSI_THRESHOLD:
            on_premises = True
        # log according to configured level
        if LOG_LEVEL == 0: log_probe(data)
        if foreign and LOG_LEVEL == 1: log_probe(data)
        if on_premises and LOG_LEVEL == 2: log_probe(data)
        if foreign and on_premises:
            if LOG_LEVEL == 3: log_probe(data)
            # send alerts periodically
            if bssid not in alerts:
                alerts[bssid] = datetime.now() - timedelta(minutes=5)
            if (datetime.now() - alerts[bssid]).seconds > ALERT_THRESHOLD:
                if LOG_LEVEL == 4: log_probe(data)
                alerts[bssid] = datetime.now()
                call_alerts(bssid=bssid, rssi=rssi, essid=essid, oui=oui)

# connect to the wuds database
# wuds runs as root and should be able to write anywhere
with sqlite3.connect(LOG_FILE) as conn:
    with closing(conn.cursor()) as cur:
        # build the database schema if necessary
        cur.execute('CREATE TABLE IF NOT EXISTS probes (dtg TEXT, mac TEXT, rssi INT, ssid TEXT, oui TEXT)')
        cur.execute('CREATE TABLE IF NOT EXISTS messages (dtg TEXT, lvl TEXT, msg TEXT)')
        conn.commit()
        log_message(0, 'WUDS started.')
        # set up the sniffer
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
        log_message(0, 'WUDS stopped.')
