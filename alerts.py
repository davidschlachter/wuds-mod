from config import *

'''
Each module must receive the 'data' variable as a parameter. The 'data' variable
is a dictionary consisting of the bssid, essid, and rssi. Each module must start
with 'alert_' and have a matching variable in config.py for enabling/disabling.
All module variables should be defined in config.py.
'''

from email.mime.text import MIMEText
import smtplib

def alert_sms(data):
    msg = MIMEText('WUDS proximity alert! A foreign device (%s) has been detected on the premises.' % (data['bssid']))
    server = smtplib.SMTP(SMTP_SERVER)
    server.starttls()
    server.login(USERNAME, PASSWORD)
    server.sendmail(USERNAME, PHONE, msg.as_string())
    server.quit()
