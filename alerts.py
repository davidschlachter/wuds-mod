from config import *

'''
Each module must receive **kwargs as a parameter. The kwargs variable is a dictionary
consisting of all the data extracted from the probe request. Each module name must
start with 'alert_' and have a matching variable in config.py for enabling/disabling.
Configurable module options may be defined in config.py.
'''

from email.mime.text import MIMEText
import smtplib

def alert_sms(**kwargs):
    msg = MIMEText('WUDS proximity alert! A foreign device (%s - %s) has been detected on the premises.' % (kwargs['bssid'], kwargs['oui']))
    server = smtplib.SMTP(SMTP_SERVER)
    server.starttls()
    server.login(USERNAME, PASSWORD)
    server.sendmail(USERNAME, PHONE, msg.as_string())
    server.quit()
