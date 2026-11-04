import threading
from lib.logger import *
from lib.config import *
import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from lib.objects import AccountBreachAlertTemplate, HostAlertTemplate, DefaultCredsAlertTemplate
import requests
import json
import uuid
import base64
from lib.settings import homenet, lock


class AlertReporter(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.ctime = int(time.time())

    def run(self):

        while 1:
            self.ctime = int(time.time())
            if homenet.dst_emails:
                self.report_new_alerts()
            else:
                pass
            time.sleep(15)

    def report_new_alerts(self):
        alerts = utils.get_not_reported_alerts()
        if not alerts:
            return

        # Build the email bodies (which read homenet) and snapshot the mailer
        # settings under the lock, but release it before the SMTP send: network
        # I/O must not be performed while holding the global lock, or every other
        # thread stalls for the duration of each (possibly timing-out) send.
        prepared = []
        with lock:
            mailer_mode = homenet.mailer_mode
            mailer_address = homenet.mailer_address
            mailer_pwd = homenet.mailer_pwd
            recipients = list(homenet.dst_emails)
            for alert in alerts:
                if alert[1] == 'data_breach':
                    t = AccountBreachAlertTemplate(alert)
                    t.create_body()
                elif alert[1] == 'default_creds':
                    t = DefaultCredsAlertTemplate(homenet, alert)
                    t.create_body()
                else:
                    t = HostAlertTemplate(homenet, alert)
                    t.create_body()

                prepared.append((alert, {'subject': t.subject, 'body': t.body}))

        if mailer_mode != 'gmail' or not (mailer_address and mailer_pwd) or not recipients:
            return

        # Send outside the lock.
        for alert, email in prepared:
            res = self.sendmail_gmail(email, mailer_address, mailer_pwd, recipients)
            if res:
                utils.update_alert_nrep(alert[0], alert[5] + 1)
            else:
                log.debug('FG-ERROR: Falcongate was not able to send a Gmail alert')

    def sendmail_gmail(self, report, fromaddr, passwd, recipients):
        try:
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(fromaddr, passwd)
            for address in recipients:
                msg = MIMEMultipart()
                msg['From'] = fromaddr
                msg['To'] = address
                msg['Subject'] = report['subject']
                body = report['body']
                msg.attach(MIMEText(body, 'plain'))
                text = msg.as_string()
                server.sendmail(fromaddr, address, text)
            server.quit()
            return True
        except Exception as e:
            log.debug('FG-ERROR: ' + str(e.__doc__) + " - " + str(e))
            return False
