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
        with lock:
            for alert in alerts:
                email = {}

                if alert[1] == 'data_breach':
                    t = AccountBreachAlertTemplate(alert)
                    t.create_body()
                elif alert[1] == 'default_creds':
                    t = DefaultCredsAlertTemplate(homenet, alert)
                    t.create_body()
                else:
                    t = HostAlertTemplate(homenet, alert)
                    t.create_body()

                email['subject'] = t.subject
                email['body'] = t.body

                if (not homenet.mailer_mode) or (homenet.mailer_mode == 'standalone'):
                    res = self.sendmail_stand(email)
                    if res:
                        utils.update_alert_nrep(alert[0], alert[5] + 1)
                    else:
                        log.debug('FG-ERROR: FalconGate was not able to send a standalone alert')
                elif homenet.mailer_mode == 'gmail':
                    res = self.sendmail_gmail(email, homenet.mailer_address, homenet.mailer_pwd)
                    if res:
                        utils.update_alert_nrep(alert[0], alert[5] + 1)
                    else:
                        log.debug('FG-ERROR: FalconGate was not able to send a Gmail alert')
                elif homenet.mailer_mode == 'cloud':
                    res = self.send_alert_cloud(alert)
                    if res:
                        utils.update_alert_nrep(alert[0], alert[5] + 1)
                    else:
                        log.debug('FG-ERROR: FalconGate was not able to send a Cloud alert')

    def sendmail_stand(self, report):
        fromaddr = "no-reply@falcongate.local"
        try:
            server = smtplib.SMTP('localhost')
            msg = ("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n" % (fromaddr, ", ".join(homenet.dst_emails), report['subject']))
            msg += report['body']
            for address in homenet.dst_emails:
                server.sendmail(fromaddr, address, msg)
            server.quit()
            return True
        except Exception as e:
            log.debug('FG-ERROR: ' + str(e.__doc__) + " - " + str(e))
            return False

    def sendmail_gmail(self, report, fromaddr, passwd):
        try:
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(fromaddr, passwd)
            for address in homenet.dst_emails:
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

    def send_alert_cloud(self, alert):
        try:
            alertID = str(uuid.uuid4())
            headers = {"content-type": "application/json",
                   "User-Agent": "Mozilla/5.0",
                   "x-api-key": homenet.fg_intel_key}

            if alert[6] == "Data Breach":
                sourceHost = "N/A"
                sourceIP = "N/A"
            else:
                sourceHost = homenet.hosts[alert[7]].hostname
                sourceIP = alert[7].encode('utf-8')

            description = base64.b64encode(alert[10].encode('utf-8'))

            report = {'alertID': alertID, 'apiKey': homenet.fg_intel_key, 'threatType': alert[6].encode('utf-8'), 'description': description,
                      'sourceHost': sourceHost, 'sourceIP': sourceIP, 'indicators': alert[8].encode('utf-8').replace(':', '-'),
                      'reported': 'False', 'send_email': 'True', 'send_telegram': [lambda: 'False', lambda: 'True'][homenet.telegram_id is not None](),
                      'telegram_id': str(homenet.telegram_id), 'reference': alert[11].encode('utf-8'), 'detected': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(alert[2]))}

            report_json = json.dumps(report)

            response = requests.post(homenet.fg_api_alert_url, headers=headers, data=report_json)

            if response.status_code == 200:
                return True
            else:
                return False
        except Exception as e:
            log.debug('FG-ERROR: ' + str(e.__doc__) + " - " + str(e))
            return False
