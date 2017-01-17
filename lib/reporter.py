import threading
from lib.logger import *
from lib.config import *
import smtplib
import time
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText


class AlertReporter(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.ctime = int(time.time())

    def run(self):
        global homenet
        global lock

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
            for a in alerts:
                email = {}
                email['subject'] = "A " + a[6] + " alert was reported for host " + a[7]
                indicators = a[8].replace('.', '[.]')
                indicators = indicators.split('|')
                references = a[11].split('|')
                email['body'] = "FalconGate has reported a " + a[6] + " alert for the device below:\r\n\r\n" \
                                "IP address: " + a[7] + "\r\n" \
                                "Hostname: " + str(homenet.hosts[a[7]].hostname) + "\r\n" \
                                "MAC address: " + str(homenet.hosts[a[7]].mac) + "\r\n" \
                                "MAC vendor: " + str(homenet.hosts[a[7]].vendor) + "\r\n" \
                                "Operating system family: " + "\r\n".join(homenet.hosts[a[7]].os_family) + "\r\n" \
                                "Device family: " + str("\r\n".join(homenet.hosts[a[7]].device_family)) + "\r\n\r\n" \
                                "Description: " + a[10] + "\r\n\r\n" \
                                "The following indicators were detected:\r\n" + str("\r\n".join(indicators)) + "\r\n\r\n" \
                                "References:\r\n" + str("\r\n".join(references)) + "\r\n\r\n" \
                                "This is the first time this incident is reported.\r\n" \
                                "We recommend to investigate this issue asap."
                if (not homenet.mailer_mode) or (homenet.mailer_mode == 'standalone'):
                    res = self.sendmail_stand(email)
                    if res:
                        utils.update_alert_nrep(a[0], a[5] + 1)
                    else:
                        pass
                elif homenet.mailer_mode == 'gmail':
                    res = self.sendmail_gmail(email, homenet.mailer_address, homenet.mailer_pwd)
                    if res:
                        utils.update_alert_nrep(a[0], a[5] + 1)
                    else:
                        pass

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
            log.debug(e.__doc__ + " - " + e.message)
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
            log.debug(e.__doc__ + " - " + e.message)
            return False
