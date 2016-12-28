import threading
from lib.logger import *
from lib.config import *
import smtplib
import time


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
            try:
                if homenet.dst_emails:
                    self.find_active_alerts()
                else:
                    pass
            except Exception as e:
                log.debug(e.__doc__ + " - " + e.message)
            time.sleep(30)

    def find_active_alerts(self):
        with lock:
            for k in homenet.hosts.keys():
                for k1 in homenet.hosts[k].alerts.keys():
                    if homenet.hosts[k].alerts[k1].nreports == 0 or (((self.ctime - homenet.hosts[k].alerts[k1].last_reported) > 86400) and not homenet.hosts[k].alerts[k1].handled):
                        subject = "A " + homenet.hosts[k].alerts[k1].threat + " alert was reported for host " + homenet.hosts[k].ip
                        body = "FalconGate has reported a " + homenet.hosts[k].alerts[k1].threat + " alert for the device below:\r\n\r\n" \
                               "IP address: " + homenet.hosts[k].ip + "\r\n" \
                               "Hostname: " + homenet.hosts[k].hostname + "\r\n" \
                               "MAC address: " + homenet.hosts[k].mac + "\r\n" \
                               "MAC vendor: " + homenet.hosts[k].vendor + "\r\n" \
                               "Operating system family: " + "\r\n".join(homenet.hosts[k].os_family) + "\r\n" \
                               "Device family: " + "\r\n".join(homenet.hosts[k].device_family) + "\r\n\r\n" \
                               "Description: " + homenet.hosts[k].alerts[k1].description + "\r\n\r\n" \
                               "The following indicators were detected:\r\n" + "\r\n".join(homenet.hosts[k].alerts[k1].indicators) + "\r\n\r\n" \
                               "References:\r\n" + "\r\n".join(homenet.hosts[k].alerts[k1].references) + "\r\n\r\n" \
                               "This incident has been reported " + str(homenet.hosts[k].alerts[k1].nreports) + " times previously\r\n\r\n" \
                               "We recommend to investigate this issue asap."
                        self.sendmail(homenet.dst_emails, subject, body)
                        homenet.hosts[k].alerts[k1].last_reported = self.ctime
                        homenet.hosts[k].alerts[k1].nreports += 1

    @staticmethod
    def sendmail(toaddrs, subject, body):
        fromaddr = "no-reply@falcongate.local"

        # Add the From: and To: headers at the start!
        msg = ("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n"
               % (fromaddr, ", ".join(toaddrs), subject))

        msg += body

        server = smtplib.SMTP('localhost')
        server.sendmail(fromaddr, toaddrs, msg)
        server.quit()
