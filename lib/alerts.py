import threading
from lib.logger import *
import lib.utils as utils
import time


class HourlyAlerts(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.ctime = None

    def run(self):
        global lock
        global homenet

        while 1:
            self.ctime = int(time.time())
            try:
                with lock:
                    for k in homenet.hosts.keys():
                        if homenet.hosts[k].mac != homenet.mac:
                            if len(homenet.hosts[k].dga_domains) >= 20:
                                self.create_dga_alert(k)
                                del homenet.hosts[k].dga_domains[:]
                            if len(homenet.hosts[k].spammed_domains) >= 20:
                                self.create_spamming_alert(k)
                                del homenet.hosts[k].spammed_domains[:]
            except Exception as e:
                log.debug(e.__doc__ + " - " + e.message)
            time.sleep(3600)

    def create_dga_alert(self, src):
        description = 'This host has been detected to perform a well-known Malware traffic ' \
                      'pattern: Domain Generation Algorithm (DGA). This is a strong indication ' \
                      'on the presence of active Malware on this device.'
        indicators = '|'.join(homenet.hosts[src].dga_domains)
        reference = 'https://en.wikipedia.org/wiki/Domain_generation_algorithm'
        a = [0, 'dga', self.ctime, self.ctime, 0, 0, 'Malware', src, indicators, 0, description, reference]
        alert_id = utils.add_alert_to_db(a)
        homenet.hosts[src].alerts.append(alert_id)

    def create_spamming_alert(self, src):
        description = 'This host has been detected to be requesting MX records for multiple ' \
                      'different domains in a short period of time. This could indicate that ' \
                      'this device it\'s infected with Malware with spamming capabilities.'
        indicators = '|'.join(homenet.hosts[src].spammed_domains)
        reference = 'https://en.wikipedia.org/wiki/Spamming'
        a = [0, 'spammer', self.ctime, self.ctime, 0, 0, 'Spammer', src, indicators, 0, description, reference]
        alert_id = utils.add_alert_to_db(a)
        homenet.hosts[src].alerts.append(alert_id)


class MinuteAlerts(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.ctime = int(time.time())

    def run(self):
        global lock
        global homenet

        while 1:
            self.ctime = int(time.time())
            try:
                with lock:
                    for k in homenet.hosts.keys():
                        if homenet.hosts[k].mac != homenet.mac:
                            for k1 in homenet.hosts[k].dns.keys():
                                if homenet.hosts[k].dns[k1].bad:
                                    self.create_bad_domain_alert(k, k1)
                            for k1 in homenet.hosts[k].files.keys():
                                if homenet.hosts[k].files[k1].vt_positives > 2:
                                    self.create_bad_file_alert(k, k1)

                            for k1 in homenet.hosts[k].conns.keys():
                                for threat in homenet.bad_ips.keys():
                                    if homenet.hosts[k].conns[k1].dst_ip in homenet.bad_ips[threat]:
                                        self.create_bad_ip_alert(threat, k, k1)
            except Exception as e:
                log.debug(e.__doc__ + " - " + e.message)
            time.sleep(60)

    def create_bad_domain_alert(self, src, dst):
        description = 'This host was detected trying to resolve the IP address of a domain ' \
                      'which has recent Malware history according to VirusTotal and/or the ' \
                      'local FalconGate blacklist. This could be an indicator of the presence ' \
                      'of Malware on this host.'
        indicators = homenet.hosts[src].dns[dst].query
        reference = 'https://www.virustotal.com/en/domain/' + homenet.hosts[src].dns[dst].query + '/information/'
        a = [0, 'malware', self.ctime, self.ctime, 0, 0, 'Malware', src, indicators, 0, description, reference]
        alert_id = utils.add_alert_to_db(a)
        homenet.hosts[src].alerts.append(alert_id)

    def create_bad_file_alert(self, src, fid):
        description = 'This host was detected downloading a file known to be Malware or a ' \
                      'Malware vector according to VirusTotal. This file could be utilized ' \
                      'to infect this machine or could indicate the presence of active ' \
                      'Malware on this system.'
        indicators = "SHA1: " + homenet.hosts[src].files[fid].sha1
        reference = homenet.hosts[src].files[fid].vt_report
        a = [0, 'malware', self.ctime, self.ctime, 0, 0, 'Malware', src, indicators, 0, description, reference]
        alert_id = utils.add_alert_to_db(a)
        homenet.hosts[src].alerts.append(alert_id)

    def create_bad_ip_alert(self, threat, src, dst):
        description = 'This host has been detected trying to communicate with a malicious ' \
                      'IP address included in the local blacklist. This traffic was blocked ' \
                      'by FalconGate. This could be an indicator of the presence of Malware or hacker activity ' \
                      'on this host.'
        indicators = homenet.hosts[src].conns[dst].dst_ip
        reference = 'https://www.virustotal.com/en/ip-address/' + homenet.hosts[src].conns[dst].dst_ip + '/information/'
        a = [0, threat, self.ctime, self.ctime, 0, 0, threat, src, indicators, 0, description, reference]
        alert_id = utils.add_alert_to_db(a)
        homenet.hosts[src].alerts.append(alert_id)
