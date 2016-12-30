import threading
from lib.logger import *
import lib.utils as utils
from lib.objects import *
import time
import os


class HourlyAlerts(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.ctime = None

    def run(self):
        global lock
        global homenet

        while 1:
            try:
                self.ctime = int(time.time())
                self.check_dga()
                self.check_spamming()
            except Exception as e:
                log.debug(e.__doc__ + " - " + e.message)
            time.sleep(3600)

    def check_dga(self):
        with lock:
            for k in homenet.hosts.keys():
                if homenet.hosts[k].mac != homenet.mac:
                    if homenet.hosts[k].dga_counter >= 5:
                        if 'dga' in homenet.hosts[k].alerts:
                            homenet.hosts[k].alerts['dga'].last_seen = self.ctime
                        else:
                            a = Alert('dga')
                            a.threat = 'Malware'
                            a.description = 'This host has been detected to perform a well-known Malware traffic ' \
                                            'pattern: Domain Generation Algorithm (DGA). This is a strong indication ' \
                                            'on the presence of active Malware on this device.'
                            a.first_seen = self.ctime
                            a.last_seen = self.ctime
                            a.indicators = homenet.hosts[k].dga_domains
                            a.references.append('https://en.wikipedia.org/wiki/Domain_generation_algorithm')
                            homenet.hosts[k].alerts['dga'] = a

                        homenet.hosts[k].dga_counter = 0

    def check_spamming(self):
        with lock:
            for k in homenet.hosts.keys():
                if homenet.hosts[k].mac != homenet.mac:
                    if homenet.hosts[k].spamm_counter >= 5:
                        if 'spammer' in homenet.hosts[k].alerts:
                            homenet.hosts[k].alerts['spammer'].last_seen = self.ctime
                        else:
                            a = Alert('spammer')
                            a.threat = 'Spammer'
                            a.description = 'This host has been detected to be requesting MX records for multiple ' \
                                            'different domains in a short period of time. This could indicate that ' \
                                            'this device it\'s infected with Malware with spamming capabilities.'
                            a.first_seen = self.ctime
                            a.last_seen = self.ctime
                            a.indicators = homenet.hosts[k].spammed_domains
                            a.references.append('https://en.wikipedia.org/wiki/Spamming')
                            homenet.hosts[k].alerts['spammer'] = a

                        homenet.hosts[k].spamm_counter = 0


class MinuteAlerts(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.ctime = int(time.time())

    def run(self):
        global lock
        global homenet

        while 1:
            try:
                self.ctime = int(time.time())
                self.find_bad_files()
                self.find_bad_domains()
                self.find_bad_ip()
                self.find_port_scan()
            except Exception as e:
                log.debug(e.__doc__ + " - " + e.message)
            time.sleep(60)

    def find_bad_domains(self):
        with lock:
            for k in homenet.hosts.keys():
                if homenet.hosts[k].mac != homenet.mac:
                    for k1 in homenet.hosts[k].dns.keys():
                        if homenet.hosts[k].dns[k1].bad and (homenet.hosts[k].dns[k1].counter >= 3):
                            if 'bad_domain' in homenet.hosts[k].alerts:
                                homenet.hosts[k].alerts['bad_domain'].last_seen = self.ctime
                                if (homenet.hosts[k].dns[k1].query not in homenet.hosts[k].alerts['bad_domain'].indicators) and (len(homenet.hosts[k].alerts['bad_domain'].indicators) <= 10):
                                    homenet.hosts[k].alerts['bad_domain'].indicators.append(homenet.hosts[k].dns[k1].query)
                            else:
                                a = Alert('bad_domain')
                                a.threat = 'Malware'
                                a.description = 'This host was detected trying to resolve the IP address of a domain ' \
                                                'which has recent Malware history according to VirusTotal and/or the ' \
                                                'local FalconGate blacklist. This could be an indicator of the presence ' \
                                                'of Malware on this host.'
                                a.first_seen = self.ctime
                                a.last_seen = self.ctime
                                a.indicators.append(homenet.hosts[k].dns[k1].query)
                                a.references.append('https://www.virustotal.com/en/domain/' + homenet.hosts[k].dns[k1].query + '/information/')
                                homenet.hosts[k].alerts['bad_domain'] = a

    def find_bad_files(self):
        with lock:
            for k in homenet.hosts.keys():
                if homenet.hosts[k].mac != homenet.mac:
                    for k1 in homenet.hosts[k].files.keys():
                        if homenet.hosts[k].files[k1].vt_positives > 2:
                            if 'bad_file' in homenet.hosts[k].alerts:
                                homenet.hosts[k].alerts['bad_file'].last_seen = self.ctime
                                if homenet.hosts[k].files[k1].sha1 not in homenet.hosts[k].alerts['bad_file'].indicators:
                                    homenet.hosts[k].alerts['bad_file'].indicators.append(homenet.hosts[k].files[k1].sha1)
                            else:
                                a = Alert('bad_file')
                                a.threat = 'Malware'
                                a.description = 'This host was detected downloading a file known to be Malware or a ' \
                                                'Malware vector according to VirusTotal. This file could be utilized ' \
                                                'to infect this machine or could indicate the presence of active ' \
                                                'Malware on this system.'
                                a.first_seen = self.ctime
                                a.last_seen = self.ctime
                                a.indicators.append("SHA1: " + homenet.hosts[k].files[k1].sha1)
                                a.references.append(homenet.hosts[k].files[k1].vt_report)
                                homenet.hosts[k].alerts['bad_file'] = a

    def find_bad_ip(self):
        with lock:
            for k in homenet.hosts.keys():
                if homenet.hosts[k].mac != homenet.mac:
                    for k1 in homenet.hosts[k].conns.keys():
                        for threat in homenet.bad_ips.keys():
                            if homenet.hosts[k].conns[k1].dst_ip in homenet.bad_ips[threat]:
                                if threat in homenet.hosts[k].alerts:
                                    homenet.hosts[k].alerts[threat].last_seen = self.ctime
                                    if (homenet.hosts[k].conns[k1].dst_ip not in homenet.hosts[k].alerts[threat].indicators) and (len(homenet.hosts[k].alerts[threat].indicators) <= 10):
                                        homenet.hosts[k].alerts[threat].indicators.append(homenet.hosts[k].conns[k1].dst_ip)
                                else:
                                    a = Alert(threat)
                                    a.threat = threat
                                    a.description = 'This host has been detected trying to communicate with a malicious ' \
                                                    'IP address included in the local blacklist. This traffic was blocked ' \
                                                    'by FalconGate. This could be an indicator of the presence of Malware or hacker activity ' \
                                                    'on this host.'
                                    a.first_seen = self.ctime
                                    a.last_seen = self.ctime
                                    a.indicators.append(homenet.hosts[k].conns[k1].dst_ip)
                                    a.references.append('https://www.virustotal.com/en/ip-address/' + homenet.hosts[k].conns[k1].dst_ip + '/information/')
                                    homenet.hosts[k].alerts[threat] = a

    def find_port_scan(self):
        with lock:
            for k in homenet.hosts.keys():
                if homenet.hosts[k].mac != homenet.mac:
                    for k1 in homenet.hosts[k].scans.keys():
                        if 'port_scan' in homenet.hosts[k].alerts:
                            if k1 not in homenet.hosts[k].alerts['port_scan'].indicators:
                                homenet.hosts[k].alerts['port_scan'].indicators.append(k1)
                            if (homenet.hosts[k].scans[k1].lseen - homenet.hosts[k].alerts['port_scan'].last_seen) > 60:
                                homenet.hosts[k].alerts['port_scan'].last_seen = homenet.hosts[k].scans[k1].lseen
                        else:
                            a = Alert('port_scan')
                            a.threat = 'Port Scan'
                            a.description = 'This host has been detected scanning one or multiple destination ' \
                                            'IP addresses for open ports. This could indicate that a hacker has ' \
                                            'compromised and taken control of this host and is now trying to locate ' \
                                            'and compromise other hosts in your network.'
                            a.first_seen = self.ctime
                            a.last_seen = self.ctime
                            a.indicators.append(k1)
                            a.references.append('https://en.wikipedia.org/wiki/Port_scanner')
                            homenet.hosts[k].alerts['port_scan'] = a
