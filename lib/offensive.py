import threading
from lib.logger import *
import time
import subprocess
import re
from lib.objects import *
import lib.utils as utils
from lib.settings import homenet, lock


class ScheduledScans(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.target_ports = [21, 22, 23, 445, 3306, 3389, 5900, 5432]
        self.hydra_regex = re.compile(r"^\[(\d+)\]\[(\w+)\]\shost\:\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+login\:\s(\b.+\b)\s+password\:\s\b(.+)\b$")

    def run(self):

        # Wait until the port scan finished
        time.sleep(600)

        while 1:
            log.debug('FG-INFO: Default credentials assessment started')

            # Finding targets for Ncrack
            try:
                ssh_targets = []
                ftp_targets = []
                telnet_targets = []
                rdp_targets = []
                smb_targets = []
                rlogin_targets = []
                vnc_targets = []

                for ip in homenet.hosts.keys():
                    if utils.ping_host(ip):
                        for port in homenet.hosts[ip].tcp_ports:
                            if port == 22:
                                ssh_targets.append(ip)
                            elif port == 21:
                                ftp_targets.append(ip)
                            elif port == 23:
                                telnet_targets.append(ip)
                            elif port == 445:
                                smb_targets.append(ip)
                            elif port == 3389:
                                rdp_targets.append(ip)
                            elif port >= 5800 and port <= 6000:
                                vnc_targets.append(ip)

            except Exception as e:
                log.debug('FG-ERROR: ' + str(e.__doc__) + " - " + str(e))

            for ip in ssh_targets:
                self.brute_force_service(ip, 'ssh')

            for ip in ftp_targets:
                self.brute_force_service(ip, 'ftp')

            for ip in telnet_targets:
                self.brute_force_service(ip, 'telnet')

            for ip in rdp_targets:
                self.brute_force_service(ip, 'rdp')

            for ip in smb_targets:
                self.brute_force_service(ip, 'smb')

            for ip in vnc_targets:
                self.brute_force_service(ip, 'vnc')

            log.debug('FG-INFO: Default credentials assessment finished')

            time.sleep(86400)

    def brute_force_service(self, tip, service):

        proc = subprocess.Popen(['/usr/bin/hydra', '-C', '/tmp/default_creds.csv', tip, service], stdout=subprocess.PIPE)

        while True:
            try:
                line = proc.stdout.readline()
                if line != '':
                    line = line.strip()
                    groups = re.findall(self.hydra_regex, line.strip())
                    if groups:
                        with lock:
                            new_issue = DefaultCredentials()
                            new_issue.service = groups[0][1]
                            new_issue.port = groups[0][0]
                            new_issue.user = groups[0][3]
                            new_issue.password = groups[0][4]
                            homenet.hosts[tip].vuln_accounts.append(new_issue)
                        self.create_default_creds_alert('default_creds', tip, groups[0][1], groups[0][3], groups[0][4])
            except Exception as e:
                log.debug('FG-ERROR: Something went wrong with hydra assessment for host ' + tip + ' and service ' + service +  ' - ' + str(e))
            else:
                break

    def create_default_creds_alert(self, threat, src, service, uname, passwd):
        ctime = int(time.time())
        description = 'FalconGate has detected an account with default vendor credentials on this host. ' \
                      'This is a serious issue which could allow and attacker to remotely access and take control of ' \
                      'this device.'
        indicators = 'Service: ' + service + '|' + 'Username: ' + uname + '|' + 'Password: ' + passwd
        reference = 'https://www.sans.edu/cyber-research/security-laboratory/article/default-psswd'
        a = [0, threat, ctime, ctime, 0, 0, 'Default Credentials', src, indicators, 0, description, reference]
        alert_id = utils.add_alert_to_db(a)
        homenet.hosts[src].alerts.append(alert_id)