import threading
from lib.logger import *
import time
import subprocess
import re
from lib.objects import *


class ScheduledScans(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.target_ports = [21, 22, 23, 445, 3306, 3389, 5900, 5432]
        self.ncrack_regex = re.compile(r"^Discovered credentials on (\w+)\:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\:(\d+)\s\'(.+)\'\s\'(.+)\'$")

    def run(self):
        global homenet
        global lock

        # Wait until the port scan finished
        time.sleep(180)

        while 1:
            log.debug('FG-INFO: Default credentials assessment started')

            # Finding targets for Ncrack
            try:
                targets = {}
                for ip in homenet.hosts.keys():
                    print ip
                    port_list = []
                    for port in homenet.hosts[ip].tcp_ports:
                        print port
                        if port in self.target_ports:
                            port_list.append(str(port))
                    if len(port_list) > 0:
                        targets[ip] = port_list
            except Exception as e:
                log.debug('FG-ERROR: ' + str(e.__doc__) + " - " + str(e.message))

            if len(targets) > 0:
                for ip in targets.keys():
                    self.brute_force(ip, ','.join(targets[ip]))

            log.debug('FG-INFO: Default credentials assessment finished')

            time.sleep(86400)

    def brute_force(self, tip, ports):
        global homenet
        global lock
        print 'Now attacking', tip, 'on ports', ports
        proc = subprocess.Popen(['ncrack', '-v', '-T', '5', '-U', '/tmp/default_users.csv',
                                 '-P', '/tmp/default_passwords.csv', '-p', ports, tip],
                                stdout=subprocess.PIPE)
        for line in proc.stdout:
            print line
            groups = re.findall(self.ncrack_regex, line.strip())
            if len(groups) == 5:
                print groups
                try:
                    with lock:
                        new_issue = DefaultCredentials()
                        new_issue.service = groups[0]
                        new_issue.port = groups[2]
                        new_issue.user = groups[3]
                        new_issue.password = groups[4]
                        homenet.hosts[tip].vuln_accounts.append(new_issue)
                except Exception as e:
                    log.debug('FG-ERROR: ' + str(e.__doc__) + " - " + str(e.message))

