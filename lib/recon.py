import threading
from lib.logger import *
import time
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser


class PortScanner(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID

    def run(self):
        global homenet
        global lock

        # Wait until all active devices have been populated during boot
        time.sleep(30)

        while 1:
            ip_list = ','.join(homenet.hosts.keys())

            log.debug('FG-INFO: Port scan started')

            nm = NmapProcess(targets=ip_list, options='-sU -sS --min-rate 5000 --max-retries 1 --max-rtt-timeout 100ms -p1-10000 ')
            nm.run()

            try:
                nmap_report = NmapParser.parse(nm.stdout)

                with lock:
                    for host in nmap_report.hosts:
                        if host.address in homenet.hosts.keys():
                            for serv in host.services:
                                if (serv.protocol == 'tcp') and (serv.state == 'open'):
                                    if serv.port not in homenet.hosts[host.address].tcp_ports:
                                        homenet.hosts[host.address].tcp_ports.append(serv.port)
                                if (serv.protocol == 'udp') and (serv.state == 'open'):
                                    if serv.port not in homenet.hosts[host.address].udp_ports:
                                        homenet.hosts[host.address].udp_ports.append(serv.port)
            except Exception as e:
                log.debug('FG-WARN: ' + str(e.__doc__) + " - " + str(e.message))

            log.debug('FG-INFO: Port scan finished')

            time.sleep(86400)
