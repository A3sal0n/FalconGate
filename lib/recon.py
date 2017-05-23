import threading
from lib.logger import *
import lib.utils as utils
import time
import socket
from Queue import Queue


class PortScanner(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.ctime = int(time.time())

    def run(self):
        global homenet
        global lock
        global hosts_tcp
        global scan_lock
        num_threads = 10

        scan_lock = threading.Lock()

        # Wait until all active devices have been recorded during boot
        time.sleep(60)

        while 1:
            hosts_tcp = {}

            try:
                for k in homenet.hosts.keys():
                    hosts_tcp[homenet.hosts[k].ip] = []
            except Exception as e:
                print e

            if len(hosts_tcp) > 0:
                log.debug('FG-INFO: Port scan started')
                print 'Port scan started'
                threads = []
                q = Queue(maxsize=0)

                for i in range(num_threads):
                    worker = threading.Thread(target=self.port_scan, args=(q,))
                    worker.daemon = True
                    threads.append(worker)
                    worker.start()

                for ip in hosts_tcp.keys():
                    for port in range(1, 10000):
                        q.put([ip, 'tcp', port])

                q.join()

                for i in range(10):
                    q.put(None)

                with lock:
                    for k in homenet.hosts.keys():
                        homenet.hosts[k].tcp_ports = hosts_tcp[k]
                        #homenet.hosts[k].udp_ports = hosts[k]['udp']

                log.debug('FG-INFO: Port scan finished')

            time.sleep(86400)

    def port_scan(self, q):
        global hosts_tcp
        global scan_lock
        try:
            while True:
                target = q.get()
                if target is None:
                    break
                if target[1] == 'tcp':
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(0.2)
                result = sock.connect_ex((target[0], target[2]))
                if result == 0:
                    with scan_lock:
                        hosts_tcp[target[0]].append(target[2])
                        print target[0], "- Port {}: 	 Open".format(target[2])
                else:
                    pass
                sock.close()
                q.task_done()
        except Exception:
            pass
