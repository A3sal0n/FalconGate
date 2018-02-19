import time
import datetime
import threading
from lib.logger import *
import lib.utils as utils
from lib.settings import homenet, lock, country_stats, hosts_stats
from lib.objects import *


class HourlyStats(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.conn_counters = {}
        self.ctime = None

    def run(self):
        time.sleep(60)

        while 1:
            now = datetime.datetime.now()
            if now.minute == 0:
                log.debug('FG-INFO: Collecting hourly statistics')
                self.ctime = int(time.time())
                self.get_country_stats()
                time.sleep(3480)
            else:
                time.sleep(1)

    def get_country_stats(self):
        for k in country_stats.keys():
            nstats = HourStats()
            country_stats[k].hourly_stats[self.ctime] = nstats

        for k in homenet.hosts.keys():
            if homenet.hosts[k].mac != homenet.mac:
                for cid in homenet.hosts[k].conns.keys():
                    if homenet.hosts[k].conns[cid].ts > (self.ctime - 3600) and homenet.hosts[k].conns[cid].direction == "outbound":
                        ccode = homenet.hosts[k].conns[cid].dst_country_code
                        cname = homenet.hosts[k].conns[cid].dst_country_name
                        try:
                            if ccode:
                                country_stats[ccode].hourly_stats[self.ctime].data_sent += homenet.hosts[k].conns[cid].client_bytes
                                country_stats[ccode].hourly_stats[self.ctime].data_received += homenet.hosts[k].conns[cid].server_bytes
                                country_stats[ccode].hourly_stats[self.ctime].pqt_sent += homenet.hosts[k].conns[cid].client_packets
                                country_stats[ccode].hourly_stats[self.ctime].pqt_received += homenet.hosts[k].conns[cid].server_packets
                                country_stats[ccode].hourly_stats[self.ctime].nconn += homenet.hosts[k].conns[cid].counter
                            else:
                                pass
                        except Exception as e:
                            log.debug('FG-ERROR: ' + str(e.__doc__) + " - " + str(e.message))
