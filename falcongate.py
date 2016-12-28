#!/usr/bin/env python

import os
import threading
import socket
import sys
import time
import netifaces
import netaddr
import lib.logparser as logparser
from lib.logger import *
import lib.config as config
import lib.intel as intel
from lib.objects import *
import lib.alerts as alerts
import lib.utils as utils
import lib.reporter as reporter
import api.api as api

# Global variables
# Master network object
try:
    homenet = utils.load_pkl_object("homenet.pkl")
except Exception as e:
    log.debug(e.__doc__ + " - " + e.message)
    homenet = Network()

# Master lock for threads
lock = threading.Lock()
# Master list of bad IP addresses
bad_ips = []
# Master whitelist of IP addresses
good_ips = []
# Top domains whitelist
top_domains = intel.get_top_domains("top_domains.sqlite")

# Creating global variables in the name space of core libraries
logparser.lock = lock
intel.lock = lock
alerts.lock = lock
utils.lock = lock
reporter.lock = lock
api.lock = lock
config.lock = lock
logparser.homenet = homenet
intel.homenet = homenet
alerts.homenet = homenet
utils.homenet = homenet
reporter.homenet = homenet
api.homenet = homenet
config.homenet = homenet
logparser.top_domains = top_domains
intel.top_domains = top_domains
alerts.top_domains = top_domains

# Master thread list
threads = {}
threads["config_reader"] = config.CheckConfigFileModification("config_reader")
threads["read_dhcp_leases"] = logparser.ReadDHCPLeases("read_dhcp_leases")
threads["read_bro_dns"] = logparser.ReadBroDNS("read_bro_dns")
threads["read_bro_conn"] = logparser.ReadBroConn("read_bro_conn")
threads["read_bro_files"] = logparser.ReadBroFiles("read_bro_files")
threads["read_bro_notice"] = logparser.ReadBroNotice("read_bro_notice")
threads["read_bro_http"] = logparser.ReadBroHTTP("read_bro_http")
threads["intel_download"] = intel.DownloadIntel("intel_download")
threads["vt_intel_lookup"] = intel.CheckVirusTotalIntel("vt_intel_lookup")
threads["clean_homenet"] = utils.CleanOldHomenetObjects("clean_homenet")
threads["alerts_hourly"] = alerts.HourlyAlerts("alerts_hourly")
threads["alerts_minute"] = alerts.MinuteAlerts("alerts_minute")
threads["alert_reporter"] = reporter.AlertReporter("alert_reporter")
threads["api"] = api.FlaskAPI("api")


# Global functions
def get_lock(name):
    global lock_socket   # Without this our lock gets garbage collected
    lock_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        lock_socket.bind('\0' + name)
    except socket.error:
        sys.exit()


def main():
    if not os.geteuid() == 0:
        log.debug('Script must be run as root')
        exit('Script must be run as root')

    global homenet
    global threads

    # Check if process is not runing already
    get_lock('falcongate_main')

    log.debug('main.py started')

    # Starting threads
    for key in threads.keys():
        threads[key].daemon = True
        threads[key].start()
        log.debug('Started thread ' + key)

    time.sleep(15)

    # Store process ID and other parameters for the main thread
    homenet.pid = os.getpid()
    homenet.executable = sys.executable
    homenet.args = sys.argv[:]

    # Retrieving network configuration from local eth0 interface and storing in global variables
    addrs = netifaces.ifaddresses(homenet.interface)

    ipinfo = addrs[socket.AF_INET][0]

    # Get MAC for eth0
    homenet.mac = addrs[netifaces.AF_LINK][0]['addr']

    # IP address for eth0
    homenet.ip = ipinfo['addr']

    # Netmask for eth0
    homenet.netmask = ipinfo['netmask']

    cidr = netaddr.IPNetwork('%s/%s' % (homenet.ip, homenet.netmask))

    # Network CIDR for eth0
    network = cidr.network
    homenet.net_cidr = netaddr.IPNetwork('%s/%s' % (network, homenet.netmask))

    # Get default gateway for eth0
    gws = netifaces.gateways()
    homenet.gateway = gws['default'][netifaces.AF_INET][0]

    log.debug('Starting main loop')

    while True:

        try:
            with lock:
                try:
                    """for k in homenet.hosts["192.168.0.149"].user_agents:
                        print k
                    print "Device family:", homenet.hosts["192.168.0.149"].device_family
                    print "OS family:", homenet.hosts["192.168.0.149"].os_family"""
                except Exception as e:
                    log.debug(e.__doc__ + " - " + e.message)

            flag = False
            while not flag:
                try:
                    with lock:
                        utils.save_pkl_object(homenet, "homenet.pkl")
                    flag = True
                except Exception as e:
                    log.debug(e.__doc__ + " - " + e.message)
                    time.sleep(2)

            time.sleep(30)

        except KeyboardInterrupt:
            log.debug('Process terminated by keyboard interrupt')
            print 'Have a nice day!'
            sys.exit(0)


if __name__ == '__main__':
    main()

