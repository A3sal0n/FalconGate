#!/opt/fg/bin/python3

import os
import socket
import sys
import time
import netifaces
import netaddr
import lib.settings as sett
import lib.logparser as logparser
from lib.logger import *
import lib.config as config
import lib.intel as intel
import lib.alerts as alerts
import lib.utils as utils
import lib.reporter as reporter
import lib.recon as recon
import lib.offensive as offensive
import api.api as api
import lib.stats as stats


# Create alert database if not there
utils.create_alert_db()

# Populating master thread list
sett.threads["config_reader"] = config.CheckConfigFileModification("config_reader")
sett.threads["check_net_config"] = config.CheckNetworkModifications("check_net_config")
sett.threads["read_dhcp_leases"] = logparser.ReadDHCPLeases("read_dhcp_leases")
sett.threads["read_bro_dns"] = logparser.ReadBroDNS("read_bro_dns")
sett.threads["read_bro_conn"] = logparser.ReadBroConn("read_bro_conn")
sett.threads["read_bro_files"] = logparser.ReadBroFiles("read_bro_files")
sett.threads["read_bro_notice"] = logparser.ReadBroNotice("read_bro_notice")
sett.threads["read_bro_http"] = logparser.ReadBroHTTP("read_bro_http")
sett.threads["intel_download"] = intel.DownloadIntel("intel_download")
sett.threads["vt_intel_lookup"] = intel.CheckVirusTotalIntel("vt_intel_lookup")
sett.threads["clean_homenet"] = utils.CleanOldHomenetObjects("clean_homenet")
sett.threads["alerts_daily"] = alerts.DailyAlerts("alerts_daily")
sett.threads["alerts_hourly"] = alerts.HourlyAlerts("alerts_hourly")
sett.threads["alerts_minute"] = alerts.MinuteAlerts("alerts_minute")
sett.threads["alert_reporter"] = reporter.AlertReporter("alert_reporter")
sett.threads["port_scanner"] = recon.PortScanner("port_scanner")
sett.threads["vuln_scanner"] = offensive.ScheduledScans("vuln_scanner")
sett.threads["net_stats"] = stats.HourlyStats("net_stats")
sett.threads["api"] = api.FlaskAPI("api")


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
        log.debug('FG-FATAL: Script must be run as root')
        exit('Script must be run as root')

    # Check if process is not runing already
    get_lock('falcongate_main')

    log.debug('FG-INFO: main.py started')

    # Store process ID and other parameters for the main thread
    sett.homenet.pid = os.getpid()
    sett.homenet.executable = sys.executable
    sett.homenet.args = sys.argv[:]

    # Starting threads
    for key in sett.threads.keys():
        sett.threads[key].daemon = True
        sett.threads[key].start()
        log.debug('FG-INFO: Started thread ' + key)

    time.sleep(15)

    try:

        # Retrieving network configuration from local eth0 interface and storing in global variables
        addrs = netifaces.ifaddresses(sett.homenet.interface)

        ipinfo = addrs[socket.AF_INET][0]


        # Get MAC for eth0
        sett.homenet.mac = addrs[netifaces.AF_LINK][0]['addr']

        # IP address for eth0
        sett.homenet.ip = ipinfo['addr']

        # Netmask for eth0
        sett.homenet.netmask = ipinfo['netmask']

        cidr = netaddr.IPNetwork('%s/%s' % (sett.homenet.ip, sett.homenet.netmask))

        # Network CIDR for eth0
        network = cidr.network
        sett.homenet.net_cidr = netaddr.IPNetwork('%s/%s' % (network, sett.homenet.netmask))

        # Get default gateway for eth0
        gws = netifaces.gateways()
        cgw = gws['default'][netifaces.AF_INET][0]

        sett.homenet.gateway = cgw

    except Exception as e:
        log.debug('FG-ERROR: Falcongate had issues detecting your network configuration')

    log.debug('FG-DEBUG: Starting main loop')

    while True:
        try:
            time.sleep(60)
        except KeyboardInterrupt:
            log.debug('FG-INFO: Process terminated by keyboard interrupt')
            print('Have a nice day!')
            sys.exit(0)


if __name__ == '__main__':
    main()

