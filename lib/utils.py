import socket
import base64
import sqlite3 as lite
import subprocess
import threading
import time
import re
from struct import unpack
from socket import AF_INET, inet_pton
import cPickle as pickle
from lib.logger import *
import os
import sys


class CleanOldHomenetObjects(threading.Thread):
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
                self.clean_old_host_objects()
            except Exception as e:
                log.debug(e.__doc__ + " - " + e.message)
            time.sleep(600)

    def clean_old_host_objects(self):
        with lock:
            for k in homenet.hosts.keys():
                # Cleaning old DNS entries
                for l in homenet.hosts[k].dns.keys():
                    if (self.ctime - homenet.hosts[k].dns[l].ts) > 86400:
                        del homenet.hosts[k].dns[l]

                # Cleaning old connections
                for l in homenet.hosts[k].conns.keys():
                    if (self.ctime - homenet.hosts[k].conns[l].lseen) > 3600:
                        del homenet.hosts[k].conns[l]

                # Cleaning old alerts
                for l in homenet.hosts[k].alerts.keys():
                    if ((self.ctime - homenet.hosts[k].alerts[l].last_seen) > 604800) and homenet.hosts[k].alerts[l].last_reported:
                        del homenet.hosts[k].alerts[l]

                # Cleaning old files
                for l in homenet.hosts[k].dns.keys():
                    if (self.ctime - homenet.hosts[k].files[l].ts) > 604800:
                        del homenet.hosts[k].files[l]


# Resolves all the IP addresses for a specific domain
# Returns an array with the addresses
def domain_resolver(domain):
    record = socket.gethostbyname_ex(domain)
    return record[2]


def get_sld_from_query(query):
    fields = query.split(".")
    return fields[-2]+"."+fields[-1]


def get_tld_from_query(query):
    fields = query.split(".")
    return fields[-1]


def encode_base64(s):
    return base64.b64encode(s)


def decode_base64(s):
    return base64.b64decode(s)


def get_vendor(mac):
        con = lite.connect('vendors.sqlite')
        with con:
            cur = con.cursor()
            tmac = mac.replace(':', '').upper()

            cur.execute("SELECT vendor from vendors where mac_id=?", (tmac[0:6],))
            row = cur.fetchone()
            if row:
                return row[0]
            else:
                pass
        con.close()


# Iptables manipulation routines
def block_ip(target, falcongate_ip):
    subprocess.call(["/sbin/iptables", "-t", "nat", "-A", "BlockIP", "-d", str(target), "-p", "tcp", "-m", "tcp", "--dport", "1:65535", "-j", "DNAT", "--to-destination", str(falcongate_ip)+":8080"])


def clean_blocked_ip(target, falcongate_ip):
    subprocess.call(["/sbin/iptables", "-t", "nat", "-D", "BlockIP", "-d", str(target), "-p", "tcp", "-m", "tcp", "--dport", "1:65535", "-j", "DNAT", "--to-destination", str(falcongate_ip)+":8080"])


def validate_ip(ip):
    aa = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip)
    if aa:
        return True
    else:
        return False


def validate_domain(domain):
    aa = re.match(r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$", domain)
    if aa:
        return True
    else:
        return False


def validate_base64(target_str):
    aa = re.match(r"^(?:[A-Za-z0-9+\/\/n]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{4})$", target_str)
    if aa:
        return True
    else:
        return False


def lookup(ip):
    f = unpack('!I', inet_pton(AF_INET, ip))[0]
    private = (
        [2130706432, 4278190080], # 127.0.0.0,   255.0.0.0   http://tools.ietf.org/html/rfc3330
        [3232235520, 4294901760], # 192.168.0.0, 255.255.0.0 http://tools.ietf.org/html/rfc1918
        [2886729728, 4293918720], # 172.16.0.0,  255.240.0.0 http://tools.ietf.org/html/rfc1918
        [167772160,  4278190080], # 10.0.0.0,    255.0.0.0   http://tools.ietf.org/html/rfc1918
    )
    for net in private:
        if (f & net[1]) == net[0]:
            return True
    return False


def flush_ipset_list(list_name):
    p = subprocess.Popen(["ipset", "flush", list_name], stdout=subprocess.PIPE)
    output, err = p.communicate()


def restore_ipset_blacklist(fpath):
    cmd = "ipset restore < " + fpath
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    output, err = p.communicate()


def add_ip_ipset_blacklist(ip, listname):
    cmd = "ipset add {} {}".format(listname, ip)
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    output, err = p.communicate()


def del_ip_ipset_blacklist(ip, listname):
    cmd = "ipset del {} {}".format(listname, ip)
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    output, err = p.communicate()


def list_ipset_blacklist(listname):
    cmd = "ipset list {}".format(listname)
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    output, err = p.communicate()
    lines = output.split('\n')
    return lines


def reboot_appliance():
    cmd = "reboot"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    output, err = p.communicate()


def kill_falcongate(pid):
    sys.stdout.flush()
    devnull = open(os.devnull, 'wb')
    subprocess.Popen(['nohup', '/etc/init.d/kill-falcongate.sh', str(pid)], stdout=devnull, stderr=devnull, shell=False)


def save_pkl_object(obj, filename):
    with open(filename, 'wb') as output:
        pickle.dump(obj, output, pickle.HIGHEST_PROTOCOL)
    return True


def load_pkl_object(filename):
    obj = pickle.load(open(filename, "rb"))
    return obj
