import threading
import requests
import time
import sqlite3 as lite
from lib.logger import *
import string
import re
import urllib2
from datetime import datetime
from lib.config import *
import lib.utils as utils


url_list = {'Malware': ['http://malc0de.com/bl/IP_Blacklist.txt',
                        'https://sslbl.abuse.ch/blacklist/sslipblacklist.csv',
                        'http://rules.emergingthreats.net/blockrules/emerging-dshield.rules',
                        'https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt'],
            'Botnet': ['http://rules.emergingthreats.net/blockrules/emerging-botcc.rules'],
            'Hacking': ['http://rules.emergingthreats.net/blockrules/compromised-ips.txt',
                        'http://rules.emergingthreats.net/blockrules/emerging-ciarmy.rules',
                        'https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.csv'],
            'Tor': ['https://check.torproject.org/exit-addresses',
                    'https://www.dan.me.uk/torlist/',
                    'https://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv']}


class Domain:
    def __init__(self):
        self.name = ""
        self.detected_urls = 0
        self.detected_comm_payloads = 0
        self.detected_down_payloads = 0
        self.categories = []


class DownloadIntel(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.ip_regex = re.compile(r"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
        self.headers = {'User-Agent': 'Mozilla/5.0'}
        self.all_ips = []

    def run(self):
        log.debug('Downloading daily blacklists')

        while 1:
            del self.all_ips[:]

            with lock:
                homenet.bad_ips.clear()

            self.retrieve_bad_ips()

            utils.flush_ipset_list('blacklist')

            fout = open('/tmp/ip_blacklist', 'w')

            with lock:
                myset = set(self.all_ips)

            for entry in myset:
                if len(entry) >= 7:
                    fout.write('add blacklist ' + entry + '\n')
            fout.close()
            utils.restore_ipset_blacklist('/tmp/ip_blacklist')

            time.sleep(14400)

    def retrieve_bad_ips(self):
        # Downloading Intel from open sources
        for threat in url_list.keys():
            homenet.bad_ips[threat] = []
            for url in url_list[threat]:
                req = urllib2.Request(url, None, self.headers)
                try:
                    response = urllib2.urlopen(req)
                except Exception:
                    log.debug('Error while retrieving the bad IPs from: ' + url)
                    continue
                entries = re.findall(self.ip_regex, response.read())
                for ip in entries:
                    if ip[3] == 0:
                        continue
                    else:
                        ip = self.buildIP(ip)
                        with lock:
                            if ip not in homenet.user_whitelist:
                                homenet.bad_ips[threat].append(ip)
                                self.all_ips.append(ip)

        # Adding user blacklisted IP addresses
        with lock:
            homenet.bad_ips['user_blacklist'] = []
            homenet.bad_ips['user_blacklist'] = homenet.bad_ips['user_blacklist'] + homenet.blacklist
            self.all_ips = self.all_ips + homenet.blacklist

    def buildIP(self, tupla):
        return tupla[0] + '.' + tupla[1] + '.' + tupla[2] + '.' + tupla[3]

    def write_to_db(self):
        conn = lite.connect('ip_blacklist.sqlite')
        cur = conn.cursor()
        cur.execute("delete from ip_blacklist")
        conn.commit()
        for entry in self.ip_list:
            try:
                cur.execute("INSERT INTO ip_blacklist (ip) VALUES('%s')" % entry)
            except lite.IntegrityError:
                pass
        conn.commit()
        conn.close()


class CheckVirusTotalIntel(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID

    def run(self):
        global homenet
        global lock

        while 1:
            dns_lookup_list = {}
            file_lookup_list = {}
            if homenet.vt_api_key:
                with lock:
                    for k, host in homenet.hosts.iteritems():
                        # Get all DNS entries which need VT lookup
                        for k1, dns in host.dns.iteritems():
                            if not dns.bad:
                                if dns.sld not in dns_lookup_list:
                                    dns_lookup_list[dns.sld] = [k]
                                else:
                                    dns_lookup_list[dns.sld].append(k)

                        # Get all files which need VT lookup
                        for k1, f in host.files.iteritems():
                            if not f.vt_flag:
                                if f.sha1 not in file_lookup_list:
                                    file_lookup_list[f.sha1] = [k]
                                else:
                                    file_lookup_list[f.sha1].append(k)

                # Processing files first and updating homenet for obvious reasons
                files = file_lookup_list.keys()
                if len(files) > 0:
                    while len(files) > 0:
                        process = files[:4]
                        for fhash in process:
                            res = self.eval_vt_intel_file(fhash)
                            if res is None:
                                continue
                            else:
                                try:
                                    for host in file_lookup_list[fhash]:
                                        with lock:
                                            tmp = homenet.hosts[host].files[fhash]
                                            tmp.vt_flag = True
                                            tmp.vt_positives = res["positives"]
                                            tmp.vt_report = res["report"]
                                            homenet.hosts[host].files[fhash] = tmp
                                except KeyError:
                                    pass
                        del files[:4]
                        time.sleep(62)

                domains = dns_lookup_list.keys()
                if len(domains) > 0:
                    while len(domains) > 0:
                        process = domains[:4]
                        for d in process:
                            val = self.eval_vt_intel_domain(d)
                            if val is None:
                                continue
                            else:
                                try:
                                    for host in dns_lookup_list[d]:
                                        with lock:
                                            tmp = homenet.hosts[host].dns[d]
                                            tmp.bad = val
                                            homenet.hosts[host].dns[d] = tmp
                                except KeyError:
                                    pass
                        del domains[:4]
                        time.sleep(62)
            else:
                pass
            time.sleep(10)

    @staticmethod
    def eval_vt_intel_file(fhash):
        params = {'resource': fhash, 'apikey': homenet.vt_api_key}
        headers = {"Accept-Encoding": "gzip, deflate",
                   "User-Agent": "My python example client"}

        try:
            response = requests.get(homenet.vt_api_file_url, params=params, headers=headers)
            response_json = response.json()
        except Exception:
            log.debug("There were some issues while connecting to VirusTotal's API")
            return None

        if response_json["response_code"] == 1:
            res = {"positives": int(response_json["positives"]), "report": response_json["permalink"]}
            return res
        else:
            return None

    @staticmethod
    def eval_vt_intel_domain(domain):
        ctime = int(time.time())
        params = {'domain': domain, 'apikey': homenet.vt_api_key}
        headers = {"Accept-Encoding": "gzip, deflate",
                   "User-Agent": "My python example client"}
        try:
            response = requests.get(homenet.vt_api_domain_url, params=params, headers=headers)
            response_json = response.json()
        except Exception:
            log.debug("There were some issues while connecting to VirusTotal's API")
            return None
        domain = Domain()
        domain.name = domain
        try:
                domain.categories = response_json["categories"]

                try:
                    durls = response_json['detected_urls']
                    count = 0
                    for u in durls:
                        d = u["scan_date"]
                        d = datetime.strptime(d, '%Y-%m-%d %H:%M:%S')
                        ts = time.mktime(d.timetuple())
                        if ts > (ctime - 2592000):
                            count += 1
                    domain.detected_urls = count
                except Exception as e:
                    log.debug(e.__doc__ + " - " + e.message)

                try:
                    samples = response_json['detected_communicating_samples']
                    count = 0
                    for s in samples:
                        d = s["date"]
                        d = datetime.strptime(d, '%Y-%m-%d %H:%M:%S')
                        ts = time.mktime(d.timetuple())
                        if ts > (ctime - 2592000):
                            count += 1
                        domain.detected_comm_payloads = count
                except Exception as e:
                    log.debug(e.__doc__ + " - " + e.message)

                try:
                    samples = response_json['detected_downloaded_samples']
                    count = 0
                    for s in samples:
                        d = s["date"]
                        d = datetime.strptime(d, '%Y-%m-%d %H:%M:%S')
                        ts = time.mktime(d.timetuple())
                        if ts > (ctime - 2592000):
                            count += 1
                        domain.detected_down_payloads = count
                except Exception as e:
                    log.debug(e.__doc__ + " - " + e.message)

        except Exception as e:
            log.debug(e.__doc__ + " - " + e.message)

        if (domain.detected_urls > 1) or (domain.detected_comm_payloads > 1) or (domain.detected_down_payloads > 1):
            return True
        else:
            return False


def get_top_domains(dbname):
    con = lite.connect(dbname)
    con.text_factory = str
    with con:
        cur = con.cursor()
        cur.execute("SELECT domain FROM domains")
        rows = cur.fetchall()
        domains = []
        if rows:
            for row in rows:
                domains.append(row[0])
        else:
            pass
        return domains
