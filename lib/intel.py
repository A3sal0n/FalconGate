import threading
import requests
from lib.logger import *
import re
from datetime import datetime
from lib.config import *
import lib.utils as utils
from lib.settings import homenet, lock, top_domains


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
        self.ip_regex = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
        self.domain_regex = re.compile(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}')
        self.headers = {'User-Agent': 'Mozilla/5.0'}
        self.all_ips = set()
        self.all_domains = set()

    def run(self):
        time.sleep(60)

        while 1:
            log.debug('FG-INFO: Downloading daily blacklists')

            # Clearing old intel
            self.all_ips.clear()
            self.all_domains.clear()

            with lock:
                # Clearing old intel
                for threat in homenet.bad_ips.keys():
                    del homenet.bad_ips[threat][:]
                for threat in homenet.bad_domains.keys():
                    del homenet.bad_domains[threat][:]

                # Retrieving intel from local sources
                self.retrieve_bad_ips()
                self.retrieve_bad_domains()

                # Retrieving intel from Falcongate public API
                self.retrieve_fg_intel()

                for threat in homenet.bad_ips.keys():
                    for ip in homenet.bad_ips[threat]:
                        if ip not in homenet.user_whitelist:
                            self.all_ips.add(ip)

                for threat in homenet.bad_domains.keys():
                    for domain in homenet.bad_domains[threat]:
                        if domain not in homenet.user_domain_whitelist:
                            self.all_domains.add(domain)

                # Adding user blacklisted domains
                for entry in homenet.user_domain_blacklist:
                    if entry not in homenet.user_domain_whitelist:
                        self.all_domains.add(entry)

                # Adding user blacklisted IP addresses
                utils.flush_ipset_list('blacklist-user')
                for ip in homenet.user_blacklist:
                    if ip not in homenet.user_whitelist:
                        utils.add_ip_ipset_blacklist(ip, 'blacklist-user')

                # Reconfiguring ipset and dnsmasq with the new block lists
                # Blocking IP addresses from threat intel open sources it's disabled by default. Remove the comment in the line below to enable at your own risk :)
                #self.configure_ipset()
                self.configure_dnsmasq()

            time.sleep(14400)

    def configure_ipset(self):
        utils.flush_ipset_list('blacklist')

        fout = open('/tmp/ip_blacklist', 'w')

        for entry in self.all_ips:
            if len(entry) >= 7:
                fout.write('add blacklist ' + entry + '\n')
        fout.close()
        utils.restore_ipset_blacklist('/tmp/ip_blacklist')

    def configure_dnsmasq(self):
        fout = open('/etc/dnsmasq.block', 'w')
        fout.write("127.0.0.1\tlocalhost\n")
        fout.write("::1\tlocalhost #[IPv6]\n")
        for entry in self.all_domains:
            fout.write('127.0.0.1' + '\t' + entry + '\n')
        fout.close()
        utils.restart_dnsmasq()

    def retrieve_bad_ips(self):
        # Downloading Intel from open sources
        for threat in homenet.blacklist_sources_ip.keys():
            for url in homenet.blacklist_sources_ip[threat]:
                if len(url) > 0:
                    try:
                        response = requests.get(url, headers=self.headers)
                        entries = re.findall(self.ip_regex, response.content)
                        for ip in entries:
                            if ip not in homenet.user_whitelist:
                                homenet.bad_ips[threat].append(ip)
                    except Exception as e:
                        log.debug('FG-ERROR: Error while retrieving the bad IPs from: ' + url)

    def retrieve_bad_domains(self):
        # Downloading Intel from open sources
        for threat in homenet.blacklist_sources_domain.keys():
            for url in homenet.blacklist_sources_domain[threat]:
                if len(url) > 0:
                    try:
                        response = requests.get(url, headers=self.headers)
                        txt = response.text
                        lines = txt.split('\n')
                        for line in lines:
                            if (len(line) > 0) and (line[0] != '#'):
                                entries = re.findall(self.domain_regex, line)
                                for domain in entries:
                                    homenet.bad_domains[threat].append(domain)
                    except Exception as e:
                        log.debug('FG-ERROR: Error while retrieving the bad domains from: ' + url)

    def retrieve_fg_intel(self):
        headers = {"User-Agent": "Mozilla/5.0"}

        # Downloading the list of malicious IP addresses
        try:
            response = requests.get(homenet.fg_intel_ip, headers=headers)
            rjson = response.json()
            for threat in rjson.keys():
                if threat == 'Tor' and homenet.allow_tor == 'true':
                    pass
                else:
                    set1 = set(homenet.bad_ips[threat])
                    set2 = set(rjson[threat])
                    homenet.bad_ips[threat] = list(set1 | set2)
        except Exception as e:
            log.debug('FG-ERROR: There was an error while downloading the IP blacklist - ' + str(e))

        # Downloading the list of malicious domains
        try:
            response = requests.get(homenet.fg_intel_domains, headers=headers)
            rjson = response.json()
            for threat in rjson.keys():
                set1 = set(homenet.bad_domains[threat])
                set2 = set(rjson[threat])
                homenet.bad_domains[threat] = list(set1 | set2)
        except Exception as e:
            log.debug('FG-ERROR: There was an error while downloading the domain blacklist - ' + str(e))

        # Downloading the list of default user names and passwords
        try:
            response = requests.get(homenet.fg_intel_creds, headers=headers)
            fout = open('/tmp/default_creds.csv', 'w')
            fout.write(response.text)
            fout.close()
        except Exception as e:
            log.debug('FG-ERROR: There was an error while downloading the list of default credentials - ' + str(e))


class CheckVirusTotalIntel(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID

    def run(self):

        while 1:
            dns_lookup_list = {}
            file_lookup_list = {}
            if homenet.vt_api_key:
                with lock:
                    for k, host in homenet.hosts.items():
                        # Get all DNS entries which need VT lookup
                        for k1, dns in host.dns.items():
                            if not dns.bad:
                                if dns.sld not in top_domains:
                                    if dns.sld not in dns_lookup_list:
                                        dns_lookup_list[dns.sld] = [k]
                                    else:
                                        dns_lookup_list[dns.sld].append(k)

                        # Get all files which need VT lookup
                        for k1, f in host.files.items():
                            if not f.vt_flag:
                                if f.sha1 not in file_lookup_list:
                                    file_lookup_list[f.sha1] = [k]
                                else:
                                    file_lookup_list[f.sha1].append(k)

                # Processing files first and updating homenet for obvious reasons
                files = list(file_lookup_list.keys())
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

                domains = list(dns_lookup_list.keys())
                time.sleep(10)
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
                   "User-Agent": "Mozilla/5.0"}

        try:
            response = requests.get(homenet.vt_api_file_url, params=params, headers=headers)
            response_json = response.json()
        except Exception as e:
            log.debug('FG-ERROR: There were some issues while connecting to VirusTotal API')
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
                   "User-Agent": "Mozilla/5.0"}
        try:
            response = requests.get(homenet.vt_api_domain_url, params=params, headers=headers)
            response_json = response.json()
        except Exception as e:
            log.debug('FG-ERROR: There were some issues while connecting to VirusTotal API')
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
                    log.debug('FG-DEBUG: ' + str(e.__doc__) + " - " + str(e))

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
                    log.debug('FG-DEBUG: ' + str(e.__doc__) + " - " + str(e))

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
                    log.debug('FG-DEBUG: ' + str(e.__doc__) + " - " + str(e))

        except Exception as e:
            log.debug('FG-DEBUG: ' + str(e.__doc__) + " - " + str(e))

        if (domain.detected_urls > 1) or (domain.detected_comm_payloads > 1) or (domain.detected_down_payloads > 1):
            return True
        else:
            return False
