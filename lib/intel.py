import threading
import requests
from lib.logger import *
import os
import shutil
import time
import gzip
import re
from datetime import datetime
from lib.config import *
import lib.utils as utils
import lib.settings as settings
from lib.settings import homenet, lock, top_domains

# Reused across requests so TCP/TLS connections are pooled instead of a new
# handshake per call. urllib3's connection pool is safe for concurrent requests.
session = requests.Session()


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
        # Hydra default-credentials list: refreshed weekly from the remote
        # SecLists lists, with a bundled seed used until the first download
        # succeeds (or whenever the remote is unreachable).
        self.creds_file = '/tmp/default_creds.csv'
        self.creds_seed = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'default_creds.csv')
        self.creds_refresh_interval = 604800  # 7 days, in seconds
        self.last_creds_refresh = 0
        # Detection-only domain blocklists (blocklistproject, public domain /
        # Unlicense). These feed alerting only - they are never blackholed.
        # Refreshed weekly from the plain-domain ("-nl") variants; the bundled
        # gzip is the offline fallback. Category order sets precedence when a
        # domain appears in several lists (worst first).
        self.detect_base_url = 'https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version'
        self.detect_categories = ['malware', 'ransomware', 'phishing', 'fraud', 'scam',
                                  'abuse', 'crypto', 'drugs', 'gambling', 'vaping']
        self.detect_seed = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'detect_domains.csv.gz')
        self.detect_refresh_interval = 604800  # 7 days, in seconds
        self.last_detect_refresh = 0

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

                # Retrieving intel from the premium (subscribed) feed, if enabled
                self.retrieve_premium_intel()

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

            # Refresh the Hydra default-credentials list about once a week, and
            # whenever the file is missing (e.g. after a reboot clears /tmp). On
            # failure last_creds_refresh is left unchanged so the next 4h cycle
            # retries until a download succeeds.
            now = int(time.time())
            if (now - self.last_creds_refresh) >= self.creds_refresh_interval \
                    or not os.path.isfile(self.creds_file):
                if self.retrieve_default_creds():
                    self.last_creds_refresh = now

            # Refresh the detection-only domain blocklists about once a week, and
            # whenever the in-memory map is empty (e.g. just after start). Done
            # outside the lock: it rebinds settings.detect_domains atomically and
            # building the multi-million-entry map must not block other threads.
            # On failure last_detect_refresh is left unchanged so the next 4h
            # cycle retries until a download succeeds.
            if (now - self.last_detect_refresh) >= self.detect_refresh_interval \
                    or not settings.detect_domains:
                if self.refresh_detect_domains():
                    self.last_detect_refresh = now

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
                        response = session.get(url, headers=self.headers, verify=False)
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
                        response = session.get(url, headers=self.headers, verify=False)
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
            response = session.get(homenet.fg_intel_ip, headers=headers, verify=False)
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
            response = session.get(homenet.fg_intel_domains, headers=headers, verify=False)
            rjson = response.json()
            for threat in rjson.keys():
                set1 = set(homenet.bad_domains[threat])
                set2 = set(rjson[threat])
                homenet.bad_domains[threat] = list(set1 | set2)
        except Exception as e:
            log.debug('FG-ERROR: There was an error while downloading the domain blacklist - ' + str(e))

    def retrieve_default_creds(self):
        # Download the SecLists default-credential lists, normalise each line
        # into Hydra's "-C" login:password format and merge them into a single
        # deduplicated file for brute_force_service(). Returns True only if at
        # least one remote list was fetched and the merged file was written, so
        # the caller keeps retrying (and the existing file is left untouched)
        # until a refresh actually succeeds.
        entries = []
        seen = set()
        downloaded = False
        for url in homenet.fg_intel_creds:
            if not url:
                continue
            try:
                response = session.get(url, headers=self.headers, verify=False)
                if response.status_code == 200 and response.text:
                    downloaded = True
                    for line in response.text.splitlines():
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        # Password-only lists (e.g. VNC) have no username; Hydra's
                        # -C format still needs a colon, so use an empty login.
                        if ':' not in line:
                            line = ':' + line
                        if line not in seen:
                            seen.add(line)
                            entries.append(line)
            except Exception as e:
                log.debug('FG-ERROR: Error while downloading default credentials from ' + url + ' - ' + str(e))

        if downloaded and entries:
            try:
                with open(self.creds_file, 'w') as fout:
                    fout.write('\n'.join(entries) + '\n')
                log.debug('FG-INFO: Refreshed default credentials list - ' + str(len(entries)) + ' entries')
                return True
            except Exception as e:
                log.debug('FG-ERROR: Could not write ' + self.creds_file + ' - ' + str(e))
                return False

        # Remote refresh failed: make sure Hydra still has a list to work with
        # by seeding from the bundled copy if none is present yet.
        if not os.path.isfile(self.creds_file):
            try:
                shutil.copyfile(self.creds_seed, self.creds_file)
                log.debug('FG-INFO: Seeded default credentials from bundled list ' + self.creds_seed)
            except Exception as e:
                log.debug('FG-ERROR: Could not seed default credentials from ' + self.creds_seed + ' - ' + str(e))
        return False

    def load_detect_seed(self):
        # Load the bundled gzipped blocklistproject lists ("domain,category" per
        # line) into a fresh {domain: category} map and rebind it atomically.
        # Used as the offline fallback when the remote refresh fails.
        dmap = {}
        try:
            with gzip.open(self.detect_seed, 'rt', encoding='utf-8', errors='replace') as fin:
                for line in fin:
                    domain, _, category = line.strip().partition(',')
                    if domain and category:
                        dmap[domain] = category
            settings.detect_domains = dmap
            log.debug('FG-INFO: Loaded detection domains from bundled seed - ' + str(len(dmap)) + ' entries')
            return True
        except Exception as e:
            log.debug('FG-ERROR: Could not load detection seed ' + self.detect_seed + ' - ' + str(e))
            return False

    def download_detect_domains(self):
        # Download the plain-domain blocklistproject lists for each category and
        # build a {domain: category} map. Categories are processed worst-first so
        # a domain listed in several keeps its most severe category. Returns the
        # map on success, or None if nothing could be downloaded.
        dmap = {}
        downloaded = False
        for category in self.detect_categories:
            url = self.detect_base_url + '/' + category + '-nl.txt'
            try:
                response = session.get(url, headers=self.headers, verify=False)
                if response.status_code == 200 and response.text:
                    downloaded = True
                    for line in response.text.splitlines():
                        domain = line.strip()
                        if not domain or domain.startswith('#'):
                            continue
                        if domain not in dmap:
                            dmap[domain] = category
            except Exception as e:
                log.debug('FG-ERROR: Error while downloading detection domains from ' + url + ' - ' + str(e))
        if downloaded and dmap:
            return dmap
        return None

    def refresh_detect_domains(self):
        # Refresh the detection blocklist. Frees the current map before building
        # the new one so memory does not spike to ~2x the (multi-million entry)
        # map. Falls back to the bundled seed when the remote is unreachable.
        # Returns True only when a fresh remote copy was loaded.
        if settings.detect_domains:
            settings.detect_domains = {}
        dmap = self.download_detect_domains()
        if dmap:
            settings.detect_domains = dmap
            log.debug('FG-INFO: Refreshed detection domains - ' + str(len(dmap)) + ' entries')
            return True
        # Remote failed: make sure detection still has data to work with.
        if not settings.detect_domains:
            self.load_detect_seed()
        return False

    def retrieve_premium_intel(self):
        # Pull the premium (subscribed) threat-intel feed from the authenticated
        # endpoint using the account API key. The endpoint is expected to return
        # JSON of the form {"ips": {category: [...]}, "domains": {category: [...]}}.
        # Entries are merged into the existing blacklists (same semantics as the
        # public FalconGate feed). No-op when no key/URL is configured. Must be
        # called while holding the lock (it mutates the shared blacklists).
        if not homenet.fg_api_key or not homenet.fg_premium_url:
            return
        headers = dict(self.headers)
        headers['Authorization'] = 'Bearer ' + homenet.fg_api_key
        try:
            response = session.get(homenet.fg_premium_url, headers=headers, verify=False)
            if response.status_code in (401, 403):
                log.debug('FG-ERROR: Premium feed rejected the API key (HTTP ' + str(response.status_code) + ')')
                return
            if response.status_code != 200:
                log.debug('FG-ERROR: Premium feed returned HTTP ' + str(response.status_code))
                return
            rjson = response.json()
        except Exception as e:
            log.debug('FG-ERROR: There was an error while downloading the premium feed - ' + str(e))
            return

        for threat, values in rjson.get('ips', {}).items():
            if threat in homenet.bad_ips:
                homenet.bad_ips[threat] = list(set(homenet.bad_ips[threat]) | set(values))
        for threat, values in rjson.get('domains', {}).items():
            if threat in homenet.bad_domains:
                homenet.bad_domains[threat] = list(set(homenet.bad_domains[threat]) | set(values))
        log.debug('FG-INFO: Merged premium threat intel feed')


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
            response = session.get(homenet.vt_api_file_url, params=params, headers=headers, verify=False)
            response_json = response.json()
        except Exception as e:
            log.debug('FG-ERROR: There were some issues while connecting to VirusTotal API - ' + str(e.__doc__) + " - " + str(e))
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
            response = session.get(homenet.vt_api_domain_url, params=params, headers=headers, verify=False)
            response_json = response.json()
        except Exception as e:
            log.debug('FG-ERROR: There were some issues while connecting to VirusTotal API - ' + str(e.__doc__) + " - " + str(e))
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
