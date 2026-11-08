import threading
from lib.logger import *
import lib.utils as utils
import time
import requests
from lib.settings import homenet, lock

# Reused across requests so TCP/TLS connections are pooled instead of a new
# handshake per call.
session = requests.Session()

# Detection blocklist categories alerted on as soon as they are observed. Hits
# in any other category are bundled per device and reported hourly.
IMMEDIATE_CATEGORIES = ('malware', 'ransomware', 'phishing', 'fraud', 'scam', 'abuse')

CATEGORY_REFERENCE = 'https://github.com/blocklistproject/Lists'

CATEGORY_DESCRIPTIONS = {
    'malware': 'These domains are known to distribute or control Malware. This could indicate an active '
               'infection on this host.',
    'ransomware': 'These domains are associated with Ransomware, which encrypts data and demands payment to '
                  'unlock it. Check this host immediately and make sure your backups are safe.',
    'phishing': 'These domains are used to trick people into giving away passwords or personal data. If anything '
                'was entered on this site, change those passwords.',
    'fraud': 'These domains are associated with online fraud. Be careful with any payment or personal details '
             'shared with this site.',
    'scam': 'These domains are associated with online scams. Do not trust offers or requests from this site.',
    'abuse': 'These domains are associated with abusive or deceptive activity. This could indicate unwanted '
             'software or behaviour on this host.',
    'crypto': 'These domains are associated with cryptocurrency mining or cryptojacking. This host\'s resources '
              'could be in use without its owner knowing.',
    'drugs': 'These domains are related to drugs. Check that this activity is expected on this device.',
    'gambling': 'These domains are related to online gambling. Check that this activity is expected on this device.',
    'vaping': 'These domains are related to vaping products. Check that this activity is expected on this device.',
}


def is_immediate(dns):
    return dns.category in IMMEDIATE_CATEGORIES


def is_bundled(dns):
    return bool(dns.category) and not is_immediate(dns)


def create_bad_domain_alert(src, dst, ctime):
    dns = homenet.hosts[src].dns[dst]
    reference = 'https://www.virustotal.com/en/domain/' + dns.query + '/information/'
    if dns.category:
        alert_type = dns.category
        threat = dns.category.capitalize()
        description = 'This host was detected trying to resolve the IP address of a domain on the ' + threat \
                      + ' detection blocklist. ' + CATEGORY_DESCRIPTIONS.get(dns.category, '')
        indicators = 'Category: ' + dns.category + '|' + dns.query
    else:
        alert_type = 'malware'
        threat = 'Malware'
        description = 'This host was detected trying to resolve the IP address of a domain flagged by ' \
                      'VirusTotal. This could indicate the presence of Malware on this host.'
        indicators = dns.query
    a = [0, alert_type, ctime, ctime, 0, 0, threat, src, indicators, 0, description.strip(), reference]
    alert_id = utils.add_alert_to_db(a)
    homenet.hosts[src].alerts.append(alert_id)


class DailyAlerts(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.headers = {'User-Agent': 'Mozilla/5.0'}
        self.ctime = None

    def run(self):

        while 1:
            self.ctime = int(time.time())
            self.get_pwnage()
            time.sleep(86400)

    def get_pwnage(self):
        pwnings = {}
        if len(homenet.email_watchlist) > 0:
            for a in homenet.email_watchlist:
                try:
                    r = session.get(homenet.hibp_api_url + a, headers=self.headers, verify=False)
                    if r.status_code == 200:
                        r_json = r.json()
                        if len(r_json) >= 1:
                            pwnings[a] = r_json
                except Exception as e:
                    log.debug('FG-ERROR: ' + str(e.__doc__) + " - " + str(e))
                time.sleep(1)

        if len(pwnings) > 0:
            for a in pwnings.keys():
                self.create_pwning_alert(a, pwnings[a])

    def create_pwning_alert(self, src, breaches):
        for breach in breaches:
            description = breach['Description']
            indicators = 'Site breached: ' + breach['Domain'] + '|' + 'BreachDate: ' + breach['BreachDate'] \
                         + '|' + 'AddedDate: ' + breach['AddedDate'] + '|' + 'StolenData: ' \
                         + ','.join(breach['DataClasses']) + '|' + 'Verified: ' + str(breach['IsVerified'])
            reference = homenet.hibp_api_url + src
            a = [0, 'data_breach', self.ctime, self.ctime, 0, 0, 'Data Breach', src, indicators, 0, description, reference]
            alert_id = utils.add_alert_to_db(a)


class HourlyAlerts(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.ctime = None

    def run(self):

        while 1:
            self.ctime = int(time.time())
            try:
                with lock:
                    for k in homenet.hosts.keys():
                        if homenet.hosts[k].mac != homenet.mac:
                            if len(homenet.hosts[k].dga_domains) >= 20:
                                self.create_dga_alert(k)
                                del homenet.hosts[k].dga_domains[:]
                            if len(homenet.hosts[k].spammed_domains) >= 20:
                                self.create_spamming_alert(k)
                                del homenet.hosts[k].spammed_domains[:]
                            self.create_bundled_domain_alert(k)
            except Exception as e:
                log.debug('FG-ERROR:' + str(e.__doc__) + " - " + str(e))
            time.sleep(3600)

    def create_bundled_domain_alert(self, src):
        # Entries stay in host.dns once bundled, so a domain looked up again is
        # not reported every hour; the 24 hour DNS cleanup eventually drops them.
        entries = [dns for dns in homenet.hosts[src].dns.values()
                   if dns.bad and is_bundled(dns) and not dns.bundled]
        if not entries:
            return
        entries.sort(key=lambda dns: (dns.category, dns.query))
        categories = sorted({dns.category for dns in entries})
        threat = ', '.join(category.capitalize() for category in categories)
        description = 'This host was detected trying to resolve the IP address of domains on the ' + threat \
                      + ' detection blocklists during the last hour.'
        for category in categories:
            description += ' ' + category.capitalize() + ': ' + CATEGORY_DESCRIPTIONS.get(category, '')
        indicators = '|'.join(dns.category.capitalize() + ': ' + dns.query for dns in entries)
        fseen = int(min(dns.ts for dns in entries))
        a = [0, 'bundled_domains', fseen, self.ctime, 0, 0, threat, src, indicators, 0, description.strip(),
             CATEGORY_REFERENCE]
        alert_id = utils.add_alert_to_db(a)
        homenet.hosts[src].alerts.append(alert_id)
        for dns in entries:
            dns.bundled = True

    def create_dga_alert(self, src):
        description = 'This host has been detected to perform a well-known Malware traffic ' \
                      'pattern: Domain Generation Algorithm (DGA). This is a strong indication ' \
                      'on the presence of active Malware on this device.'
        indicators = '|'.join(homenet.hosts[src].dga_domains)
        reference = 'https://en.wikipedia.org/wiki/Domain_generation_algorithm'
        a = [0, 'dga', self.ctime, self.ctime, 0, 0, 'Malware', src, indicators, 0, description, reference]
        alert_id = utils.add_alert_to_db(a)
        homenet.hosts[src].alerts.append(alert_id)

    def create_spamming_alert(self, src):
        description = 'This host has been detected to be requesting MX records for multiple ' \
                      'different domains in a short period of time. This could indicate that ' \
                      'this device it\'s infected with Malware with spamming capabilities.'
        indicators = '|'.join(homenet.hosts[src].spammed_domains)
        reference = 'https://en.wikipedia.org/wiki/Spamming'
        a = [0, 'spammer', self.ctime, self.ctime, 0, 0, 'Spammer', src, indicators, 0, description, reference]
        alert_id = utils.add_alert_to_db(a)
        homenet.hosts[src].alerts.append(alert_id)


class MinuteAlerts(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.ctime = int(time.time())

    def run(self):

        while 1:
            self.ctime = int(time.time())
            try:
                with lock:
                    # Iterate over snapshots (list(...)) because entries are
                    # deleted inside the loop; iterating a live dict view raises
                    # RuntimeError: "dictionary changed size during iteration".
                    for k in list(homenet.hosts.keys()):
                        if homenet.hosts[k].mac != homenet.mac:
                            # Checking for new DNS requests to malicious domains
                            for k1 in list(homenet.hosts[k].dns.keys()):
                                if homenet.hosts[k].dns[k1].bad and not is_bundled(homenet.hosts[k].dns[k1]):
                                    create_bad_domain_alert(k, k1, self.ctime)
                                    del homenet.hosts[k].dns[k1]
                            # Checking for new malicious file hashes
                            for k1 in list(homenet.hosts[k].files.keys()):
                                if homenet.hosts[k].files[k1].vt_positives > 2:
                                    self.create_bad_file_alert(k, k1)
                                    del homenet.hosts[k].files[k1]
                            # Checking for new connections to malicious IP addresses
                            for k1 in list(homenet.hosts[k].conns.keys()):
                                for threat in homenet.bad_ips.keys():
                                    if homenet.hosts[k].conns[k1].dst_ip in homenet.bad_ips[threat]:
                                        self.create_bad_ip_alert(threat, k, k1)
                                        del homenet.hosts[k].conns[k1]
                                        break
            except Exception as e:
                log.debug('FG-ERROR:' + str(e.__doc__) + " - " + str(e))
            time.sleep(60)

    def create_bad_file_alert(self, src, fid):
        description = 'This host was detected downloading a file known to be Malware or a ' \
                      'Malware vector according to VirusTotal. This file could be utilized ' \
                      'to infect this machine or could indicate the presence of active ' \
                      'Malware on this system.'
        indicators = "SHA1: " + homenet.hosts[src].files[fid].sha1
        reference = homenet.hosts[src].files[fid].vt_report
        a = [0, 'malware', self.ctime, self.ctime, 0, 0, 'Malware', src, indicators, 0, description, reference]
        alert_id = utils.add_alert_to_db(a)
        homenet.hosts[src].alerts.append(alert_id)

    def create_bad_ip_alert(self, threat, src, dst):
        description = 'This host has been detected trying to communicate with a malicious ' \
                      'IP address included in the local blacklist. This traffic was blocked ' \
                      'by Falcongate. This could be an indicator of the presence of Malware or hacker activity ' \
                      'on this host.'
        indicators = homenet.hosts[src].conns[dst].dst_ip
        reference = 'https://www.virustotal.com/en/ip-address/' + homenet.hosts[src].conns[dst].dst_ip + '/information/'
        a = [0, threat, self.ctime, self.ctime, 0, 0, threat, src, indicators, 0, description, reference]
        alert_id = utils.add_alert_to_db(a)
        homenet.hosts[src].alerts.append(alert_id)
