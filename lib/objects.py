class HostAlertTemplate:
    def __init__(self, homenet, alert):
        self.homenet = homenet
        self.alert = alert
        self.subject = "A " + alert[6] + " alert was reported for host " + alert[7]
        self.indicators = alert[8].replace('.', '[.]').split('|')
        self.references = alert[11].split('|')
        self.body = ''

    def create_body(self):
        self.body = "FalconGate has reported a " + self.alert[6] + " alert for the device below:\r\n\r\n" \
                    "IP address: " + self.alert[7] + "\r\n" \
                    "Hostname: " + str(self.homenet.hosts[self.alert[7]].hostname) + "\r\n" \
                    "MAC address: " + str(self.homenet.hosts[self.alert[7]].mac) + "\r\n" \
                    "MAC vendor: " + str(self.homenet.hosts[self.alert[7]].vendor) + "\r\n" \
                    "Operating system family: " + "\r\n".join(self.homenet.hosts[self.alert[7]].os_family) + "\r\n" \
                    "Device family: " + str("\r\n".join(self.homenet.hosts[self.alert[7]].device_family)) + "\r\n\r\n" \
                    "Description: " + self.alert[10] + "\r\n\r\n" \
                    "The following indicators were detected:\r\n" + str("\r\n".join(self.indicators)) + "\r\n\r\n" \
                    "References:\r\n" + str("\r\n".join(self.references)) + "\r\n\r\n" \
                    "This is the first time this incident is reported.\r\n" \
                    "We recommend to investigate this issue asap."


class AccountBreachAlertTemplate:
    def __init__(self, alert):
        self.alert = alert
        self.subject = "A " + alert[6] + " alert was reported for account " + alert[7]
        self.indicators = alert[8].split('|')
        self.references = alert[11].split('|')
        self.body = ''

    def create_body(self):
        self.body = "FalconGate has reported a " + self.alert[6] + " alert:\r\n\r\n" \
                    "Account at risk: " + self.alert[7] + "\r\n\r\n" \
                    "Description: " + self.alert[10] + "\r\n\r\n" \
                    "The following indicators were detected:\r\n" + str("\r\n".join(self.indicators)) + "\r\n\r\n" \
                    "References:\r\n" + str("\r\n".join(self.references)) + "\r\n\r\n" \
                    "This is the first time this incident is reported.\r\n" \
                    "We recommend to change immediately the password for this account to prevent further misuse by" \
                    " malicious hackers."


class DNSRequest:
    def __init__(self):
        self.ts = None
        self.lseen = None
        self.query = None
        self.sld = None
        self.tld = None
        self.cip = None
        self.sip = None
        self.qtype = None
        self.qresult = None
        self.bad = False
        self.counter = 0


class HTTPObject:
    def __init__(self):
        self.ts = None
        self.lseen = None
        self.src_ip = None
        self.dst_ip = None
        self.dest_port = None
        self.host = None
        # {'url': ['method', 'status_code', 'user_agent', 'referrer', 'response_body_len', 'proxied', 'mime_type']}
        self.urls = {}


class Conn:
    def __init__(self):
        self.ts = None
        self.lseen = None
        self.src_ip = None
        self.dst_ip = None
        self.dst_port = None
        self.proto = None
        self.service = None
        self.duration = 0
        self.client_bytes = 0
        self.server_bytes = 0
        self.client_packets = 0
        self.server_packets = 0
        self.country_code = None
        self.counter = 0


class PortScan:
    def __init__(self):
        self.ts = None
        self.lseen = None
        self.src_ip = None
        self.dst_ip = None
        self.duration = None


class Host:
    def __init__(self):
        self.ts = None
        self.lseen = None
        self.mac = None
        self.ip = None
        self.hostname = None
        self.vendor = None
        self.os_family = []
        self.device_family = []
        self.dga_domains = []
        self.spammed_domains = []
        self.user_agents = []
        self.dns = {}
        self.conns = {}
        self.files = {}
        self.scans = {}
        self.alerts = []
        self.interesting_urls = []
        self.tcp_ports = []
        self.udp_ports = []


class Network:
    def __init__(self):
        self.pid = None
        self.executable = None
        self.args = []
        self.hosts = {}
        self.mac_history = {}
        self.interface = None
        self.mac = None
        self.ip = None
        self.gateway = None
        self.netmask = None
        self.net_cidr = None
        self.bad_ips = {'Tor': [], 'Malware': [], 'Botnet': [], 'Hacking': [], 'Phishing': [], 'Ransomware': [], 'Ads': [], 'User': []}
        self.bad_domains = {'Tor': [], 'Malware': [], 'Botnet': [], 'Hacking': [], 'Phishing': [], 'Ransomware': [], 'Ads': [], 'User': []}
        self.user_blacklist = []
        self.user_whitelist = []
        self.default_credentials = {}
        self.target_mime_types = ["application/x-7z-compressed", "application/x-ace-compressed", "application/x-shockwave-flash",
                                  "application/pdf", "application/vnd.android.package-archive", "application/octet-stream",
                                  "application/x-bzip", "application/x-bzip2", "application/x-debian-package", "application/java-archive",
                                  "	application/javascript", "application/x-msdownload", "application/x-ms-application", "application/vnd.ms-excel",
                                  "application/vnd.ms-excel.addin.macroenabled.12", "application/vnd.ms-excel.sheet.binary.macroenabled.12",
                                  "application/vnd.ms-excel.template.macroenabled.12", "application/vnd.ms-excel.sheet.macroenabled.12",
                                  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                                  "application/vnd.openxmlformats-officedocument.wordprocessingml.template", "application/vnd.ms-powerpoint.slide.macroenabled.12",
                                  "application/vnd.ms-powerpoint.presentation.macroenabled.12", "application/vnd.ms-powerpoint.slideshow.macroenabled.12",
                                  "application/vnd.ms-powerpoint.template.macroenabled.12", "application/msword", "application/vnd.ms-word.document.macroenabled.12",
                                  "application/vnd.ms-word.template.macroenabled.12", "application/x-rar-compressed", "application/x-tar", "application/zip", "application/x-dosexec",
                                  "application/x-ms-installer", "application/x-elf", "application/x-sh", "text/x-perl", "text/x-python"]
        self.tld_whitelist = ['local', 'test', 'localhost', 'example', 'invalid', 'arpa']
        # Malicious TLDs
        # https://www.tripwire.com/state-of-security/security-data-protection/cyber-security/most-suspicious-tlds-revealed-by-blue-coat-systems/
        # https://www.spamhaus.org/statistics/tlds/
        self.tld_blacklist = ['zip', 'review', 'country', 'kim', 'cricket', 'science', 'work', 'party', 'gq', 'link',
                              'gdn', 'stream', 'download', 'top', 'us', 'study', 'click', 'biz']
        self.vt_api_key = None
        self.fg_intel_key = None
        self.dst_emails = None
        self.email_watchlist = []
        self.fg_api_url = None
        self.vt_api_domain_url = None
        self.vt_api_ip_url = None
        self.vt_api_file_url = None
        self.hibp_api_url = None
        self.mailer_mode = None
        self.mailer_address = None
        self.mailer_pwd = None
        self.last_alert_id = 0
        self.blacklist_sources_ip = {}
        self.blacklist_sources_domain = {}


class Report:
    def __init__(self, alert):
        self.alert = alert
        self.alert_name = None
        self.description = None
        self.src_mac = None
        self.src_ip = None
        self.vendor = None
        self.vt_reports = []


class Indicator:
    def __init__(self):
        self.DGA = None
        self.domain = []
        self.dst_ip = []


class File:
    def __init__(self):
        self.ts = None
        self.lseen = None
        self.source = None
        self.conn_id = None
        self.mime_type = None
        self.md5 = None
        self.sha1 = None
        self.size = None
        self.vt_flag = False
        self.vt_positives = 0
        self.vt_report = None

