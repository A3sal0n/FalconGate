
class Alert:
    def __init__(self, alert_type):
        self.alert_type = alert_type
        self.first_seen = None
        self.last_seen = None
        self.last_reported = None
        self.nreports = 0
        self.threat = None
        self.indicators = []
        self.handled = False
        self.description = None
        self.references = []

    def serialize_alert(self):
        alert = {'alert_type': self.alert_type, 'first_seen': self.first_seen, 'last_seen': self.last_seen,
                 'last_reported': self.last_reported, 'nreports': self.nreports, 'threat': self.threat,
                 'indicators': self.indicators, 'handled': self.handled}
        return alert


class DNSRequest:
    def __init__(self):
        self.ts = None
        self.query = None
        self.sld = None
        self.tld = None
        self.cip = None
        self.sip = None
        self.qtype = None
        self.qresult = None
        self.bad = None
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
        self.dga_counter = 0
        self.dga_domains = []
        self.spamm_counter = 0
        self.spammed_domains = []
        self.user_agents = []
        self.dns = {}
        self.conns = {}
        self.files = {}
        self.scans = {}
        self.alerts = {}
        self.interesting_urls = []


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
        self.bad_ips = {}
        self.user_blacklist = []
        self.user_whitelist = []
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
        self.dst_emails = None
        self.vt_api_domain_url = None
        self.vt_api_ip_url = None
        self.vt_api_file_url = None


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

