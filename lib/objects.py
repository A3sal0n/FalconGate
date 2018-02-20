import collections
from lib.logger import *


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
                    "We recommend to investigate this issue as soon as possible."


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


class DefaultCredsAlertTemplate:
    def __init__(self, homenet, alert):
        self.homenet = homenet
        self.alert = alert
        self.subject = "An account with default vendor credentials was found on host " + alert[7]
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
                    "We recommend you to fix this issue as soon as possible."


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
        self.direction = None
        self.duration = 0
        self.client_bytes = 0
        self.server_bytes = 0
        self.client_packets = 0
        self.server_packets = 0
        self.src_country_code = None
        self.src_country_name = None
        self.dst_country_code = None
        self.dst_country_name = None
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
        self.vuln_accounts = []


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
        self.bad_ips = {'Tor': [], 'Malware': [], 'Botnet': [], 'Hacking': [], 'Phishing': [], 'Ransomware': [],
                        'Ads': [], 'User': []}
        self.bad_domains = {'Tor': [], 'Malware': [], 'Botnet': [], 'Hacking': [], 'Phishing': [], 'Ransomware': [],
                            'Ads': [], 'Crypto-miners': [], 'User': []}
        self.user_blacklist = []
        self.user_whitelist = []
        self.user_domain_blacklist = []
        self.user_domain_whitelist = []
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
                                  "application/x-ms-installer", "application/x-elf", "application/x-sh", "text/x-perl", "text/x-python", "image/x-icon", "application/x-executable"]
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
        self.fg_api_intel_url = None
        self.fg_api_alert_url = None
        self.fg_api_malware_url = None
        self.vt_api_domain_url = None
        self.vt_api_ip_url = None
        self.vt_api_file_url = None
        self.hibp_api_url = None
        self.mailer_mode = None
        self.mailer_address = None
        self.mailer_pwd = None
        self.telegram_id = None
        self.allow_tor = None
        self.cloud_malware_sandbox = None
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
        self.fuid = None
        self.lseen = None
        self.tx_hosts = None
        self.rx_hosts = None
        self.conn_id = None
        self.mime_type = None
        self.md5 = None
        self.sha1 = None
        self.size = None
        self.vt_flag = False
        self.vt_positives = 0
        self.vt_report = None


class DefaultCredentials:
    def __init__(self):
        self.service = ''
        self.port = ''
        self.user = ''
        self.password = ''


class Country:
    def __init__(self, code, name):
        self.code = code
        self.name = name
        self.is_risky = self.is_risky(code)
        self.hourly_stats = {}

    @staticmethod
    def is_risky(ccode):
        risk_countries = ["CN", "US", "TR", "BR", "RU", "VN", "JP", "IN", "TW", "RO", "HU"]
        if ccode in risk_countries:
            return True
        else:
            return False

    def get_stats(self, stime, etime):
        sout = {"bytes_sent": 0, "bytes_received": 0, "pqt_sent": 0, "pqt_received": 0, "nconn": 0}
        skeys = sorted(self.hourly_stats)
        try:
            for k in skeys:
                if stime <= k <= etime:
                    sout["bytes_sent"] += self.hourly_stats[k].data_sent
                    sout["bytes_received"] += self.hourly_stats[k].data_received
                    sout["pqt_sent"] += self.hourly_stats[k].pqt_sent
                    sout["pqt_received"] += self.hourly_stats[k].pqt_received
                    sout["nconn"] += self.hourly_stats[k].nconn
        except Exception as e:
            log.debug('FG-ERROR: ' + str(e.__doc__) + " - " + str(e.message))

        return sout


class HourStats:
    def __init__(self):
        self.data_sent = 0
        self.data_received = 0
        self.pqt_sent = 0
        self.pqt_received = 0
        self.nconn = 0

# Other useful stuff
CC = {
    "AF": "AFGHANISTAN",
    "AX": "ALAND ISLANDS",
    "AL": "ALBANIA",
    "DZ": "ALGERIA",
    "AS": "AMERICAN SAMOA",
    "AD": "ANDORRA",
    "AO": "ANGOLA",
    "AI": "ANGUILLA",
    "AQ": "ANTARCTICA",
    "AG": "ANTIGUA AND BARBUDA",
    "AR": "ARGENTINA",
    "AM": "ARMENIA",
    "AW": "ARUBA",
    "AU": "AUSTRALIA",
    "AT": "AUSTRIA",
    "AZ": "AZERBAIJAN",
    "BS": "BAHAMAS",
    "BH": "BAHRAIN",
    "BD": "BANGLADESH",
    "BB": "BARBADOS",
    "BY": "BELARUS",
    "BE": "BELGIUM",
    "BZ": "BELIZE",
    "BJ": "BENIN",
    "BM": "BERMUDA",
    "BT": "BHUTAN",
    "BO": "BOLIVIA, PLURINATIONAL STATE OF",
    "BQ": "BONAIRE, SINT EUSTATIUS AND SABA",
    "BA": "BOSNIA AND HERZEGOVINA",
    "BW": "BOTSWANA",
    "BV": "BOUVET ISLAND",
    "BR": "BRAZIL",
    "IO": "BRITISH INDIAN OCEAN TERRITORY",
    "BN": "BRUNEI DARUSSALAM",
    "BG": "BULGARIA",
    "BF": "BURKINA FASO",
    "BI": "BURUNDI",
    "KH": "CAMBODIA",
    "CM": "CAMEROON",
    "CA": "CANADA",
    "CV": "CAPE VERDE",
    "KY": "CAYMAN ISLANDS",
    "CF": "CENTRAL AFRICAN REPUBLIC",
    "TD": "CHAD",
    "CL": "CHILE",
    "CN": "CHINA",
    "CX": "CHRISTMAS ISLAND",
    "CC": "COCOS (KEELING) ISLANDS",
    "CO": "COLOMBIA",
    "KM": "COMOROS",
    "CG": "CONGO",
    "CD": "CONGO, THE DEMOCRATIC REPUBLIC OF THE",
    "CK": "COOK ISLANDS",
    "CR": "COSTA RICA",
    "CI": "COTE D'IVOIRE",
    "HR": "CROATIA",
    "CU": "CUBA",
    "CW": "CURACAO",
    "CY": "CYPRUS",
    "CZ": "CZECH REPUBLIC",
    "DK": "DENMARK",
    "DJ": "DJIBOUTI",
    "DM": "DOMINICA",
    "DO": "DOMINICAN REPUBLIC",
    "EC": "ECUADOR",
    "EG": "EGYPT",
    "SV": "EL SALVADOR",
    "GQ": "EQUATORIAL GUINEA",
    "ER": "ERITREA",
    "EE": "ESTONIA",
    "EU": "EUROPE",
    "ET": "ETHIOPIA",
    "FK": "FALKLAND ISLANDS (MALVINAS)",
    "FO": "FAROE ISLANDS",
    "FJ": "FIJI",
    "FI": "FINLAND",
    "FR": "FRANCE",
    "GF": "FRENCH GUIANA",
    "PF": "FRENCH POLYNESIA",
    "TF": "FRENCH SOUTHERN TERRITORIES",
    "GA": "GABON",
    "GM": "GAMBIA",
    "GE": "GEORGIA",
    "DE": "GERMANY",
    "GH": "GHANA",
    "GI": "GIBRALTAR",
    "GR": "GREECE",
    "GL": "GREENLAND",
    "GD": "GRENADA",
    "GP": "GUADELOUPE",
    "GU": "GUAM",
    "GT": "GUATEMALA",
    "GG": "GUERNSEY",
    "GN": "GUINEA",
    "GW": "GUINEA-BISSAU",
    "GY": "GUYANA",
    "HT": "HAITI",
    "HM": "HEARD ISLAND AND MCDONALD ISLANDS",
    "VA": "HOLY SEE (VATICAN CITY STATE)",
    "HN": "HONDURAS",
    "HK": "HONG KONG",
    "HU": "HUNGARY",
    "IS": "ICELAND",
    "IN": "INDIA",
    "ID": "INDONESIA",
    "IR": "IRAN, ISLAMIC REPUBLIC OF",
    "IQ": "IRAQ",
    "IE": "IRELAND",
    "IM": "ISLE OF MAN",
    "IL": "ISRAEL",
    "IT": "ITALY",
    "JM": "JAMAICA",
    "JP": "JAPAN",
    "JE": "JERSEY",
    "JO": "JORDAN",
    "KZ": "KAZAKHSTAN",
    "KE": "KENYA",
    "KI": "KIRIBATI",
    "KP": "KOREA, DEMOCRATIC PEOPLE'S REPUBLIC OF",
    "KR": "KOREA, REPUBLIC OF",
    "KW": "KUWAIT",
    "KG": "KYRGYZSTAN",
    "LA": "LAO PEOPLE'S DEMOCRATIC REPUBLIC",
    "LV": "LATVIA",
    "LB": "LEBANON",
    "LS": "LESOTHO",
    "LR": "LIBERIA",
    "LY": "LIBYA",
    "LI": "LIECHTENSTEIN",
    "LT": "LITHUANIA",
    "LU": "LUXEMBOURG",
    "MO": "MACAO",
    "MK": "MACEDONIA, THE FORMER YUGOSLAV REPUBLIC OF",
    "MG": "MADAGASCAR",
    "MW": "MALAWI",
    "MY": "MALAYSIA",
    "MV": "MALDIVES",
    "ML": "MALI",
    "MT": "MALTA",
    "MH": "MARSHALL ISLANDS",
    "MQ": "MARTINIQUE",
    "MR": "MAURITANIA",
    "MU": "MAURITIUS",
    "YT": "MAYOTTE",
    "MX": "MEXICO",
    "FM": "MICRONESIA, FEDERATED STATES OF",
    "MD": "MOLDOVA, REPUBLIC OF",
    "MC": "MONACO",
    "MN": "MONGOLIA",
    "ME": "MONTENEGRO",
    "MS": "MONTSERRAT",
    "MA": "MOROCCO",
    "MZ": "MOZAMBIQUE",
    "MM": "MYANMAR",
    "NA": "NAMIBIA",
    "NR": "NAURU",
    "NP": "NEPAL",
    "NL": "NETHERLANDS",
    "NC": "NEW CALEDONIA",
    "NZ": "NEW ZEALAND",
    "NI": "NICARAGUA",
    "NE": "NIGER",
    "NG": "NIGERIA",
    "NU": "NIUE",
    "NF": "NORFOLK ISLAND",
    "MP": "NORTHERN MARIANA ISLANDS",
    "NO": "NORWAY",
    "OM": "OMAN",
    "PK": "PAKISTAN",
    "PW": "PALAU",
    "PS": "PALESTINE, STATE OF",
    "PA": "PANAMA",
    "PG": "PAPUA NEW GUINEA",
    "PY": "PARAGUAY",
    "PE": "PERU",
    "PH": "PHILIPPINES",
    "PN": "PITCAIRN",
    "PL": "POLAND",
    "PT": "PORTUGAL",
    "PR": "PUERTO RICO",
    "QA": "QATAR",
    "RE": "REUNION",
    "RO": "ROMANIA",
    "RU": "RUSSIAN FEDERATION",
    "RW": "RWANDA",
    "BL": "SAINT BARTHELEMY",
    "SH": "SAINT HELENA, ASCENSION AND TRISTAN DA CUNHA",
    "KN": "SAINT KITTS AND NEVIS",
    "LC": "SAINT LUCIA",
    "MF": "SAINT MARTIN (FRENCH PART)",
    "PM": "SAINT PIERRE AND MIQUELON",
    "VC": "SAINT VINCENT AND THE GRENADINES",
    "WS": "SAMOA",
    "SM": "SAN MARINO",
    "ST": "SAO TOME AND PRINCIPE",
    "SA": "SAUDI ARABIA",
    "SN": "SENEGAL",
    "RS": "SERBIA",
    "SC": "SEYCHELLES",
    "SL": "SIERRA LEONE",
    "SG": "SINGAPORE",
    "SX": "SINT MAARTEN (DUTCH PART)",
    "SK": "SLOVAKIA",
    "SI": "SLOVENIA",
    "SB": "SOLOMON ISLANDS",
    "SO": "SOMALIA",
    "ZA": "SOUTH AFRICA",
    "GS": "SOUTH GEORGIA AND THE SOUTH SANDWICH ISLANDS",
    "SS": "SOUTH SUDAN",
    "ES": "SPAIN",
    "LK": "SRI LANKA",
    "SD": "SUDAN",
    "SR": "SURINAME",
    "SJ": "SVALBARD AND JAN MAYEN",
    "SZ": "SWAZILAND",
    "SE": "SWEDEN",
    "CH": "SWITZERLAND",
    "SY": "SYRIAN ARAB REPUBLIC",
    "TW": "TAIWAN, PROVINCE OF CHINA",
    "TJ": "TAJIKISTAN",
    "TZ": "TANZANIA, UNITED REPUBLIC OF",
    "TH": "THAILAND",
    "TL": "TIMOR-LESTE",
    "TG": "TOGO",
    "TK": "TOKELAU",
    "TO": "TONGA",
    "TT": "TRINIDAD AND TOBAGO",
    "TN": "TUNISIA",
    "TR": "TURKEY",
    "TM": "TURKMENISTAN",
    "TC": "TURKS AND CAICOS ISLANDS",
    "TV": "TUVALU",
    "UG": "UGANDA",
    "UA": "UKRAINE",
    "AE": "UNITED ARAB EMIRATES",
    "GB": "UNITED KINGDOM",
    "US": "UNITED STATES",
    "UM": "UNITED STATES MINOR OUTLYING ISLANDS",
    "UY": "URUGUAY",
    "UZ": "UZBEKISTAN",
    "VU": "VANUATU",
    "VE": "VENEZUELA, BOLIVARIAN REPUBLIC OF",
    "VN": "VIET NAM",
    "VG": "VIRGIN ISLANDS, BRITISH",
    "VI": "VIRGIN ISLANDS, U.S.",
    "WF": "WALLIS AND FUTUNA",
    "EH": "WESTERN SAHARA",
    "YE": "YEMEN",
    "ZM": "ZAMBIA",
    "ZW": "ZIMBABWE",
}