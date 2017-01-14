import time
import threading
import re
from lib.utils import *
from lib.objects import *
import lib.intel as intel
from lib.logger import *
from user_agents import parse
import os
from pygtail import Pygtail


reported_domains = []


class ReadBroConn(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID

    def run(self):
        global homenet
        global lock

        while 1:
            if os.path.isfile("/usr/local/bro/spool/bro/conn.log"):
                try:
                    for line in Pygtail("/usr/local/bro/spool/bro/conn.log"):
                        if line[0] == "#":
                            pass
                        else:
                            line = line.strip()
                            fields = line.split()
                            try:
                                cip = fields[2]
                                cid = fields[2] + fields[4] + fields[5]
                                cid = cid.strip(".")
                                with lock:
                                    if cip in homenet.hosts:
                                        if cid not in homenet.hosts[cip].conns:
                                            homenet.hosts[cip].conns[cid] = self.map_conn_fields(fields)
                                        else:
                                            if (float(fields[0]) - homenet.hosts[cip].conns[cid].ts) >= 3600:
                                                del homenet.hosts[cip].conns[cid]
                                                homenet.hosts[cip].conns[cid] = self.map_conn_fields(fields)
                                            else:
                                                if (homenet.hosts[cip].conns[cid].lseen - homenet.hosts[cip].conns[cid].ts) >= 86400:
                                                    del homenet.hosts[cip].conns[cid]
                                                    homenet.hosts[cip].conns[cid] = self.map_conn_fields(fields)
                                                else:
                                                    homenet.hosts[cip].conns[cid].lseen = float(fields[0])
                                                    try:
                                                        homenet.hosts[cip].conns[cid].duration += float(fields[8])
                                                    except ValueError:
                                                        pass
                                                    try:
                                                        homenet.hosts[cip].conns[cid].client_bytes += int(fields[9])
                                                    except ValueError:
                                                        pass
                                                    try:
                                                        homenet.hosts[cip].conns[cid].server_bytes += int(fields[10])
                                                    except ValueError:
                                                        pass
                                                    homenet.hosts[cip].conns[cid].client_packets += int(fields[17])
                                                    homenet.hosts[cip].conns[cid].server_packets += int(fields[19])
                                                    homenet.hosts[cip].conns[cid].counter += 1
                            except Exception:
                                log.debug(e.__doc__ + " - " + e.message)
                except (IOError, OSError) as e:
                    log.debug(e.__doc__ + " - " + e.message)
            else:
                pass
            time.sleep(10)

    @staticmethod
    def map_conn_fields(fields):
        conn = Conn()
        conn.ts = float(fields[0])
        conn.lseen = float(fields[0])
        conn.src_ip = fields[2]
        conn.dst_ip = fields[4]
        conn.dst_port = int(fields[5])
        conn.proto = fields[6]
        conn.service = fields[7]
        try:
            conn.duration = float(fields[8])
        except ValueError:
            conn.duration = 0
        try:
            conn.client_bytes = int(fields[9])
        except ValueError:
            conn.client_bytes = 0
        try:
            conn.server_bytes = int(fields[10])
        except ValueError:
            conn.server_bytes = 0
        conn.client_packets = int(fields[17])
        conn.server_packets = int(fields[19])
        conn.counter = 1
        return conn


class ReadBroDNS(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.tld_whitelist = ['local', 'test', 'localhost', 'example', 'invalid', 'arpa']

    def run(self):
        global homenet
        global lock
        global reported_domains
        global top_domains

        while 1:
            if os.path.isfile("/usr/local/bro/spool/bro/dns.log"):
                try:
                    for line in Pygtail("/usr/local/bro/spool/bro/dns.log"):
                        if line[0] == "#":
                            pass
                        else:
                            line = line.strip()
                            fields = line.split("\t")
                            try:
                                if fields[9] != "-" and validate_domain(fields[9]):
                                    query = fields[9]
                                    sld = self.get_sld(query)
                                    tld = self.get_tld(query)
                                    cip = fields[2]
                                    if tld not in self.tld_whitelist:
                                        if (sld is not None) and (sld not in top_domains) and (fields[14] != "NXDOMAIN"):
                                            if cip in homenet.hosts:
                                                if query not in homenet.hosts[cip].dns:
                                                    request = DNSRequest()
                                                    request.ts = float(fields[0])
                                                    request.cip = cip
                                                    request.query = query
                                                    request.tld = self.get_tld(query)
                                                    request.sld = sld
                                                    request.sip = fields[4]
                                                    request.qtype = fields[13]
                                                    request.qresult = fields[15]
                                                    with lock:
                                                        homenet.hosts[cip].dns[query] = request
                                                else:
                                                    with lock:
                                                        homenet.hosts[cip].dns[query].ts = float(fields[0])
                                                        homenet.hosts[cip].dns[query].counter += 1
                                            else:
                                                host = Host()
                                                host.ip = cip
                                                with lock:
                                                    homenet.hosts[cip] = host
                                            if query not in reported_domains:
                                                reported_domains.append(query)
                                        elif fields[14] == "NXDOMAIN":
                                            try:
                                                with lock:
                                                    if query not in homenet.hosts[cip].dga_domains:
                                                        homenet.hosts[cip].dga_counter += 1
                                                        if len(homenet.hosts[cip].dga_domains) < 50:
                                                            homenet.hosts[cip].dga_domains.append(query)
                                            except KeyError:
                                                host = Host()
                                                host.ip = cip
                                                host.dga_counter += 1
                                                with lock:
                                                    homenet.hosts[cip] = host
                                        else:
                                            pass

                                        if (fields[12] == 'MX') or query.startswith('mail.'):
                                            with lock:
                                                if query not in homenet.hosts[cip].spammed_domains:
                                                    homenet.hosts[cip].spamm_counter += 1
                                                    if len(homenet.hosts[cip].spammed_domains) < 50:
                                                        homenet.hosts[cip].spammed_domains.append(query)
                            except Exception as e:
                                log.debug(e.__doc__ + " - " + e.message)
                except (IOError, OSError) as e:
                    log.debug(e.__doc__ + " - " + e.message)
            else:
                pass

            time.sleep(10)

    @staticmethod
    def get_ips_from_answer(answer):
        iplist = []
        fields = answer.split(",")
        for field in fields:
            aa = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", field)
            if aa:
                iplist.append(field)
        if len(iplist) > 0:
            return iplist
        else:
            return None

    @staticmethod
    def get_sld(query):
        fields = query.split(".")
        if len(fields) == 2:
            return query
        elif len(fields) > 2:
            return fields[-2] + "." + fields[-1]
        else:
            return None

    @staticmethod
    def get_tld(query):
        fields = query.split(".")
        if len(fields) >= 2:
            return fields[-1]
        else:
            return None


class ReadDHCPLeases(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.ctime = None

    def run(self):
        global homenet
        global lock

        while 1:
            self.ctime = int(time.time())
            f = open("/var/log/dnsmasq.leases", "r")
            lines = f.readlines()
            if len(lines) > 0:
                for line in lines:
                    line = line.strip()
                    fields = line.split()
                    ts = int(fields[0])
                    mac = fields[1].upper()
                    ip = str(fields[2])
                    hostname = str(fields[3])
                    if ip not in homenet.hosts:
                        device = Host()
                        device.ts = ts
                        device.lseen = ts
                        device.mac = mac
                        device.ip = ip
                        device.hostname = hostname
                        device.vendor = get_vendor(mac)
                        with lock:
                            homenet.hosts[ip] = device
                            if mac not in homenet.mac_history:
                                homenet.mac_history[mac] = [[ip, ts]]
                                a = Alert('new_device')
                                a.threat = 'New Device'
                                a.description = 'A new device was connected to your network. If this device was not ' \
                                                'connected or authorized by you we recommend to check your router ' \
                                                'configuration and disallow the access to this device.'
                                a.first_seen = self.ctime
                                a.last_seen = self.ctime
                                a.indicators.append(ip)
                                a.indicators.append(mac)
                                a.indicators.append(hostname)
                                a.indicators.append(get_vendor(mac))
                                homenet.hosts[ip].alerts['new_device'] = a
                            else:
                                homenet.mac_history[mac].append([ip, ts])
                    else:
                        if (ts > homenet.hosts[ip].lseen) and (mac == homenet.hosts[ip].mac):
                            with lock:
                                homenet.hosts[ip].lseen = ts
                        elif (ts > homenet.hosts[ip].lseen) and (mac != homenet.hosts[ip].mac):
                            with lock:
                                del homenet.hosts[ip]
                                device = Host()
                                device.ts = ts
                                device.lseen = ts
                                device.mac = mac
                                device.ip = ip
                                device.hostname = hostname
                                device.vendor = get_vendor(mac)
                                if mac not in homenet.mac_history:
                                    homenet.mac_history[mac] = [[ip, ts]]
                                else:
                                    homenet.mac_history[mac].append([ip, ts])
                else:
                    pass
            time.sleep(30)


class ReadBroNotice(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self._cached_stamp = 0
        self.scan_regex = "^(\d+\.\d+).+Scan\:\:Port\_Scan\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\sscanned\sat\sleast" \
                          "\s15\sunique\sports\sof\shost\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\sin\s(\dm\d+s)"

    def run(self):
        global homenet
        global lock

        while 1:
            if os.path.isfile("/usr/local/bro/spool/bro/notice.log"):
                try:
                    for line in Pygtail("/usr/local/bro/spool/bro/notice.log"):
                        if line[0] != "#":
                            line = line.strip()
                            scan = re.search(self.scan_regex, line)
                            if scan:
                                ts = float(scan.group(1))
                                src = scan.group(2)
                                dst = scan.group(3)
                                duration = scan.group(4)
                                with lock:
                                    if src in homenet.hosts:
                                        if dst not in homenet.hosts[src].scans:
                                            scan_obj = PortScan()
                                            scan_obj.ts = ts
                                            scan_obj.lseen = ts
                                            scan_obj.src_ip = src
                                            scan_obj.dst_ip = dst
                                            scan_obj.duration = duration
                                            homenet.hosts[src].scans[dst] = scan_obj
                                        else:
                                            homenet.hosts[src].scans[dst].lseen = ts
                except (IOError, OSError) as e:
                    pass
            else:
                pass

            time.sleep(10)


class ReadBroFiles(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self._cached_stamp = 0
        self.target_mime_types = homenet.target_mime_types

    def run(self):
        global homenet
        global lock

        while 1:
            if os.path.isfile("/usr/local/bro/spool/bro/files.log"):
                try:
                    for line in Pygtail("/usr/local/bro/spool/bro/files.log"):
                        if line[0] != "#":
                            line = line.strip()
                            fields = line.split()
                            if len(fields) > 10:
                                try:
                                    ts = float(fields[0])
                                    fsrc = fields[2]
                                    fdst = fields[3]
                                    conn_id = fields[4]
                                    mime = fields[8]
                                    size = int(fields[13])
                                    md5 = fields[19]
                                    sha1 = fields[20]
                                    with lock:
                                        if (fdst in homenet.hosts) and (mime in self.target_mime_types) and (sha1 != "-"):
                                            if sha1 not in homenet.hosts[fdst].files:
                                                file_obj = File()
                                                file_obj.ts = ts
                                                file_obj.lseen = ts
                                                file_obj.source = fsrc
                                                file_obj.conn_id = conn_id
                                                file_obj.mime_type = mime
                                                file_obj.size = size
                                                file_obj.md5 = md5
                                                file_obj.sha1 = sha1
                                                homenet.hosts[fdst].files[sha1] = file_obj
                                            else:
                                                homenet.hosts[fdst].files[sha1].lseen = ts
                                except Exception as e:
                                    log.debug(e.__doc__ + " - " + e.message)
                except (IOError, OSError) as e:
                    log.debug(e.__doc__ + " - " + e.message)
            else:
                pass

            time.sleep(10)


class ReadBroHTTP(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.target_mime_types = homenet.target_mime_types

    def run(self):
        global homenet
        global lock

        while 1:
            if os.path.isfile("/usr/local/bro/spool/bro/http.log"):
                try:
                    for line in Pygtail("/usr/local/bro/spool/bro/http.log"):
                        if line[0] != "#":
                            line = line.strip()
                            fields = line.split("\t")
                            try:
                                sip = fields[2]
                                with lock:
                                    if sip in homenet.hosts:
                                        if fields[11] not in homenet.hosts[sip].user_agents:
                                            if len(homenet.hosts[sip].user_agents) < 100:
                                                homenet.hosts[sip].user_agents.append(fields[11])
                                            else:
                                                del homenet.hosts[sip].user_agents[0:10]
                                                homenet.hosts[sip].user_agents.append(fields[11])
                                            user_agent = parse(fields[11])
                                            dos = user_agent.os.family
                                            device = user_agent.device.family

                                            if (dos is not None) and (dos not in homenet.hosts[sip].os_family) and (dos != "Other"):
                                                homenet.hosts[sip].os_family.append(dos)

                                            if (device is not None) and (device not in homenet.hosts[sip].device_family) and (device != "Other"):
                                                homenet.hosts[sip].device_family.append(device)

                                        if fields[26] in self.target_mime_types:
                                            if fields[5] == "80":
                                                url = "hxxp://" + fields[8] + fields[9]
                                                if url not in homenet.hosts[sip].interesting_urls:
                                                    if len(homenet.hosts[sip].interesting_urls) < 200:
                                                        homenet.hosts[sip].interesting_urls.append(url)
                                                    else:
                                                        del homenet.hosts[sip].interesting_urls[0:50]
                                                        homenet.hosts[sip].interesting_urls.append(url)
                            except Exception as e:
                                log.debug(e.__doc__ + " - " + e.message)
                except (IOError, OSError) as e:
                    log.debug(e.__doc__ + " - " + e.message)
            else:
                pass

            time.sleep(10)
