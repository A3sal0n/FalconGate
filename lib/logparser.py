import time
import threading
import re
from lib.objects import *
from lib.logger import *
from user_agents import parse
import os
import lib.utils as utils


class ReadBroConn(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.bro_conn_log_path = '/usr/local/bro/logs/current/conn.log'
        self.last_pos = 0
        self.last_file_size = 0
        self.new_lines = []

    def run(self):
        global homenet
        global lock

        while 1:
            res = self.get_new_lines()
            if res:
                for line in self.new_lines:
                    if line[0] != "#":
                        line = line.strip()
                        fields = line.split('\t')
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
                        except Exception as e:
                            log.debug('FG-WARN: read_bro_conn_log - ' + e.__doc__ + " - " + e.message)
            time.sleep(5)

    def get_new_lines(self):
        try:
            f = open(self.bro_conn_log_path, 'r')
            if os.path.getsize(self.bro_conn_log_path) < self.last_file_size:
                f.seek(0)
            else:
                f.seek(self.last_pos)
            lines = f.readlines()
            if len(lines) > 0:
                self.new_lines = lines
                self.last_pos = f.tell()
                self.last_file_size = os.path.getsize(self.bro_conn_log_path)
                f.close()
                return True
            else:
                f.close()
                return False
        except Exception as e:
            log.debug('FG-WARN: read_bro_conn_log - ' + e.__doc__ + " - " + e.message)
            return False

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
        self.bro_dns_log_path = '/usr/local/bro/logs/current/dns.log'
        self.last_pos = 0
        self.last_file_size = 0
        self.new_lines = []

    def run(self):
        global homenet
        global lock
        global top_domains

        while 1:
            res = self.get_new_lines()
            if res:
                for line in self.new_lines:
                    if line[0] != '#':
                        line = line.strip()
                        fields = line.split('\t')
                        try:
                            if fields[9] != '-' and utils.validate_domain(fields[9]):
                                query = fields[9]
                                sld = utils.get_sld(query)
                                tld = utils.get_tld(query)
                                cip = fields[2]
                                if tld not in self.tld_whitelist:
                                    with lock:
                                        if cip in homenet.hosts:
                                            if fields[15] != 'NXDOMAIN':
                                                if query not in homenet.hosts[cip].dns:
                                                    request = DNSRequest()
                                                    request.ts = float(fields[0])
                                                    request.cip = cip
                                                    request.query = query
                                                    request.tld = utils.get_tld(query)
                                                    request.sld = sld
                                                    request.sip = fields[4]
                                                    request.qtype = fields[13]
                                                    request.qresult = fields[15]
                                                    homenet.hosts[cip].dns[query] = request
                                                else:
                                                    homenet.hosts[cip].dns[query].lseen = float(fields[0])
                                                    homenet.hosts[cip].dns[query].counter += 1
                                            elif fields[15] == 'NXDOMAIN':
                                                try:
                                                    if query not in homenet.hosts[cip].dga_domains:
                                                        homenet.hosts[cip].dga_domains.append(query)
                                                except KeyError:
                                                    pass

                                            if (fields[13] == 'MX') or query.startswith('mail.'):
                                                if query not in homenet.hosts[cip].spammed_domains:
                                                    homenet.hosts[cip].spammed_domains.append(query)
                        except Exception as e:
                            log.debug('FG-WARN: read_bro_dns_log - ' + e.__doc__ + " - " + e.message)
            time.sleep(5)

    def get_new_lines(self):
        try:
            f = open(self.bro_dns_log_path, 'r')
            if os.path.getsize(self.bro_dns_log_path) < self.last_file_size:
                f.seek(0)
            else:
                f.seek(self.last_pos)
            lines = f.readlines()
            if len(lines) > 0:
                self.new_lines = lines
                self.last_pos = f.tell()
                self.last_file_size = os.path.getsize(self.bro_dns_log_path)
                f.close()
                return True
            else:
                f.close()
                return False
        except Exception as e:
            log.debug('FG-WARN: read_bro_dns_log - ' + e.__doc__ + " - " + e.message)
            return False


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
            try:
                f = open('/var/log/dnsmasq.leases', 'r')
                lines = f.readlines()
                if len(lines) > 0:
                    with lock:
                        for line in lines:
                            line = line.strip()
                            fields = line.split()
                            ts = int(fields[0]) - 604800
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
                                device.vendor = utils.get_vendor(mac)
                                homenet.hosts[ip] = device
                                self.create_alert(ts, ip, mac, hostname)
                                if mac not in homenet.mac_history:
                                    homenet.mac_history[mac] = [[ip, ts]]
                                else:
                                    homenet.mac_history[mac].append([ip, ts])
                            else:
                                if (ts > homenet.hosts[ip].lseen) and (mac == homenet.hosts[ip].mac):
                                    homenet.hosts[ip].lseen = ts
                                elif (ts > homenet.hosts[ip].lseen) and (mac != homenet.hosts[ip].mac):
                                    del homenet.hosts[ip]
                                    device = Host()
                                    device.ts = ts
                                    device.lseen = ts
                                    device.mac = mac
                                    device.ip = ip
                                    device.hostname = hostname
                                    device.vendor = utils.get_vendor(mac)
                                    homenet.hosts[ip] = device
                                    self.create_alert(ts, ip, mac, hostname)
                                    if mac not in homenet.mac_history:
                                        homenet.mac_history[mac] = [[ip, ts]]
                                    else:
                                        homenet.mac_history[mac].append([ip, ts])
                else:
                    pass
            except Exception as e:
                log.debug('FG-WARN: read_dhcp_leases_log - ' + e.__doc__ + " - " + e.message)
            time.sleep(5)

    def create_alert(self, ts, ip, mac, hostname):
        ctime = int(time.time())
        description = 'A new device was connected to your network. If this device was not ' \
                      'connected or authorized by you we recommend to check your router ' \
                      'configuration and disallow the access to this device.'
        reference = ''
        vendor = utils.get_vendor(mac)
        indicators = ip + '|' + mac + '|' + hostname + '|' + [lambda:vendor, lambda:''][not vendor]()
        a = [0, 'new_device', ts, ctime, 0, 0, 'New Device', ip, indicators, 0, description, reference]
        alert_id = utils.add_alert_to_db(a)
        homenet.hosts[ip].alerts.append(alert_id)


class ReadBroNotice(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self._cached_stamp = 0
        self.scan_regex = "^(\d+\.\d+).+Scan\:\:Port\_Scan\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\sscanned\sat\sleast" \
                          "\s15\sunique\sports\sof\shost\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\sin\s(\dm\d+s)"
        self.recorded = []

    def run(self):
        global homenet
        global lock

        while 1:
            try:
                f = open('/usr/local/bro/logs/current/notice.log', 'r')
                lines = f.readlines()
                for line in lines:
                    line = line.strip()
                    fields = line.split('\t')
                    if line[0] != '#':
                        uid = fields[1]
                        if uid not in self.recorded:
                            line = line.strip()
                            scan = re.search(self.scan_regex, line)
                            if scan:
                                ts = int(float(scan.group(1)))
                                src = scan.group(2)
                                dst = scan.group(3)
                                duration = scan.group(4)
                                with lock:
                                    if src in homenet.hosts:
                                        ctime = int(time.time())
                                        description = 'This host has been detected scanning one or multiple destination ' \
                                                      'IP addresses for open ports. This could indicate that a hacker has ' \
                                                      'compromised and taken control of this device and is now trying to locate ' \
                                                      'and compromise other hosts in your network.'
                                        reference = 'https://en.wikipedia.org/wiki/Port_scanner'
                                        a = [0, 'port_scan', ts, ctime, 0, 0, 'Port Scan', src, dst, 0, description, reference]
                                        alert_id = utils.add_alert_to_db(a)
                                        homenet.hosts[src].alerts.append(alert_id)
                            self.recorded.append(uid)
            except (IOError, OSError) as e:
                log.debug('FG-WARN: read_bro_notice_log - ' + e.__doc__ + " - " + e.message)

            if len(self.recorded) > 100000:
                del self.recorded[:]

            time.sleep(5)


class ReadBroFiles(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self._cached_stamp = 0
        self.target_mime_types = homenet.target_mime_types
        self.recorded = []

    def run(self):
        global homenet
        global lock

        while 1:
            try:
                f = open('/usr/local/bro/logs/current/files.log', 'r')
                lines = f.readlines()
                for line in lines:
                    if line[0] != "#":
                        line = line.strip()
                        fields = line.split()
                        if len(fields) > 10:
                            try:
                                fuid = fields[1]
                                if fuid not in self.recorded:
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
                                    self.recorded.append(fuid)
                            except Exception as e:
                                log.debug('FG-WARN: read_bro_file_log - ' + e.__doc__ + " - " + e.message)
            except (IOError, OSError) as e:
                log.debug('FG-WARN: read_bro_file_log - ' + e.__doc__ + " - " + e.message)

            if len(self.recorded) > 100000:
                del self.recorded[:]

            time.sleep(5)


class ReadBroHTTP(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.target_mime_types = homenet.target_mime_types
        self.bro_http_log_path = '/usr/local/bro/logs/current/http.log'
        self.last_pos = 0
        self.last_file_size = 0
        self.new_lines = []

    def run(self):
        global homenet
        global lock

        while 1:
            res = self.get_new_lines()
            if res:
                for line in self.new_lines:
                    if line[0] != '#':
                        line = line.strip()
                        fields = line.split('\t')
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

                                        if (dos is not None) and (dos not in homenet.hosts[sip].os_family) and (dos != 'Other'):
                                            homenet.hosts[sip].os_family.append(dos)

                                        if (device is not None) and (device not in homenet.hosts[sip].device_family) and (device != 'Other'):
                                            homenet.hosts[sip].device_family.append(device)

                                    if fields[26] in self.target_mime_types:
                                        if fields[5] == '80':
                                            url = 'hxxp://' + fields[8] + fields[9]
                                            if url not in homenet.hosts[sip].interesting_urls:
                                                if len(homenet.hosts[sip].interesting_urls) < 200:
                                                    homenet.hosts[sip].interesting_urls.append(url)
                                                else:
                                                    del homenet.hosts[sip].interesting_urls[0:50]
                                                    homenet.hosts[sip].interesting_urls.append(url)
                        except Exception as e:
                            log.debug('FG-WARN: read_bro_http_log - ' + e.__doc__ + " - " + e.message)
            time.sleep(5)

    def get_new_lines(self):
        try:
            f = open(self.bro_http_log_path, 'r')
            if os.path.getsize(self.bro_http_log_path) < self.last_file_size:
                f.seek(0)
            else:
                f.seek(self.last_pos)
            lines = f.readlines()
            if len(lines) > 0:
                self.new_lines = lines
                self.last_pos = f.tell()
                self.last_file_size = os.path.getsize(self.bro_http_log_path)
                f.close()
                return True
            else:
                f.close()
                return False
        except IOError:
            return False
