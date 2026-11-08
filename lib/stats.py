import ipaddress
import sqlite3 as lite
import threading
import time
from lib.logger import *
from lib.settings import homenet, lock, top_domains

STATS_DB = 'logs/stats.sqlite'
# Leave time at startup for the log parsers to re-read the current Zeek logs.
FIRST_SAVE_DELAY = 30
SAVE_INTERVAL = 300
RETENTION_SECONDS = 90 * 86400
HOUR = 3600
CONNECTION_RETENTION_SECONDS = 7 * 86400
# A restart only re-reads the current conn.log, which rotates hourly.
CONNECTION_UID_RETENTION_SECONDS = 2 * HOUR
TOP_LIMIT = 10
# "NA" is Namibia's country code.
UNKNOWN_COUNTRY = 'N/A'

# conn.log lines waiting to be saved to the connections table.
pending_connections = []
pending_connections_lock = threading.Lock()

DAY = 86400
DNS_RETENTION_SECONDS = 7 * DAY
# A restart only re-reads the current dns.log, which rotates hourly.
DNS_SEEN_RETENTION_SECONDS = 2 * HOUR
# Periods up to this long are charted per hour, longer ones per day.
DNS_HOURLY_RANGE_SECONDS = 2 * DAY
NEW_DOMAIN_LIMIT = 15

# dns.log lines waiting to be saved.
pending_dns = []
pending_dns_lock = threading.Lock()


def connect_stats_db():
    con = lite.connect(STATS_DB)
    con.execute('PRAGMA busy_timeout = 5000')
    return con


def create_stats_db():
    con = connect_stats_db()
    with con:
        con.execute("create table if not exists country_stats(hour int, country text, bytes_sent int, "
                    "bytes_received int, pqt_sent int, pqt_received int, nconn int, primary key (hour, country))")
        con.execute("create table if not exists connections(src_ip text, dst_ip text, proto text, dst_port int, "
                    "country text, first_seen real, last_seen real, bytes_out int, bytes_in int, "
                    "primary key (src_ip, dst_ip, proto, dst_port))")
        con.execute("create index if not exists connections_last_seen_idx on connections (last_seen)")
        con.execute("create table if not exists connection_uids(uid text primary key, saved_at int)")
        con.execute("create table if not exists dns_activity(hour int, src_ip text, query text, sld text, category text, "
                    "lookups int, failed int, first_seen real, primary key (hour, src_ip, query))")
        con.execute("create index if not exists dns_activity_sld_idx on dns_activity (sld)")
        con.execute("create table if not exists dns_external_resolvers(src_ip text, server text, first_seen real, "
                    "last_seen real, lookups int, primary key (src_ip, server))")
        con.execute("create table if not exists dns_seen(line text primary key, saved_at int)")
    con.close()


def get_hour_start(timestamp):
    return int(timestamp) - int(timestamp) % HOUR


def save_country_stats(totals):
    """Store {hour: {country: [bytes_sent, bytes_received, pqt_sent, pqt_received, nconn]}}.

    Totals are recalculated from connections held in memory, which can be incomplete
    after a restart, so a stored value is only ever replaced by a larger one.
    """
    rows = [(hour, country) + tuple(values) for hour, countries in totals.items() for country, values in countries.items()]
    con = connect_stats_db()
    with con:
        con.executemany("insert into country_stats values (?, ?, ?, ?, ?, ?, ?) "
                        "on conflict(hour, country) do update set "
                        "bytes_sent = max(bytes_sent, excluded.bytes_sent), "
                        "bytes_received = max(bytes_received, excluded.bytes_received), "
                        "pqt_sent = max(pqt_sent, excluded.pqt_sent), "
                        "pqt_received = max(pqt_received, excluded.pqt_received), "
                        "nconn = max(nconn, excluded.nconn)", rows)
    con.close()


def delete_old_stats(now):
    con = connect_stats_db()
    with con:
        con.execute("delete from country_stats where hour < ?", (now - RETENTION_SECONDS,))
    con.close()


def get_country_stats(stime, etime):
    """Return per-country totals for every hour that overlaps the time range."""
    con = connect_stats_db()
    rows = con.execute("select country, sum(bytes_sent), sum(bytes_received), sum(pqt_sent), sum(pqt_received), "
                       "sum(nconn) from country_stats where hour > ? and hour <= ? group by country "
                       "having sum(nconn) > 0", (stime - HOUR, etime)).fetchall()
    con.close()
    return {row[0]: {"bytes_sent": row[1], "bytes_received": row[2], "pqt_sent": row[3], "pqt_received": row[4],
                     "nconn": row[5]} for row in rows}


def collect_country_totals(now):
    """Add up outbound connections from the current and previous hours, by destination country."""
    current_hour = get_hour_start(now)
    totals = {current_hour: {}, current_hour - HOUR: {}}
    # Hold the global lock while reading homenet: the Zeek log parsers mutate
    # homenet.hosts/.conns concurrently.
    with lock:
        for host in homenet.hosts.values():
            if host.mac == homenet.mac:
                continue
            for conn in host.conns.values():
                hour = totals.get(get_hour_start(conn.ts))
                if hour is None or conn.direction != "outbound" or not conn.dst_country_code:
                    continue
                country = hour.setdefault(conn.dst_country_code, [0, 0, 0, 0, 0])
                country[0] += conn.client_bytes
                country[1] += conn.server_bytes
                country[2] += conn.client_packets
                country[3] += conn.server_packets
                country[4] += conn.counter
    return totals


def is_outbound_internet(fields):
    """Tell whether a conn.log line is a connection from the local network to the Internet.

    Zeek's "not local" also covers private networks missing from its networks.cfg, such as an
    upstream router's subnet, so the destination address is checked as well.
    """
    if fields.get('local_orig') is not True or fields.get('local_resp') is not False:
        return False
    try:
        destination = ipaddress.ip_address(fields['id.resp_h'])
    except (KeyError, ValueError):
        return False
    return destination.is_global and not destination.is_multicast


def record_connection(fields, country):
    """Queue a conn.log line for the next save."""
    connection = (fields['uid'], fields['id.orig_h'], fields['id.resp_h'], fields['proto'], int(fields['id.resp_p']),
                  country or UNKNOWN_COUNTRY, float(fields['ts']), float(fields['ts']) + float(fields.get('duration', 0)),
                  int(fields.get('orig_ip_bytes', 0)), int(fields.get('resp_ip_bytes', 0)))
    with pending_connections_lock:
        pending_connections.append(connection)


def save_connections(now):
    """Add the queued connections to their running totals.

    The log parser re-reads the current conn.log after a restart. Recording each connection's
    Zeek uid in the same transaction as its bytes means it can only ever be counted once.
    """
    with pending_connections_lock:
        connections = pending_connections[:]
        del pending_connections[:]
    if not connections:
        return

    try:
        con = connect_stats_db()
        try:
            with con:
                for connection in connections:
                    uid, values = connection[0], connection[1:]
                    inserted = con.execute("insert or ignore into connection_uids values (?, ?)", (uid, now))
                    if inserted.rowcount == 1:
                        con.execute("insert into connections values (?, ?, ?, ?, ?, ?, ?, ?, ?) "
                                    "on conflict(src_ip, dst_ip, proto, dst_port) do update set "
                                    "country = excluded.country, "
                                    "first_seen = min(first_seen, excluded.first_seen), "
                                    "last_seen = max(last_seen, excluded.last_seen), "
                                    "bytes_out = bytes_out + excluded.bytes_out, "
                                    "bytes_in = bytes_in + excluded.bytes_in", values)
        finally:
            con.close()
    except Exception:
        # Nothing was committed, so keep these connections for the next save.
        with pending_connections_lock:
            pending_connections[:0] = connections
        raise


def delete_old_connections(now):
    con = connect_stats_db()
    with con:
        con.execute("delete from connections where last_seen < ?", (now - CONNECTION_RETENTION_SECONDS,))
        con.execute("delete from connection_uids where saved_at < ?", (now - CONNECTION_UID_RETENTION_SECONDS,))
    con.close()


def get_device_label(ip):
    """Name a device by its hostname and IP address when the hostname is known."""
    with lock:
        host = homenet.hosts.get(ip)
        hostname = str(host.hostname) if host else ''
    return ip if hostname in ('', 'None', '*') else hostname + ' (' + ip + ')'


def get_top_connections(stime, etime):
    """Return the top data senders, destinations and pairs among connections active in the time range."""
    con = connect_stats_db()
    active = "from connections where last_seen >= ? and first_seen <= ?"
    senders = con.execute("select src_ip, sum(bytes_out) " + active + " group by src_ip having sum(bytes_out) > 0 "
                          "order by 2 desc limit ?", (stime, etime, TOP_LIMIT)).fetchall()
    destinations = con.execute("select dst_ip, max(country), sum(bytes_out) " + active + " group by dst_ip "
                               "having sum(bytes_out) > 0 order by 3 desc limit ?", (stime, etime, TOP_LIMIT)).fetchall()
    pairs = con.execute("select src_ip, dst_ip, sum(bytes_out) " + active + " group by src_ip, dst_ip "
                        "having sum(bytes_out) > 0 order by 3 desc limit ?", (stime, etime, TOP_LIMIT)).fetchall()
    con.close()
    return {
        "senders": [{"label": get_device_label(ip), "bytes": sent} for ip, sent in senders],
        "destinations": [{"label": ip + ' (' + country + ')', "bytes": sent} for ip, country, sent in destinations],
        "pairs": [{"label": src + ' → ' + dst, "bytes": sent} for src, dst, sent in pairs],
    }


def is_external_resolver(fields):
    """Tell whether a dns.log line is a plain DNS query sent straight to a server on the Internet."""
    try:
        server = ipaddress.ip_address(fields['id.resp_h'])
    except (KeyError, ValueError):
        return False
    return fields.get('id.resp_p') == 53 and server.is_global and not server.is_multicast


def record_dns_lookup(fields, query, sld, rcode, category):
    """Queue a dns.log line for the next save."""
    line = '|'.join(str(fields.get(name, '')) for name in ('uid', 'trans_id', 'ts', 'query', 'qtype_name'))
    ts = float(fields['ts'])
    server = fields['id.resp_h'] if is_external_resolver(fields) else None
    lookup = (line, get_hour_start(ts), fields['id.orig_h'], query, sld, category or None, int(rcode == 'NXDOMAIN'), ts, server)
    with pending_dns_lock:
        pending_dns.append(lookup)


def save_dns_lookups(now):
    """Add the queued lookups to their hourly totals, counting each log line only once."""
    with pending_dns_lock:
        lookups = pending_dns[:]
        del pending_dns[:]
    if not lookups:
        return

    try:
        con = connect_stats_db()
        try:
            with con:
                for line, hour, src_ip, query, sld, category, failed, ts, server in lookups:
                    if con.execute("insert or ignore into dns_seen values (?, ?)", (line, now)).rowcount != 1:
                        continue
                    con.execute("insert into dns_activity values (?, ?, ?, ?, ?, 1, ?, ?) "
                                "on conflict(hour, src_ip, query) do update set "
                                "category = coalesce(excluded.category, category), "
                                "lookups = lookups + 1, failed = failed + excluded.failed, "
                                "first_seen = min(first_seen, excluded.first_seen)",
                                (hour, src_ip, query, sld, category, failed, ts))
                    if server:
                        con.execute("insert into dns_external_resolvers values (?, ?, ?, ?, 1) "
                                    "on conflict(src_ip, server) do update set "
                                    "first_seen = min(first_seen, excluded.first_seen), "
                                    "last_seen = max(last_seen, excluded.last_seen), "
                                    "lookups = lookups + 1", (src_ip, server, ts, ts))
        finally:
            con.close()
    except Exception:
        # Nothing was committed, so keep these lookups for the next save.
        with pending_dns_lock:
            pending_dns[:0] = lookups
        raise


def delete_old_dns(now):
    con = connect_stats_db()
    with con:
        con.execute("delete from dns_activity where hour < ?", (now - DNS_RETENTION_SECONDS,))
        con.execute("delete from dns_external_resolvers where last_seen < ?", (now - DNS_RETENTION_SECONDS,))
        con.execute("delete from dns_seen where saved_at < ?", (now - DNS_SEEN_RETENTION_SECONDS,))
    con.close()


def format_utc_minute(timestamp):
    return time.strftime('%Y/%m/%d %H:%M UTC', time.gmtime(timestamp))


def get_dns_timeline(con, in_range, stime, etime):
    """Return lookups per hour, or per day for longer periods, split into normal, failed and flagged."""
    size, label_format = (HOUR, '%H:00') if etime - stime <= DNS_HOURLY_RANGE_SECONDS else (DAY, '%d/%m')
    totals = {row[0]: row[1:] for row in con.execute(
        "select hour - hour % ?, "
        "sum(case when category is null then lookups - failed else 0 end), "
        "sum(case when category is null then failed else 0 end), "
        "sum(case when category is not null then lookups else 0 end) "
        "from dns_activity " + in_range + " group by 1", (size, stime - HOUR, etime))}
    timeline = {'labels': [], 'normal': [], 'failed': [], 'flagged': []}
    for bucket in range(stime - stime % size, etime - etime % size + 1, size):
        normal, failed, flagged = totals.get(bucket, (0, 0, 0))
        timeline['labels'].append(time.strftime(label_format, time.gmtime(bucket)))
        timeline['normal'].append(normal)
        timeline['failed'].append(failed)
        timeline['flagged'].append(flagged)
    return timeline


def get_flagged_by_device(con, in_range, stime, etime):
    """Return flagged lookups per category for the devices with the most of them."""
    rows = con.execute("select src_ip, category, sum(lookups) from dns_activity " + in_range +
                       " and category is not null group by 1, 2", (stime - HOUR, etime)).fetchall()
    device_totals = {}
    for src_ip, _, lookups in rows:
        device_totals[src_ip] = device_totals.get(src_ip, 0) + lookups
    devices = sorted(device_totals, key=lambda ip: (-device_totals[ip], ip))[:TOP_LIMIT]
    series = {category: [0] * len(devices) for category in sorted({row[1] for row in rows if row[0] in devices})}
    for src_ip, category, lookups in rows:
        if src_ip in devices:
            series[category][devices.index(src_ip)] = lookups
    return {'labels': [get_device_label(ip) for ip in devices], 'series': series}


def get_new_domains(con, stime):
    """Return the most recently first-seen domains, leaving out well-known ones."""
    domains = []
    rows = con.execute("select sld, min(first_seen), sum(lookups), count(distinct src_ip), min(src_ip), max(category) "
                       "from dns_activity group by sld having min(first_seen) >= ? order by 2 desc", (stime,))
    for sld, first_seen, lookups, devices, device, category in rows:
        if sld in top_domains:
            continue
        label = get_device_label(device)
        domains.append({'domain': sld, 'first_seen': format_utc_minute(first_seen), 'lookups': lookups, 'category': category,
                        'device': label if devices == 1 else label + ' and ' + str(devices - 1) + ' more'})
        if len(domains) == NEW_DOMAIN_LIMIT:
            break
    return domains


def get_dns_activity(stime, etime):
    """Return the DNS overview for the time range, limited to the days that are retained."""
    stime = max(stime, etime - DNS_RETENTION_SECONDS)
    in_range = "where hour > ? and hour <= ?"
    con = connect_stats_db()
    try:
        lookups, domains, failed, flagged = con.execute(
            "select coalesce(sum(lookups), 0), count(distinct query), coalesce(sum(failed), 0), "
            "coalesce(sum(case when category is not null then lookups else 0 end), 0) "
            "from dns_activity " + in_range, (stime - HOUR, etime)).fetchone()
        failed_by_device = con.execute("select src_ip, sum(failed) from dns_activity " + in_range +
                                       " group by 1 having sum(failed) > 0 order by 2 desc limit ?",
                                       (stime - HOUR, etime, TOP_LIMIT)).fetchall()
        resolvers = con.execute("select src_ip, server, sum(lookups), max(last_seen) from dns_external_resolvers "
                                "where last_seen >= ? and first_seen <= ? group by 1, 2 order by 3 desc limit ?",
                                (stime, etime, TOP_LIMIT)).fetchall()
        return {
            'summary': {'lookups': lookups, 'domains': domains, 'flagged': flagged,
                        'failed_percent': round(100.0 * failed / lookups, 1) if lookups else 0},
            'timeline': get_dns_timeline(con, in_range, stime, etime),
            'failed_by_device': [{'label': get_device_label(ip), 'count': count} for ip, count in failed_by_device],
            'flagged_by_device': get_flagged_by_device(con, in_range, stime, etime),
            'new_domains': get_new_domains(con, stime),
            'external_resolvers': [{'device': get_device_label(ip), 'server': server, 'lookups': count,
                                    'last_seen': format_utc_minute(last_seen)}
                                   for ip, server, count, last_seen in resolvers],
        }
    finally:
        con.close()


class HourlyStats(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID

    def run(self):
        time.sleep(FIRST_SAVE_DELAY)

        while 1:
            now = int(time.time())
            try:
                save_country_stats(collect_country_totals(now))
                delete_old_stats(now)
            except Exception as e:
                log.debug('FG-ERROR: ' + str(e.__doc__) + " - " + str(e))
            try:
                save_connections(now)
                delete_old_connections(now)
            except Exception as e:
                log.debug('FG-ERROR: ' + str(e.__doc__) + " - " + str(e))
            try:
                save_dns_lookups(now)
                delete_old_dns(now)
            except Exception as e:
                log.debug('FG-ERROR: ' + str(e.__doc__) + " - " + str(e))
            time.sleep(SAVE_INTERVAL)
