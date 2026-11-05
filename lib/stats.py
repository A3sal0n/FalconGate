import ipaddress
import sqlite3 as lite
import threading
import time
from lib.logger import *
from lib.settings import homenet, lock

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
            time.sleep(SAVE_INTERVAL)
