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


def connect_stats_db():
    con = lite.connect(STATS_DB)
    con.execute('PRAGMA busy_timeout = 5000')
    return con


def create_stats_db():
    con = connect_stats_db()
    with con:
        con.execute("create table if not exists country_stats(hour int, country text, bytes_sent int, "
                    "bytes_received int, pqt_sent int, pqt_received int, nconn int, primary key (hour, country))")
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


class HourlyStats(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID

    def run(self):
        time.sleep(FIRST_SAVE_DELAY)

        while 1:
            try:
                now = int(time.time())
                save_country_stats(collect_country_totals(now))
                delete_old_stats(now)
            except Exception as e:
                log.debug('FG-ERROR: ' + str(e.__doc__) + " - " + str(e))
            time.sleep(SAVE_INTERVAL)
