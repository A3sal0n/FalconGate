import threading
from lib.objects import *
import sqlite3 as lite


def get_top_domains(dbname):
    con = lite.connect(dbname)
    con.text_factory = str
    with con:
        cur = con.cursor()
        cur.execute("SELECT domain FROM domains")
        rows = cur.fetchall()
        domains = []
        if rows:
            for row in rows:
                domains.append(row[0])
        else:
            pass
        return domains


# Global variables
# Master network object
global homenet
homenet = Network()

# Master lock for threads
global lock
lock = threading.Lock()

# Master list of bad IP addresses
global bad_ips
bad_ips = []

# Master whitelist of IP addresses
global good_ips
good_ips = []

# Top domains whitelist
global top_domains
top_domains = get_top_domains("db/top_domains.sqlite")

# Master thread list
global threads
threads = {}

# Stats globals
global country_stats
country_stats = {}
for k in CC.keys():
    country_stats[k] = Country(k, CC[k])

global hosts_stats
hosts_stats = {}




