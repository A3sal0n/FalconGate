# FalconGate — Component Testing Guide

This guide helps you verify that every component FalconGate depends on is
installed and working after running the installer
(`install/Ubuntu/easy_install.sh` or `install/Debian/easy_install.sh`).

It applies to **both the Ubuntu and Debian installs** — the components are the
same; only a few distro-specific details differ (called out inline), chiefly the
PHP-FPM service name and the networking backend (Ubuntu uses netplan, Debian uses
ifupdown / `/etc/network/interfaces`).

Work through the sections in order. The earlier components (packet capture, Zeek,
dnsmasq, dnscrypt-proxy) are the foundation the detection logic is built on, so
confirming them first makes later failures easier to diagnose.

## Conventions

- Run the commands **on the FalconGate appliance** over SSH unless a step says
  "from a client device."
- `IFACE0` is the **internal/monitoring** interface, `IFACE1` is the
  **uplink/WAN** interface. Substitute your real interface names (check with
  `ip -br link`).
- `IP0` is the appliance address on the internal network (e.g. `192.168.100.1`
  in router mode). Substitute your real address.
- Most commands need root. Prefix with `sudo` or run from a root shell.
- A ✅ line shows what a healthy result looks like.
- **PHP-FPM service name** depends on the PHP version your distro ships
  (Ubuntu 24.04: `php8.3-fpm`; Debian 12: `php8.2-fpm`; Debian 13: `php8.4-fpm`).
  Set a shell variable once and reuse it in the commands below:

  ```bash
  PHP_FPM="php$(ls /etc/php | sort -V | tail -1)-fpm"
  echo "$PHP_FPM"   # e.g. php8.3-fpm
  ```
- FalconGate logs through syslog and its logs API reads `/var/log/syslog`, so
  **rsyslog must be installed** (the default on Ubuntu and on Debian 12/13). If
  that file is absent, `journalctl | grep FG-` shows the same messages.

---

## 0. Quick health snapshot

Run this first to see the state of every managed service at once:

```bash
systemctl --no-pager status falcongate zeek dnsmasq dnscrypt-proxy nginx "$PHP_FPM" netfilter-persistent
```

✅ `falcongate`, `dnsmasq`, `dnscrypt-proxy`, `nginx`, and `$PHP_FPM` show
`active (running)`; `zeek` shows `active (exited)` (it is a `oneshot` service
that leaves the Zeek cluster running in the background).

List the ports the appliance is listening on:

```bash
ss -tulpn
```

✅ You should see `:53` (dnsmasq), `:443` and `:80` (nginx), `127.0.0.1:5000`
(FalconGate API), and `127.0.2.1:53` (dnscrypt-proxy).

---

## 1. Packet capture (Zeek AF_PACKET)

Zeek captures traffic with its built-in AF_PACKET support, which needs no extra
kernel module. If capture is misconfigured, Zeek sees no packets and no detection
works.

```bash
# Built-in AF_PACKET plugin available?
/opt/zeek/bin/zeek -N Zeek::AF_Packet

# Workers configured to capture through it?
grep -E '^(interface|lb_method|lb_procs)=' /opt/zeek/etc/node.cfg

# Zeek workers holding packet sockets?
sudo ss --packet --processes | grep zeek
```

✅ `zeek -N` lists `Zeek::AF_Packet`, `node.cfg` shows
`interface=af_packet::<IFACE0>` and `lb_method=custom`, and `ss` shows packet
sockets owned by `zeek` once Zeek is running.

Zeek is installed as an apt package from the Zeek project's repository. Confirm
the package and its source:

```bash
apt-cache policy zeek-8.0
```

✅ The installed version is listed with a
`download.opensuse.org/repositories/security:/zeek` source.

---

## 2. Zeek (network security monitor)

Zeek watches `IFACE0` and writes the logs FalconGate parses.

```bash
# Cluster node status
/opt/zeek/bin/zeekctl status
```

✅ The `manager`, `proxy-1`, and `worker-1` nodes are listed as `running`.

Confirm Zeek is actively producing logs (the FalconGate log parsers read these
exact files):

```bash
ls -l /opt/zeek/spool/manager/
tail -f /opt/zeek/spool/manager/conn.log
```

✅ `conn.log`, `dns.log`, `http.log`, `files.log`, and `notice.log` exist, and
`conn.log` grows while traffic flows through the appliance. Each line is JSON
(FalconGate relies on the `json-logs` policy).

Verify the FalconGate Zeek policy is installed:

```bash
ls /opt/zeek/share/zeek/policy/FalconGate/
grep -r "FalconGate/extract-important-files" /opt/zeek/share/zeek/site/local.zeek
```

✅ The policy directory contains `extract-important-files.zeek`, and `local.zeek`
loads it. When suspicious files cross the wire they are carved into
`/opt/zeek/spool/manager/extract_files/`.

If `zeekctl status` is unhappy, re-run the deploy:

```bash
/opt/zeek/bin/zeekctl deploy
```

---

## 3. Dnsmasq (DNS + DHCP, domain blocking)

Dnsmasq hands out DHCP leases on the internal network, forwards DNS to
dnscrypt-proxy, and enforces the domain blocklist via `/etc/dnsmasq.block`.

```bash
# Service up and config valid
dnsmasq --test
systemctl status dnsmasq
```

✅ `dnsmasq --test` prints `syntax check OK`.

**DNS resolution** (from a client on the internal network, or on the appliance
pointing at `IP0`):

```bash
dig @IP0 example.com
```

✅ You get an answer section with an A record.

**Domain blocking** — pick any domain currently listed in the block file:

```bash
grep -m1 -v localhost /etc/dnsmasq.block        # on the appliance, see a blocked domain
dig @IP0 <that-domain>
```

✅ A blocked domain resolves to `127.0.0.1` (dnsmasq returns the sinkhole entry
written by FalconGate's intel downloader).

**DHCP** — from a client set to DHCP on the internal network:

```bash
# On the appliance, watch leases being handed out
tail -f /var/log/dnsmasq.leases
```

✅ The client receives an address inside the configured DHCP range and appears
in `dnsmasq.leases`.

---

## 4. dnscrypt-proxy (encrypted upstream DNS)

Dnsmasq forwards to dnscrypt-proxy on `127.0.2.1:53`, which encrypts queries to
upstream resolvers.

```bash
systemctl status dnscrypt-proxy
# Resolve directly through dnscrypt-proxy
dig @127.0.2.1 example.com
```

✅ The query returns an answer. In the journal you can see it selecting a
resolver:

```bash
journalctl -u dnscrypt-proxy --no-pager | tail -20
```

✅ Log lines show a chosen server (e.g. `google`, `cloudflare`) and successful
certificate retrieval.

---

## 5. iptables + ipset (firewall and IP blocking)

FalconGate blocks malicious/blacklisted IPs through two ipset lists referenced
by the iptables ruleset.

```bash
# Rules loaded, including the blacklist match-sets
sudo iptables -L -n -v
sudo iptables -t nat -L -n -v

# ipset lists exist
sudo ipset list -name
```

✅ `iptables -L` shows `FORWARD`/`INPUT` rules matching `blacklist` and
`blacklist-user` sets, the nat table shows a `MASQUERADE` rule on `IFACE1`, and
`ipset list -name` returns `blacklist` and `blacklist-user`.

**Test user-driven blocking** through the running API (this is exactly what the
web UI's block action calls):

```bash
# Add a harmless test IP to the user blacklist
curl -s -X POST http://127.0.0.1:5000/api/v1.0/falcongate/response/host \
  -H 'Content-Type: application/json' \
  -d '{"action":"blacklist","target":["198.51.100.23"]}'

# Confirm it landed in the set
sudo ipset list blacklist-user | grep 198.51.100.23

# Clean up
curl -s -X POST http://127.0.0.1:5000/api/v1.0/falcongate/response/host \
  -H 'Content-Type: application/json' \
  -d '{"action":"unblock","target":["198.51.100.23"]}'
```

✅ The address appears in `blacklist-user` after the first call and is gone after
the unblock call.

Confirm persistence across reboots:

```bash
ls -l /etc/ipset.rules /etc/iptables.rules
grep ipset /etc/crontab
```

✅ Both rule files exist and the crontab restores/saves ipset on reboot.

---

## 6. FalconGate service + internal API

The main Python daemon runs all detection threads and exposes a local Flask API
on `127.0.0.1:5000` (consumed by the PHP web UI).

```bash
systemctl status falcongate
```

✅ `active (running)`.

Check the daemon's own log stream (it logs to syslog, tagged `FG-`):

```bash
grep "FG-" /var/log/syslog | tail -30
```

✅ You see `FG-INFO: Started thread ...` lines for the config reader, log
parsers, intel downloader, port scanner, etc., and no repeating `FG-FATAL` /
`FG-ERROR` tracebacks.

**API smoke tests** (each mirrors a page in the web UI):

```bash
# Active devices
curl -s -X POST http://127.0.0.1:5000/api/v1.0/falcongate/status \
  -H 'Content-Type: application/json' -d '{"target":"devices"}'

# Network configuration
curl -s -X POST http://127.0.0.1:5000/api/v1.0/falcongate/status \
  -H 'Content-Type: application/json' -d '{"target":"network"}'

# Recent alerts (last week, all)
curl -s -X POST http://127.0.0.1:5000/api/v1.0/falcongate/status \
  -H 'Content-Type: application/json' \
  -d '{"target":"alerts","timeframe":"alerts_week","filter":"all"}'

# Last 20 FalconGate log lines
curl -s -X POST http://127.0.0.1:5000/api/v1.0/falcongate/status \
  -H 'Content-Type: application/json' -d '{"target":"logs","log_count":20}'
```

✅ Each returns HTTP 200 with a JSON body (devices array, network object, alert
list, or log lines).

---

## 7. Nginx + PHP-FPM (web dashboard)

The dashboard is served over HTTPS and renders data from the API above.

```bash
nginx -t
systemctl status nginx "$PHP_FPM"
```

✅ `nginx -t` reports the config is OK. On Debian the installer also removes the
distro's default site (`/etc/nginx/sites-enabled/default`) so FalconGate answers
on port 80.

Test the HTTP→HTTPS redirect and that PHP executes:

```bash
curl -sI http://IP0/                       # expect 301 to https
curl -skI https://IP0/                     # expect 200
```

✅ Port 80 returns `301` to `https://`, and port 443 returns `200`.

From a browser on the internal network, open `https://IP0/`.

✅ The login page loads (self-signed certificate warning is expected). Log in
with the admin account:

- Default username: `admin`
- While the default password is in use, every dashboard page opens a window
  asking for a new one. It appears again after a Falcongate reset.
- The password hash lives in `html/pwd.db`. Change it from the dashboard's admin
  page (which uses the running PHP-FPM), or regenerate the hash with the bundled
  script if the PHP CLI (`php-cli`) is installed:

  ```bash
  cd /opt/FalconGate/html
  php encrypt_passwd.php 'yourNewPassword'   # prints the bcrypt hash
  # then write "admin <hash>" into /opt/FalconGate/html/pwd.db
  ```

✅ After login the dashboard shows devices, alerts, logs, and network stats
without PHP errors (check `/var/log/nginx/error.log` if a page is blank).

---

## 8. Recon: Nmap port scanning

FalconGate runs a daily Nmap scan of known hosts (the `PortScanner` thread) and
stores discovered open ports per device.

```bash
# Nmap present and runnable
nmap --version

# From a client on the network, generate a scannable target, or confirm
# FalconGate's scan ran:
grep "Port scan" /var/log/syslog | tail
```

✅ `nmap --version` works, and syslog shows `FG-INFO: Port scan started` /
`... finished`. After a scan cycle, the devices API (section 6) reports open
TCP/UDP ports for active hosts.

> The first automatic scan runs shortly after boot and then once every 24 h, so
> on a fresh install you may need to wait or restart the service to see results.

---

## 9. Offensive: default-credential assessment (Hydra)

After the port scan, the `ScheduledScans` thread tests hosts that expose
remote-access services (SSH, FTP, Telnet, RDP, SMB, VNC) against a list of known
default credentials and raises an alert on any hit.

```bash
# Tool present
hydra -h | head -3

# Assessment activity in the log
grep "Default credentials assessment" /var/log/syslog | tail
```

✅ Hydra runs, and syslog shows the assessment `started` / `finished` lines.

To exercise the full path, stand up a throwaway service on the internal network
that uses a known default credential (for example a test SSH container with a
default account) and confirm a **"Default credentials"** alert appears in the
dashboard after the next assessment cycle. Only do this against systems you own.

---

## 10. Threat-intel download

The `DownloadIntel` thread refreshes IP/domain blocklists every 4 hours and
rewrites `/etc/dnsmasq.block`.

```bash
grep "Downloading daily blacklists" /var/log/syslog | tail
wc -l /etc/dnsmasq.block
```

✅ The download log line appears, and `/etc/dnsmasq.block` contains many sinkhole
entries (more than the two localhost lines). Re-running the domain-block test in
section 3 against a freshly listed domain confirms the pipeline end-to-end.

---

## 11. Detection logic (optional, uses the test scripts)

The `tests/` folder contains scripts that generate traffic patterns FalconGate
should detect. **Run these from a client device connected to the FalconGate
network**, not on the appliance:

| Script | Simulates | Expected alert |
|---|---|---|
| `tests/dga.py` | Domain Generation Algorithm lookups | **Malware / DGA** alert (after ≥20 random-domain lookups, raised hourly) |
| `tests/malware_domains.py` | DNS lookups of known-bad domains | **Malware** (bad domain) alert |
| `tests/port_scanner.py` | An outbound port scan | See the note below — no alert on a stock Zeek 8 install |

> **Port scanning note:** Zeek 8 no longer ships the built-in scan detector
> (`misc/scan` was removed upstream), so the bundled `local.zeek` does not emit a
> `Scan::*` notice and `tests/port_scanner.py` will not raise a FalconGate alert
> on a stock install. FalconGate's own port-scan feature works the other way
> around: the `PortScanner` thread (`lib/recon.py`) uses Nmap to scan your LAN
> devices and records their open ports (verified in section 8), rather than
> detecting scans originating from clients. To get Zeek-side scan detection back,
> install a scan-detection Zeek package and `@load` it from `local.zeek`.

The application-level unit tests run on the appliance:

```bash
cd /opt/FalconGate
/opt/fg/bin/python -m unittest discover -s tests -p 'test_*.py' -v
```

✅ The network-configuration tests pass.

After running a traffic script, check for the resulting alert:

```bash
curl -s -X POST http://127.0.0.1:5000/api/v1.0/falcongate/status \
  -H 'Content-Type: application/json' \
  -d '{"target":"alerts","timeframe":"alerts_week","filter":"all"}'
```

✅ A matching alert is present (DGA alerts are evaluated hourly; domain alerts
every minute — allow a few minutes).

---

## 12. Email alerting (optional)

If you configured Gmail reporting in the dashboard, FalconGate emails new alerts
via `smtp.gmail.com:587`.

- Ensure `dst_emails`, `mailer_address`, and `mailer_pwd` are set in
  `html/user_config.ini` (via the dashboard config page).
- Trigger an alert (section 11) and confirm the message arrives.

```bash
grep -i "gmail\|mailer\|sendmail" /var/log/syslog | tail
```

✅ No `FG-ERROR: Falcongate was not able to send a Gmail alert` lines; the alert
email is delivered.

> Gmail requires an **App Password** (not your normal account password) and may
> block the login otherwise — check the appliance's outbound connectivity to
> `smtp.gmail.com:587` if delivery fails.

---

## Troubleshooting summary

| Symptom | First thing to check |
|---|---|
| No detections at all | AF_PACKET capture configured (§1) and Zeek logs growing (§2) |
| Clients get no DNS / no IP | dnsmasq running, `IP0` listener, DHCP range (§3) |
| DNS works but not encrypted | dnscrypt-proxy on `127.0.2.1` (§4) |
| Blocked IPs still reachable | ipset sets populated + iptables rules loaded (§5) |
| Dashboard blank / errors | API 200s (§6), then nginx + php-fpm logs (§7) |
| No alerts emailed | user_config mail settings + Gmail App Password (§12) |

All FalconGate daemon activity is tagged `FG-` in `/var/log/syslog`, so
`grep "FG-" /var/log/syslog` is the single most useful command when something
behaves unexpectedly (use `journalctl | grep FG-` if your system has no
`/var/log/syslog`).
