The installation script targets **Debian 12 (bookworm)** or **Debian 13
(trixie)** and builds CPython 3.15.0 under `/opt/python/3.15.0`. It does not
replace the system Python. This Debian installer is a port of the Ubuntu one; it
has not yet been validated on a Debian server, so treat the listed OS and Python
versions as the target, not a tested-support claim.

Zeek is not in Debian's stable repositories, so the installer adds the Zeek
project's repository on the openSUSE Build Service (`security:zeek`) and installs
the `zeek-8.0` LTS package to `/opt/zeek`. Later Zeek 8.0 patch releases arrive
through apt. Zeek captures packets with its built-in **AF_PACKET** support, which
needs no out-of-tree kernel module, so kernel upgrades don't affect capture.

Run `easy_install.sh` from a Debian 12/13 installation with two active network
interfaces and at least 5 GiB of free disk space. The script installs system
packages including Zeek, builds Python, configures networking, and reboots system
services. Review the script and its network configuration before running it on a
production host.

## Differences from the Ubuntu installer

- **Networking** is configured with ifupdown (`/etc/network/interfaces`) instead
  of netplan — see [`templates/interfaces.router.tpl`](templates/interfaces.router.tpl)
  and [`templates/interfaces.attached.tpl`](templates/interfaces.attached.tpl).
  This also matches the `/etc/network/interfaces` path FalconGate already expects
  in `lib/utils.py`. The installer assumes a standard Debian install that uses
  ifupdown; on a cloud image that uses `systemd-networkd` or cloud-init you will
  need to disable those first.
- **No PPA**: dnscrypt-proxy is installed from Debian's own repositories.
- **PHP-FPM** version differs by release (8.2 on bookworm, 8.4 on trixie), so the
  installer detects the installed version and points nginx at the correct
  `/run/php/phpX.Y-fpm.sock` socket automatically.
- **DNS**: `/etc/resolv.conf` is pointed directly at dnscrypt-proxy
  (`127.0.2.1`); systemd-resolved is disabled only if it happens to be present.

## WAN/LAN interface detection

After you select the two interfaces, the installer automatically detects which
one has Internet access and uses it as the WAN (uplink, NAT'd). The other
interface becomes the LAN: it receives the static IP (`192.168.100.1` in router
mode) and runs the DHCP server that clients connect to, and it is also the
interface Zeek monitors. Connect your management/client device to the LAN
interface to reach the dashboard and SSH. If auto-detection cannot determine
which interface reaches the Internet (for example, neither is online during
install), the script falls back to asking you to pick the WAN interface.

## Deployment modes

During installation `easy_install.sh` asks you to choose a **deployment mode**.
The mode only changes how the two interfaces are addressed and how the appliance
relates to the rest of your network; the detection stack (Zeek, dnsmasq,
dnscrypt-proxy, the blocklists, and the web UI) is identical in both modes.

In both modes the roles are the same: **IFACE0 is the LAN** (static IP, DHCP
server, the interface Zeek monitors, management access allowed) and **IFACE1 is
the WAN** (the Internet uplink that gets NAT/MASQUERADE; new inbound connections
from this side are dropped by the firewall). The installer picks which physical
NIC fills each role using the WAN auto-detection described above. DNS in both
modes is resolved locally through dnscrypt-proxy at `127.0.2.1`, and the iptables
ruleset ([`fw/iptables.rules`](fw/iptables.rules)) is the same for both.

| | Attached mode | Router mode |
|---|---|---|
| Appliance's role | Joins an **existing** network next to your current router | **Becomes the gateway** for a new, isolated LAN |
| LAN interface (IFACE0) | Static `<base>.2` on your existing subnet | Static `192.168.100.1` on a new subnet |
| WAN interface (IFACE1) | Static `<base>.3` on the same existing subnet | **DHCP client** to your modem/ISP/upstream router |
| Upstream gateway | Your existing router (reused) | Learned via DHCP on the WAN |
| DHCP pool (dnsmasq) | `<base>.100`–`<base>.200` | `192.168.100.100`–`192.168.100.200` |
| How devices get protected | Point a device's gateway/DNS at the appliance (or let its DHCP serve them) | Every device on the LAN is protected automatically |
| interfaces template | [`templates/interfaces.attached.tpl`](templates/interfaces.attached.tpl) | [`templates/interfaces.router.tpl`](templates/interfaces.router.tpl) |

`<base>` is the first three octets of your existing subnet, derived from the
default gateway found on the WAN interface (e.g. a gateway of `192.168.1.1`
yields `192.168.1`).

### Attached mode

The appliance sits **on your existing LAN** alongside the router you already
have. Both of its interfaces get static addresses on that subnet — `<base>.2` on
the LAN side and `<base>.3` on the WAN side — and the WAN side holds the default
route to your existing router. FalconGate does not replace your router; it
protects only the devices whose traffic is sent through it.

Because FalconGate is not inline, a device is only inspected/filtered when it
routes through the appliance. You achieve that either by setting the device's
gateway (and DNS) to the appliance's LAN IP (`<base>.2`), or by letting the
appliance's own DHCP server lease it an address. If you use the appliance's DHCP,
**disable DHCP on your existing router** (or restrict its range) so the two DHCP
servers on the shared subnet don't conflict. Manage the appliance via its LAN IP
(`<base>.2`): the firewall drops new inbound connections that arrive on the WAN
IP (`<base>.3`).

### Router mode

The appliance **becomes the gateway** for a brand-new, isolated LAN. The WAN
interface pulls its address via DHCP from your modem or upstream router, while
the LAN interface takes the static address `192.168.100.1` and serves DHCP on
`192.168.100.0/24`. Every client connected to the LAN interface is routed and
filtered through FalconGate by default — there is nothing to configure per
device.

Connect your management device to the LAN side and reach the dashboard at
`https://192.168.100.1` (SSH: `ssh <your-user>@192.168.100.1`).
