The installation script targets Ubuntu Server 24.04 LTS and builds CPython 3.15.0
under `/opt/python/3.15.0`. It does not replace the system Python. The installer
and appliance deployment have not yet been validated on an Ubuntu 24.04 server;
the listed OS and Python versions are the migration target, not a tested-support
claim.

Run `easy_install.sh` from an Ubuntu Server 24.04 installation with two active
network interfaces and at least 5 GiB of free disk space. The script installs
system packages including Zeek, builds Python, configures networking, and reboots
system services. Review the script and its network configuration before running
it on a production host.

Zeek is not in Ubuntu's stable repositories, so the installer adds the Zeek
project's repository on the openSUSE Build Service (`security:zeek`) and installs
the `zeek-8.0` LTS package to `/opt/zeek`. Later Zeek 8.0 patch releases arrive
through apt. Zeek captures packets with its built-in **AF_PACKET** support, which
needs no out-of-tree kernel module, so kernel upgrades don't affect capture. A
Debian port of this installer is available under [`../Debian`](../Debian).

After you select the two interfaces, the installer automatically detects which
one has Internet access and uses it as the WAN (uplink, NAT'd). The other
interface becomes the LAN: it receives the static IP you choose (`192.168.100.1` by default in router
mode) and runs the DHCP server that clients connect to, and it is also the
interface Zeek monitors. Connect your management/client device to the LAN
interface to reach the dashboard and SSH. If auto-detection cannot determine
which interface reaches the Internet (for example, neither is online during
install), the script falls back to asking you to pick the WAN interface.

## LAN IP address

The installer asks you for the static IP address of the LAN interface. It suggests
`192.168.100.1` in router mode and `<base>.2` in attached mode, so you can press
Enter to keep the suggestion. The LAN uses a /24 network, and the DHCP pool is always
`.100` to `.200` of that network: choosing `10.20.30.1`, for example, gives a pool of
`10.20.30.100` to `10.20.30.200`.

The address must be unused and private (`10.x.x.x`, `172.16-31.x.x` or `192.168.x.x`),
and its last number can't be `0`, `255` or inside the DHCP pool. In attached mode it
must be on your existing `<base>.0/24` network and can't be the gateway or `<base>.3`,
which is the WAN interface's address. In router mode it can't be on the same network
as the WAN interface. The installer asks again if the address doesn't meet these rules.

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
| LAN interface (IFACE0) | Static IP you choose on your existing subnet (default `<base>.2`) | Static IP you choose on a new subnet (default `192.168.100.1`) |
| WAN interface (IFACE1) | Static `<base>.3` on the same existing subnet | **DHCP client** to your modem/ISP/upstream router |
| Upstream gateway | Your existing router (reused) | Learned via DHCP on the WAN |
| DHCP pool (dnsmasq) | `<base>.100`–`<base>.200` | `.100`–`.200` of the LAN subnet (default `192.168.100.100`–`192.168.100.200`) |
| How devices get protected | Point a device's gateway/DNS at the appliance (or let its DHCP serve them) | Every device on the LAN is protected automatically |
| Netplan template | [`50-cloud-init.yaml.tpl`](templates/50-cloud-init.yaml.tpl) | [`50-cloud-init.yaml.router.tpl`](templates/50-cloud-init.yaml.router.tpl) |

`<base>` is the first three octets of your existing subnet, derived from the
default gateway found on the WAN interface (e.g. a gateway of `192.168.1.1`
yields `192.168.1`).

### Attached mode

The appliance sits **on your existing LAN** alongside the router you already
have. Both of its interfaces get static addresses on that subnet — `<base>.2` on
the LAN side and `<base>.3` on the WAN side — and both use your existing router as
their upstream gateway. FalconGate does not replace your router; it protects only
the devices whose traffic is sent through it.

Because FalconGate is not inline, a device is only inspected/filtered when it
routes through the appliance. You achieve that either by setting the device's
gateway (and DNS) to the appliance's LAN IP (`<base>.2`), or by letting the
appliance's own DHCP server lease it an address. If you use the appliance's DHCP,
**disable DHCP on your existing router** (or restrict its range) so the two DHCP
servers on the shared subnet don't conflict. Manage the appliance via its LAN IP
(`<base>.2`): the firewall drops new inbound connections that arrive on the WAN
IP (`<base>.3`).

Choose attached mode when you want to add FalconGate to a network without
re-cabling it or changing the existing router, and you're comfortable steering
selected devices through it.

### Router mode

The appliance **becomes the gateway** for a brand-new, isolated LAN. The WAN
interface pulls its address via DHCP from your modem or upstream router, while
the LAN interface takes the static address you choose (`192.168.100.1` by default)
and serves DHCP on
its /24 network (`192.168.100.0/24` by default). Every client connected to the LAN interface is routed and
filtered through FalconGate by default — there is nothing to configure per
device.

This is the recommended mode for the typical "FalconGate is my router" topology:
plug your modem/uplink into the WAN interface and your switch/clients into the
LAN interface. Connect your management device to the LAN side and reach the
dashboard at `https://<LAN IP>` (SSH: `ssh ubuntu@<LAN IP>`), using the LAN address
you chose.

Choose router mode when FalconGate should be the single choke point for all of
your LAN's traffic.