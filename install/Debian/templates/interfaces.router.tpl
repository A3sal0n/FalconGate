# Falcongate router-mode network configuration (Debian / ifupdown)
# IFACE0 = LAN (static, serves DHCP), IFACE1 = WAN (DHCP client / uplink)

auto lo
iface lo inet loopback

# LAN interface: static address, Falcongate serves DHCP here
auto IFACE0
iface IFACE0 inet static
    address IP0
    netmask 255.255.255.0

# WAN interface: obtains its address and default route from the upstream router
auto IFACE1
iface IFACE1 inet dhcp
