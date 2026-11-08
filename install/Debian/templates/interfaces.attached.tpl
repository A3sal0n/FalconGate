# Falcongate attached-mode network configuration (Debian / ifupdown)
# Both interfaces sit on the existing LAN subnet. IFACE0 = LAN (static + DHCP
# server), IFACE1 = WAN (static, holds the default route to the existing router).

auto lo
iface lo inet loopback

# LAN interface: management + the address clients use as their gateway/DNS
auto IFACE0
iface IFACE0 inet static
    address IP0
    netmask 255.255.255.0

# WAN interface: carries the single default route to the existing router
auto IFACE1
iface IFACE1 inet static
    address IP1
    netmask 255.255.255.0
    gateway GATEWAY
