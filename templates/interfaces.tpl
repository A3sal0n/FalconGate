auto lo
iface lo inet loopback

auto $IFACE0$
iface $IFACE0$ inet static
        address 192.168.0.2
        netmask 255.255.255.0
        gateway 192.168.0.1

auto $IFACE1$
iface $IFACE1$ inet dhcp
