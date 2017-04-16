auto lo
iface lo inet loopback

auto $IFACE0$
iface $IFACE0$ inet dhcp

auto $IFACE1$
iface $IFACE1$ inet static
address $STATIP$
netmask $NETMASK$
gateway $GATEWAY$
