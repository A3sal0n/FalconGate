auto lo
iface lo inet loopback

auto $IFACE$
iface $IFACE$ inet static
address $STATIP$
netmask $NETMASK$
gateway $GATEWAY$
