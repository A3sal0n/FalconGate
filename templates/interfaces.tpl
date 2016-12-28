auto lo
iface lo inet loopback

auto $IFACE$
iface $IFACE$ inet static
address $ETH0IP$
netmask $NETMASK$
gateway $GATEWAY$
