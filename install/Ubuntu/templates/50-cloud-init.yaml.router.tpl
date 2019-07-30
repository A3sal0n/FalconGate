network:
    ethernets:
        IFACE0:
            dhcp4: no
            addresses: [IP0/24]
            nameservers:
                addresses: [127.0.2.1,8.8.8.8]
        IFACE1:
            dhcp4: yes
    version: 2