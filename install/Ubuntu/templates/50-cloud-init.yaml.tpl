network:
    ethernets:
        IFACE0:
            dhcp4: no
            optional: true
            addresses: [IP0/24]
            gateway4: GATEWAY
            nameservers:
                addresses: [127.0.2.1,8.8.8.8]
        IFACE1:
            dhcp4: no
            optional: true
            addresses: [IP1/24]
            gateway4: GATEWAY
            nameservers:
                addresses: [127.0.2.1,8.8.8.8]
    version: 2