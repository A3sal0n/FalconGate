network:
    ethernets:
        IFACE0:
            dhcp4: no
            optional: true
            addresses: [IP0/24]
            gateway4: GATEWAY
            nameservers:
                addresses: [127.0.2.1]
        IFACE1:
            dhcp4: no
            optional: true
            addresses: [IP1/24]
            gateway4: GATEWAY
            nameservers:
                addresses: [127.0.2.1]
    version: 2