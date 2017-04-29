[Unit]
Description=dnscrypt-proxy listening socket

[Socket]
ListenStream=127.0.2.1:53
ListenDatagram=127.0.2.1:53

[Install]
WantedBy=sockets.target
