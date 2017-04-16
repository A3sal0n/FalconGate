[Unit]
Description=FalconGate Server
After=dnsmasq.service
After=nginx.service

[Service]
User=root
WorkingDirectory=/opt/FalconGate
ExecStart=/usr/bin/python falcongate.py
Restart=always

[Install]
WantedBy=multi-user.target