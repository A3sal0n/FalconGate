[Unit]
Description=Falcongate
After=dnsmasq.service
After=nginx.service

[Service]
User=root
WorkingDirectory=/opt/Falcongate
ExecStart=/opt/fg/bin/python3 falcongate.py
Restart=always

[Install]
WantedBy=multi-user.target