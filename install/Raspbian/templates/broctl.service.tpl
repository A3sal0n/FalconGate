[Unit]
Description=Bro
After=network.target

[Service]
ExecStartPre=/usr/local/bro/bin/broctl cleanup
ExecStartPre=/usr/local/bro/bin/broctl check
ExecStartPre=/usr/local/bro/bin/broctl install
ExecStart=/usr/local/bro/bin/broctl start
ExecStop=/usr/local/bro/bin/broctl stop
RestartSec=10s
Type=oneshot
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target