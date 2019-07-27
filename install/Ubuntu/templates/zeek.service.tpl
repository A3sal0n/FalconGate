[Unit]
Description=Zeek
After=network.target

[Service]
ExecStartPre=/opt/zeek/bin/zeekctl cleanup
ExecStartPre=/opt/zeek/bin/zeekctl check
ExecStartPre=/opt/zeek/bin/zeekctl install
ExecStart=/opt/zeek/bin/zeekctl start
ExecStop=/opt/zeek/bin/zeekctl stop
RestartSec=10s
Type=oneshot
RemainAfterExit=yes
TimeoutStopSec=600

[Install]
WantedBy=multi-user.target