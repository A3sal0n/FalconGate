The installation script targets Ubuntu Server 24.04 LTS and builds CPython 3.15.0
under `/opt/python/3.15.0`. It does not replace the system Python. The installer
and appliance deployment have not yet been validated on an Ubuntu 24.04 server;
the listed OS and Python versions are the migration target, not a tested-support
claim.

Run `easy_install.sh` from an Ubuntu Server 24.04 installation with two active
network interfaces and at least 5 GiB of free disk space. The script installs
system packages, builds Python, Zeek, and PF_RING, configures networking, and
reboots system services. Review the script and its network configuration before
running it on a production host.