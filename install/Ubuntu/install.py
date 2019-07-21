#!/usr/bin/env python

import os
import shutil
import fileinput
import re
from subprocess import Popen, PIPE

# Edit the variables below to reflect your own configuration
# Static interface
IFACE0 = 'ens33'
# DHCP interface
IFACE1 = 'ens34'
# IP address of the static interface
STATIP = '192.168.0.2'
# Gateway for the static interface
GATEWAY = '192.168.0.1'
# Network mask for the static interface
NETMASK = '255.255.255.0'
# Start IP for Falcongate DHCP range
DHCPSTART = '192.168.0.4'
# Final IP for Falcongate DHCP range
DHCPEND = '192.168.0.100'


def run_command(cmd):
    os.system(cmd)


template_list = ["templates/config.ini.tpl", "templates/interfaces.tpl", "templates/broctl.tpl",
                 "templates/dnsmasq.conf.tpl",
                 "templates/local.bro.tpl", "templates/nginx_default_site.tpl",
                 "templates/dhcpcd.conf.tpl", "templates/falcongate.service.tpl", "templates/node.cfg.tpl",
                 "fw/iptables.rules"]


def main():
    if not os.geteuid() == 0:
        exit('Script must be run as root')

    install_dir = os.getcwd()
    os.chdir("../../")
    root_dir = os.getcwd()
    os.chdir(install_dir)

    for f in template_list:
        for line in fileinput.input(f, inplace=1):
            line = re.sub("\$FALCONGATEDIR\$", root_dir, line.rstrip())
            line = re.sub("\$IFACE0\$", IFACE0, line.rstrip())
            line = re.sub("\$IFACE1\$", IFACE1, line.rstrip())
            line = re.sub("\$STATIP\$", STATIP, line.rstrip())
            line = re.sub("\$NETMASK\$", NETMASK, line.rstrip())
            line = re.sub("\$GATEWAY\$", GATEWAY, line.rstrip())
            line = re.sub("\$DHCPSTART\$", DHCPSTART, line.rstrip())
            line = re.sub("\$DHCPEND\$", DHCPEND, line.rstrip())
            print(line)

    print "Updating apt sources..."
    run_command("apt-get update")

    print "Upgrading system..."
    run_command("apt-get upgrade -y")
    run_command("apt dist-upgrade -y")

    # Installing dependencies
    print "Installing dependencies..."
    run_command("apt-get install -y dnsmasq nginx php-fpm php-curl exim4-daemon-light mailutils ipset cmake make gcc "
                "g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev git python-pip dnscrypt-proxy nmap hydra "
                "libgeoip-dev")

    # Installing Zeek
    print "Installing Zeek..."
    os.chdir("../../tmp")
    print "Cloning Zeek repo..."
    run_command("git clone --recursive https://github.com/zeek/zeek")
    os.chdir("zeek")
    print "Configuring Zeek..."
    run_command("./configure")
    print "Building Zeek..."
    print "Sit back and relax because this can take quite some time :)"
    run_command("make -j2")
    print "Installing Zeek..."
    run_command("make install")
    os.chdir(install_dir)
    run_command("rm -rf ../../tmp/zeek*")
    print "Configuring broctl service..."
    shutil.copy("templates/broctl.tpl", "/etc/init.d/broctl")
    run_command("chmod +x /etc/init.d/broctl")
    run_command("update-rc.d broctl defaults")
    print "Copying and installing default Zeek policies..."
    shutil.copy("templates/local.bro.tpl", "/usr/local/bro/share/bro/site/local.bro")
    shutil.copy("templates/node.cfg.tpl", "/usr/local/bro/etc/node.cfg")
    run_command("mkdir /usr/local/bro/share/bro/policy/FalconGate")
    run_command("cp -R ../../common/bro/rules/* /usr/local/bro/share/bro/policy/FalconGate/")
    run_command("/usr/local/bro/bin/broctl install")

    # Configuring ipset
    print "Configuring ipset..."
    run_command("ipset create blacklist hash:ip maxelem 500000")
    run_command("ipset create blacklist-user hash:ip")

    # Installing conf files
    print "Installing configuration files..."
    shutil.copy("templates/config.ini.tpl", "../../config.ini")
    shutil.copy("templates/user_config.ini.tpl", "../../html/user_config.ini")
    shutil.copy("templates/pwd.db.tpl", "../../html/pwd.db")
    shutil.copy("templates/interfaces.tpl", "/etc/network/interfaces")
    shutil.copy("templates/update-exim4.conf.conf.tpl", "/etc/exim4/update-exim4.conf.conf")
    shutil.copy("templates/dnsmasq.conf.tpl", "/etc/dnsmasq.conf")
    shutil.copy("templates/nginx_default_site.tpl", "/etc/nginx/sites-available/default")
    shutil.copy("templates/falcongate.service.tpl", "/etc/systemd/system/falcongate.service")
    shutil.copy("templates/dhcpcd.conf.tpl", "/etc/dhcpcd.conf")
    shutil.copy("templates/sysctl.conf.tpl", "/etc/sysctl.conf")

    # Creating domain block file for dnsmasq
    run_command("touch /etc/dnsmasq.block")

    run_command("chown www-data:www-data ../../html/user_config.ini")
    run_command("chown www-data:www-data ../../html/pwd.db")

    # Installing Python libraries
    print "Installing Python dependencies..."
    run_command("pip install --upgrade pip")
    run_command("pip install setuptools")
    run_command("pip install -r requirements.txt")

    # Configure the system time according to IP geographical location
    run_command("pip install -U tzupdate")
    run_command("tzupdate")

    # Configuring falcongate service
    print "Configuring falcongate service..."
    run_command("systemctl enable falcongate.service")

    # Installing FW scripts
    print "Installing and configuring FW scripts..."
    shutil.copy("fw/firewall", "/etc/network/if-pre-up.d/firewall")
    run_command("chmod +x /etc/network/if-pre-up.d/firewall")
    shutil.copy("fw/firewall-down", "/etc/network/if-down.d/firewall-down")
    run_command("chmod +x /etc/network/if-down.d/firewall-down")

    # Enabling IP forwarding
    run_command("echo 1 > /proc/sys/net/ipv4/ip_forward")

    # Loading default FW rules
    run_command("iptables-restore < fw/iptables.rules")

    # Configuring default DNS server for FalconGate
    run_command("echo \"nameserver 127.0.2.1\" > /etc/resolv.conf")

    # Restarting device
    print "Installation finished!\n" \
          "Disable your router's DHCP function and reboot the FalconGate server to start protecting your network.\n" \
          "Have a good day!"


if __name__ == '__main__':
    main()
