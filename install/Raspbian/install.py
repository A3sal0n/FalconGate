#!/usr/bin/env python

import os
import glob
import shutil
import fileinput
import re
from subprocess import Popen, PIPE


def get_default_gateway():
    proc = Popen(['ip', 'route'], stdout=PIPE)
    out, err = proc.communicate()
    lines = out.split("\n")
    flag = False
    for line in lines:
        fields = line.split()
        try:
            if fields[0] == 'default' and len(fields) >= 5:
                gw = fields[2]
                iface = fields[4]
                flag = True
                return (iface, gw)
        except Exception:
            pass
    if not flag:
        print 'It was not possible to detect the default gateway. Try to configure manually your device.'


def run_command(cmd):
    os.system(cmd)


template_list = ["templates/config.ini.tpl", "templates/interfaces.tpl", "templates/broctl.service.tpl", "templates/dnsmasq.conf.tpl",
                 "templates/local.bro.tpl", "templates/nginx_default_site.tpl",
                 "templates/dhcpcd.conf.tpl", "templates/falcongate.service.tpl", "templates/node.cfg.tpl"]


def main():
    if not os.geteuid() == 0:
        exit('Script must be run as root')

    install_dir = os.getcwd()
    os.chdir("../../")
    root_dir = os.getcwd()
    os.chdir(install_dir)

    # Detecting default gateway
    print "Detecting default gateway..."
    (iface0, gw) = get_default_gateway()

    print iface0, gw

    iface1 = iface0 + ':1'

    octects = str(gw).split(".")
    STATIP = octects[0] + "." + octects[1] + "." + octects[2] + ".2"
    dhcpstart = octects[0] + "." + octects[1] + "." + octects[2] + ".4"
    dhcpend = octects[0] + "." + octects[1] + "." + octects[2] + ".254"
    netmask = '255.255.255.0'

    for f in template_list:
        for line in fileinput.input(f, inplace=1):
            line = re.sub("\$FALCONGATEDIR\$", root_dir, line.rstrip())
            line = re.sub("\$IFACE0\$", iface0, line.rstrip())
            line = re.sub("\$IFACE1\$", iface1, line.rstrip())
            line = re.sub("\$STATIP\$", STATIP, line.rstrip())
            line = re.sub("\$NETMASK\$", netmask, line.rstrip())
            line = re.sub("\$GATEWAY\$", gw, line.rstrip())
            line = re.sub("\$DHCPSTART\$", dhcpstart, line.rstrip())
            line = re.sub("\$DHCPEND\$", dhcpend, line.rstrip())
            print(line)

    print "Updating apt sources..."
    run_command("apt-get update")

    # Installing dependencies
    print "Installing dependencies..."
    run_command("aptitude install -y dnsmasq nginx php-fpm php-curl exim4-daemon-light mailutils ipset cmake make gcc "
                "g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev git python-pip build-essential "
                "dnsutils libsodium-dev locate bash-completion libsystemd-dev pkg-config nmap libssh-dev hydra")

    os.chdir("../../tmp")

    # Installing DNSCrypt from Raspbian's test packages
    print "Installing DNSCrypt from source..."
    run_command("wget https://download.dnscrypt.org/dnscrypt-proxy/LATEST.tar.bz2")
    run_command("tar -xf LATEST.tar.bz2")
    files = glob.glob("dnscrypt-proxy*")
    if len(files) == 0:
        print "dnscrypt-proxy folder not found in path!"
        exit()
    os.chdir(files[0])
    run_command("ldconfig")
    run_command("./configure --with-systemd")
    run_command("make")
    run_command("make install")
    run_command("useradd -r -d /var/dnscrypt -m -s /usr/sbin/nologin dnscrypt")
    shutil.copy("../../install/Raspbian/templates/dnscrypt-proxy.service.tpl", "/etc/systemd/system/dnscrypt-proxy.service")
    shutil.copy("../../install/Raspbian/templates/dnscrypt-proxy.socket.tpl", "/etc/systemd/system/dnscrypt-proxy.socket")
    run_command("systemctl enable dnscrypt-proxy.service")

    os.chdir("../")

    # Installing Bro
    print "Installing Bro..."
    print "Cloning Bro repo..."
    run_command("git clone --recursive git://git.bro.org/bro")
    os.chdir("bro")
    print "Configuring Bro..."
    run_command("./configure")
    print "Building Bro..."
    print "Sit back and relax because this can take quite some time :)"
    run_command("make -j2")
    print "Installing Bro..."
    run_command("make install")
    os.chdir(install_dir)
    run_command("rm -rf ../../tmp/bro*")
    print "Configuring broctl service..."
    shutil.copy("templates/broctl.service.tpl", "/etc/systemd/system/broctl.service")
    run_command("systemctl enable broctl.service")
    print "Copying and installing default Bro policies..."
    shutil.copy("templates/local.bro.tpl", "/usr/local/bro/share/bro/site/local.bro")
    shutil.copy("templates/node.cfg.tpl", "/usr/local/bro/etc/node.cfg")
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
