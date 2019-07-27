#!/bin/bash

# Find default gateway
GATE=$(ip route | gawk 'match($0, /default\s+via\s+(.+)\s+dev\s+enp0s3/, a) {print a[1]}')
BASE=$(echo $GATE | gawk 'match($0, /([0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+/, a) {print a[1]}')

# Edit the variables below to reflect your own configuration
# Inbound interface
IFACE0="enp0s3"
IP0="$BASE.2"
# Outbound interface
IFACE1="enp0s8"
IP1="$BASE.3"
GATEWAY=$GATE
NETMASK="255.255.255.0"
# DHCP range
DHCPSTART="$BASE.100"
DHCPEND="$BASE.200"

if [ "$(whoami)" != "root" ]; then
	echo "Sorry, you are not root."
	exit 1
fi

echo "Updating system software..."
sleep 3

add-apt-repository ppa:shevchuk/dnscrypt-proxy

apt-get update && apt-get upgrade -y

echo "Installing software dependencies..."
sleep 3

apt-get install cmake make gcc g++ flex bison libpcap-dev libssl-dev libffi-dev python-dev swig zlib1g-dev libgeoip-dev build-essential libelf-dev dnsmasq nginx php-fpm php-curl exim4-daemon-light mailutils ipset git python3-pip python3-venv dnscrypt-proxy nmap hydra -y

cd /opt

echo "Cloning Falcongate repository..."
sleep 3

git clone https://github.com/A3sal0n/FalconGate.git

cd FalconGate/

git pull --all && git checkout dev

cd ../

echo "Creating Python3 virtual environment and installing dependencies..."
sleep 3

python3 -m venv fg

source fg/bin/activate

pip3 install -r FalconGate/install/Ubuntu/Python/requirements.txt

pip3 install -U tzupdate

tzupdate

deactivate

echo "Installing PF_RING from source..."
sleep 3

git clone https://github.com/ntop/PF_RING.git

cd PF_RING/kernel

make

insmod ./pf_ring.ko

cd ../userland

make

cd lib/

./configure --prefix=/opt/PF_RING

make install

cd ../libpcap

./configure --prefix=/opt/PF_RING/

make install

cd ../tcpdump-*

./configure --prefix=/opt/PF_RING/

make install

cd ../../kernel

make

make install

echo "pf_ring" >> /etc/modules

echo "Installing Zeek from source..."
sleep 3

cd /tmp

git clone --recursive https://github.com/zeek/zeek

cd zeek/

echo "Configuring and building Zeek..."
echo "Sit back and relax because this can take some time :)"
sleep 5

./configure --with-pcap=/opt/PF_RING --prefix=/opt/zeek/

make -j2

make install

echo "$PATH:/opt/zeek/bin" >/etc/environment

export PATH=/opt/zeek/bin:$PATH

echo "Copying configuration files..."
sleep 2

cd /opt

cp FalconGate/install/Ubuntu/templates/broctl.tpl /etc/init.d/broctl
cp FalconGate/install/Ubuntu/templates/local.bro.tpl /opt/zeek/share/zeek/site/local.zeek
sed -e "s/IFACE0/$IFACE0/g" FalconGate/install/Ubuntu/templates/node.cfg.tpl > /opt/zeek/etc/node.cfg
sed -e "s/IFACE0/$IFACE0/g" FalconGate/install/Ubuntu/templates/config.ini.tpl > FalconGate/config.ini
cp FalconGate/install/Ubuntu/templates/user_config.ini.tpl FalconGate/html/user_config.ini
cp FalconGate/install/Ubuntu/templates/pwd.db.tpl FalconGate/html/pwd.db
sed -e "s/IFACE0/$IFACE0/g" -e "s/IP0/$IP0/g" -e "s/IFACE1/$IFACE1/g"  -e "s/IP1/$IP1/g" -e "s/GATEWAY/$GATEWAY/g" FalconGate/install/Ubuntu/templates/50-cloud-init.yaml.tpl > /etc/netplan/50-cloud-init.yaml
cp FalconGate/install/Ubuntu/templates/update-exim4.conf.tpl /etc/exim4/update-exim4.conf
sed -e "s/IFACE0/$IFACE0/g" -e "s/IP0/$IP0/g" -e "s/DHCPSTART/$DHCPSTART/g" -e "s/DHCPEND/$DHCPEND/g" FalconGate/install/Ubuntu/templates/dnsmasq.conf.tpl > /etc/dnsmasq.conf
cp FalconGate/install/Ubuntu/templates/nginx_default_site.tpl /etc/nginx/conf.d/falcongate.conf
cp FalconGate/install/Ubuntu/templates/falcongate.service.tpl /etc/systemd/system/falcongate.service
sed -e "s/IFACE0/$IFACE0/g" -e "s/IP0/$IP0/g" -e "s/GATEWAY/$GATEWAY/g" FalconGate/install/Ubuntu/templates/dhcpcd.conf.tpl > /etc/dhcpcd.conf
cp FalconGate/install/Ubuntu/templates/sysctl.conf.tpl /etc/sysctl.conf
cp FalconGate/install/Ubuntu/fw/firewall /etc/network/if-pre-up.d/firewall
cp FalconGate/install/Ubuntu/fw/firewall-down /etc/network/if-down.d/firewall-down
sed -e "s/IFACE0/$IFACE0/g" -e "s/IP0/$IP0/g" -e "s/GATEWAY/$GATEWAY/g" FalconGate/install/Ubuntu/templates/dhcpcd.conf.tpl > /etc/dhcpcd.conf

# Additional Zeek configuration
chmod +x /etc/init.d/broctl
update-

rc.d broctl defaults

mkdir /opt/zeek/share/zeek/policy/FalconGate
cp -R FalconGate/common/zeek/rules/* /opt/zeek/share/zeek/policy/FalconGate/
/opt/zeek/bin/zeekctl install


# Additional firewall and ipset configuration
echo 1 > /proc/sys/net/ipv4/ip_forward
ipset create blacklist hash:ip maxelem 500000
ipset create blacklist-user hash:ip
/sbin/ipset save > /etc/ipset.rules
echo "# Falcongate Cron jobs" >> /etc/crontab
echo "@reboot root /sbin/ipset restore -! < /etc/ipset.rules" >> /etc/crontab
echo "*/5 * * * * root /sbin/ipset save > /etc/ipset.rules" >> /etc/crontab
iptables-restore < FalconGate/install/Ubuntu/fw/iptables.rules
apt-get install iptables-persistent

# Disable systemd-resolve
systemctl disable systemd-resolved.service
systemctl stop systemd-resolved
ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
echo "127.0.0.1	falcongate" >> /etc/hosts
echo "127.0.1.1	falcongate" >> /etc/hosts

# Other
touch /etc/dnsmasq.block
chown www-data:www-data FalconGate/html/user_config.ini
chown www-data:www-data FalconGate/html/pwd.db
systemctl enable falcongate.service

echo "All tasks finished!"
echo "Restart your system to enable the changes"
echo "After restart you can connect to your Falcongate system using the command below:"
echo "ssh ubuntu@$BASE.2"