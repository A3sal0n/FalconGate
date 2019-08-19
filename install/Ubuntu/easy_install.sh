#!/bin/bash

# Helper functions
verifyFreeDiskSpace() {
    # 10GB is the minimum space needed to install and run Falcongate
    local str="Disk space check"
    # Required space in KB
    local required_free_kilobytes=5242880
    # Calculate existing free space on this machine
    local existing_free_kilobytes
    existing_free_kilobytes=$(df -Pk | grep -m1 '\/$' | awk '{print $4}')

    # If the existing space is not an integer,
    if ! [[ "${existing_free_kilobytes}" =~ ^([0-9])+$ ]]; then
        # show an error that we can't determine the free space
        printf "  %b %s\\n" "${CROSS}" "${str}"
        printf "  %b Unknown free disk space! \\n" "${INFO}"
        printf "      We were unable to determine available free disk space on this system.\\n"
        printf "      You may override this check, however, it is not recommended.\\n"
        printf "      The option '%b--i_do_not_follow_recommendations%b' can override this.\\n" "${COL_LIGHT_RED}" "${COL_NC}"
        # exit with an error code
        exit 1
    # If there is insufficient free disk space,
    elif [[ "${existing_free_kilobytes}" -lt "${required_free_kilobytes}" ]]; then
        # show an error message
        printf "  %b %s\\n" "${CROSS}" "${str}"
        printf "  %b Your system disk appears to only have %s KB free\\n" "${INFO}" "${existing_free_kilobytes}"
        printf "      It is recommended to have a minimum of %s KB to install Falcongate\\n" "${required_free_kilobytes}"
        # Show there is not enough free space
        printf "\\n      %bInsufficient free space, exiting...%b\\n" "${COL_LIGHT_RED}" "${COL_NC}"
        # and exit with an error
        exit 1
    # Otherwise,
    else
        # Show that we're running a disk space check
        printf "  %b %s\\n" "${TICK}" "${str}"
    fi
}

select_deployment_mode() {
  MODE=""
  HEIGHT=15
  WIDTH=40
  CHOICE_HEIGHT=4
  BACKTITLE="Falcongate"
  TITLE="Deployment mode"
  MENU="Choose one of the following options:"

  OPTIONS=(1 "Attached"
           2 "Router")

  CHOICE=$(dialog --clear \
                  --backtitle "$BACKTITLE" \
                  --title "$TITLE" \
                  --menu "$MENU" \
                  $HEIGHT $WIDTH $CHOICE_HEIGHT \
                  "${OPTIONS[@]}" \
                  2>&1 >/dev/tty)

  case $CHOICE in
            1)
                deploymentMode="attached"
                ;;
            2)
                deploymentMode="router"
                ;;
  esac

}


chooseInterface() {
    declare -a availableInterfaces
    interfaces=$(ip --oneline link show up | grep -v "lo" | awk '{print $2}' | cut -d':' -f1 | cut -d'@' -f1)
    availableInterfaces=($interfaces)
    # Exit if there are less than 2 interfaces
    if [[ "${#availableInterfaces[@]}" -lt 2 ]]; then
        # Exit with error because there are no enough interfaces
        printf "Your device has less than 2 interfaces\\n"
        printf "Falcongate requires at least 2 interfaces active in the system.\\n"
        exit 1
    fi

    BACKTITLE="Falcongate"
    TITLE="Select interfaces for deployment"
    declare -a interfaceOptions
    for ((i = 0 ; i < ${#availableInterfaces[@]} ; i++)); do
      interfaceOptions+=("${availableInterfaces[$i]}" $((i + 1)) "OFF");
      done
    echo "${interfaceOptions[@]}"
    options=$(dialog --backtitle "$BACKTITLE" --title "$TITLE" --checklist --output-fd 1 "Choose options:" 10 60 4 "${interfaceOptions[@]}")

    clear

    optionsArray=($options)
    if [[ "${#optionsArray[@]}" -lt 2 ]]; then
      # Exit with error because there are no enough interfaces
      printf "Your selected less than 2 interfaces\\n"
      printf "Falcongate requires at least 2 interfaces for the installation.\\n"
      exit 1
    fi
}

installRequirements() {
  echo "Updating system software..."
  sleep 3

  add-apt-repository ppa:shevchuk/dnscrypt-proxy

  apt-get update && apt-get upgrade -y

  echo "Installing software dependencies..."
  sleep 3

  apt-get install cmake make gcc g++ flex bison libpcap-dev libssl-dev libffi-dev dialog python-dev swig zlib1g-dev libgeoip-dev build-essential libelf-dev dnsmasq nginx php-fpm php-curl ipset git python3-pip python3-venv dnscrypt-proxy nmap hydra -y
}


# MAIN
# Exit if any error is detected
set -e

# Check if script is running with root privs
if [ "$(whoami)" != "root" ]; then
	echo "Sorry, you are not root."
	exit 1
fi

# Check available disk space
verifyFreeDiskSpace

# Global variables
IFACE0=""
IFACE1=""
IP0=""
IP1=""
DHCPSTART=""
DHCPEND=""

# Update system software and install required packages
#installRequirements

# Allow user to choose deployment mode
select_deployment_mode

# Allow the user to choose the network interfaces for Falcongate
chooseInterface

IFACE0=${optionsArray[0]}
IFACE1=${optionsArray[1]}

# shellcheck disable=SC2170
if [ "$deploymentMode" == "attached" ]; then
  # Find default gateway
  GATE=$(ip route | awk 'match($0, /default\s+via\s+(.+)\s+dev\s+'"$IFACE0"'/, a) {print a[1]}')
  BASE=$(echo $GATE | awk 'match($0, /([0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+/, a) {print a[1]}')
  # IP address for IFACE0
  IP0="$BASE.2"
  # IP address for IFACE1
  IP1="$BASE.3"
  # Gateway
  GATEWAY=$GATE
  # Network mask
  NETMASK="255.255.255.0"
  # DHCP range
  DHCPSTART="$BASE.100"
  DHCPEND="$BASE.200"
else
  # IP address for IFACE0
  IP0="192.168.100.1"
  # DHCP range
  DHCPSTART="192.168.100.100"
  DHCPEND="192.168.100.200"
fi

echo "$deploymentMode"
echo $IP0 $IP1 $GATEWAY $NETMASK $DHCPSTART $DHCPEND


cd /opt

echo "Cloning Falcongate repository..."
sleep 3

git clone https://github.com/A3sal0n/FalconGate.git

cd FalconGate/

chmod +x falcongate.py

ln -s /opt/FalconGate/falcongate.py /sbin/falcongate

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

cp FalconGate/install/Ubuntu/templates/zeek.service.tpl /etc/systemd/system/zeek.service
cp FalconGate/install/Ubuntu/templates/local.bro.tpl /opt/zeek/share/zeek/site/local.zeek
sed -e "s/IFACE0/$IFACE0/g" FalconGate/install/Ubuntu/templates/node.cfg.tpl > /opt/zeek/etc/node.cfg
sed -e "s/IFACE0/$IFACE0/g" FalconGate/install/Ubuntu/templates/config.ini.tpl > FalconGate/config.ini
cp FalconGate/install/Ubuntu/templates/user_config.ini.tpl FalconGate/html/user_config.ini
cp FalconGate/install/Ubuntu/templates/pwd.db.tpl FalconGate/html/pwd.db
if [ "$deploymentMode" == "attached" ]; then
  sed -e "s/IFACE0/$IFACE0/g" -e "s/IP0/$IP0/g" -e "s/IFACE1/$IFACE1/g"  -e "s/IP1/$IP1/g" -e "s/GATEWAY/$GATEWAY/g" FalconGate/install/Ubuntu/templates/50-cloud-init.yaml.tpl > /etc/netplan/50-cloud-init.yaml
else
  sed -e "s/IFACE0/$IFACE0/g" -e "s/IP0/$IP0/g" -e "s/IFACE1/$IFACE1/g" FalconGate/install/Ubuntu/templates/50-cloud-init.yaml.router.tpl > /etc/netplan/50-cloud-init.yaml
fi
cp FalconGate/install/Ubuntu/templates/update-exim4.conf.tpl /etc/exim4/update-exim4.conf
sed -e "s/IFACE0/$IFACE0/g" -e "s/IP0/$IP0/g" -e "s/DHCPSTART/$DHCPSTART/g" -e "s/DHCPEND/$DHCPEND/g" FalconGate/install/Ubuntu/templates/dnsmasq.conf.tpl > /etc/dnsmasq.conf
cp FalconGate/install/Ubuntu/templates/nginx_default_site.tpl /etc/nginx/conf.d/falcongate.conf
cp FalconGate/install/Ubuntu/templates/falcongate.service.tpl /etc/systemd/system/falcongate.service
sed -e "s/IFACE0/$IFACE0/g" -e "s/IP0/$IP0/g" FalconGate/install/Ubuntu/templates/dhcpcd.conf.tpl > /etc/dhcpcd.conf
cp FalconGate/install/Ubuntu/templates/sysctl.conf.tpl /etc/sysctl.conf
cp FalconGate/install/Ubuntu/templates/dnscrypt-proxy.toml.tpl /etc/dnscrypt-proxy/dnscrypt-proxy.toml

# Additional Zeek configuration
mkdir /opt/zeek/share/zeek/policy/FalconGate
cp -R FalconGate/common/zeek/rules/* /opt/zeek/share/zeek/policy/FalconGate/
/opt/zeek/bin/zeekctl install
systemctl daemon-reload
systemctl enable zeek.service

# Additional firewall and ipset configuration
echo 1 > /proc/sys/net/ipv4/ip_forward
ipset create blacklist hash:ip maxelem 500000
ipset create blacklist-user hash:ip
/sbin/ipset save > /etc/ipset.rules
echo "# Falcongate Cron jobs" >> /etc/crontab
echo "@reboot root sleep 30 && systemctl restart netfilter-persistent.service" >> /etc/crontab
echo "@reboot root /sbin/ipset restore -! < /etc/ipset.rules" >> /etc/crontab
echo "*/5 * * * * root /sbin/ipset save > /etc/ipset.rules" >> /etc/crontab
iptables-restore < FalconGate/install/Ubuntu/fw/iptables.rules
apt-get install iptables-persistent netfilter-persistent -y

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
echo "ssh ubuntu@$IP0"

exit
