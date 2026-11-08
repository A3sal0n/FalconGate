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
    # List all non-loopback interfaces, including those administratively DOWN
    # (e.g. a second NIC with no config yet); the installer brings them up later.
    interfaces=$(ip --oneline link show | grep -v "link/loopback" | awk -F': ' '{print $2}' | cut -d'@' -f1)
    availableInterfaces=($interfaces)
    # Exit if there are less than 2 interfaces
    if [[ "${#availableInterfaces[@]}" -lt 2 ]]; then
        # Exit with error because there are no enough interfaces
        printf "Your device has less than 2 interfaces\\n"
        printf "Falcongate requires at least 2 network interfaces in the system.\\n"
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

# Decide which of the selected interfaces is the Internet uplink (WAN).
# The WAN interface is the one that currently has Internet access. The name of
# that interface is printed on stdout; nothing is printed (and a non-zero status
# is returned) when none of the candidates can reach the Internet.
detectWanInterface() {
    local iface
    for iface in "$@"; do
        # An interface without an IPv4 address cannot reach anything yet.
        if ! ip -4 addr show dev "$iface" 2>/dev/null | grep -q 'inet '; then
            continue
        fi
        # Treat the interface as WAN if it can reach a well-known public host
        # through that specific interface.
        if ping -I "$iface" -c 1 -W 2 1.1.1.1 >/dev/null 2>&1 \
           || ping -I "$iface" -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
            printf '%s' "$iface"
            return 0
        fi
    done
    return 1
}

# Fallback used only when auto-detection cannot tell which interface is the WAN.
# Lets the user pick the Internet-facing interface from the two they selected.
selectWanInterface() {
    local a="$1" b="$2" choice
    choice=$(dialog --clear --backtitle "Falcongate" \
                    --title "Select the WAN (Internet) interface" \
                    --menu "Auto-detection could not determine which interface has Internet access.\nChoose the interface connected to the Internet/uplink:" \
                    15 60 2 \
                    "$a" "Internet uplink" \
                    "$b" "Internet uplink" \
                    2>&1 >/dev/tty)
    clear
    printf '%s' "$choice"
}

# Prints why an address can't be the LAN address, or nothing if it can. The network
# templates use a /24 network, and its DHCP pool is .100 to .200 (see the MAIN section).
#   $1 the address   $2 deployment mode
#   $3 attached mode: the existing network's gateway
#   $4 router mode: the WAN interface's current address as a.b.c.d/prefix, if it has one
lanAddressProblem() {
    local ip="$1" mode="$2" gateway="$3" wan="$4"
    local octet='(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])'
    local a b c d

    if ! [[ "$ip" =~ ^$octet\.$octet\.$octet\.$octet$ ]]; then
        echo "'$ip' is not a valid IPv4 address."
        return 0
    fi
    IFS=. read -r a b c d <<< "$ip"

    # Zeek only treats private networks as local, and the detection logic depends on that.
    if ! { [ "$a" -eq 10 ] || { [ "$a" -eq 172 ] && [ "$b" -ge 16 ] && [ "$b" -le 31 ]; } \
           || { [ "$a" -eq 192 ] && [ "$b" -eq 168 ]; }; }; then
        echo "$ip is not a private address (10.x.x.x, 172.16-31.x.x or 192.168.x.x)."
    elif [ "$d" -eq 0 ] || [ "$d" -eq 255 ]; then
        echo "$ip is the network or broadcast address of its /24 network."
    elif [ "$d" -ge 100 ] && [ "$d" -le 200 ]; then
        echo "$ip is inside the DHCP pool (.100 to .200). Choose a last number outside it."
    elif [ "$mode" == "attached" ]; then
        if [ "${ip%.*}" != "${gateway%.*}" ]; then
            echo "$ip is not on the existing network (${gateway%.*}.0/24)."
        elif [ "$ip" == "$gateway" ]; then
            echo "$ip is the address of the existing gateway."
        elif [ "$d" -eq 3 ]; then
            echo "$ip is reserved for the WAN interface in attached mode."
        fi
    elif [ -n "$wan" ]; then
        local e f g h prefix mask
        IFS=./ read -r e f g h prefix <<< "$wan"
        # The two networks overlap if they match at the shorter of their prefixes.
        [ "$prefix" -gt 24 ] && prefix=24
        mask=$(( prefix == 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
        if [ $(( ((a << 24) + (b << 16) + (c << 8)) & mask )) -eq $(( ((e << 24) + (f << 16) + (g << 8) + h) & mask )) ]; then
            echo "$ip is on the same network as the WAN interface ($wan). Choose a different network."
        fi
    fi
    return 0
}

# Asks for the LAN address until it gets a usable one, and stores it in IP0.
#   $1 the suggested address, and then the arguments of lanAddressProblem from $2 on
selectLanAddress() {
    local choice="$1" mode="$2" gateway="$3" wan="$4" problem
    local prompt="Enter an unused static IP address for the LAN interface ($IFACE0).\n\nIt will use a /24 network, and the DHCP server will give devices addresses from .100 to .200 of that network."
    local message="$prompt"

    while true; do
        if ! choice=$(dialog --clear --backtitle "Falcongate" \
                             --title "LAN IP address" \
                             --inputbox "$message" 15 60 "$choice" \
                             2>&1 >/dev/tty); then
            clear
            echo "Installation cancelled: no LAN IP address was chosen." >&2
            exit 1
        fi
        choice="${choice//[[:space:]]/}"
        problem=$(lanAddressProblem "$choice" "$mode" "$gateway" "$wan")
        if [ -z "$problem" ]; then
            break
        fi
        message="$problem\n\n$prompt"
    done
    clear
    IP0="$choice"
}

installRequirements() {
  echo "Updating system software..."
  sleep 3

  apt-get update && apt-get upgrade -y

  echo "Installing software dependencies..."
  sleep 3

  apt-get install -y make gcc g++ openssl libssl-dev libffi-dev dialog zlib1g-dev libgeoip-dev build-essential dnsmasq nginx php-fpm php-curl ipset iptables git dnscrypt-proxy nmap hydra curl ca-certificates gnupg libbz2-dev libexpat1-dev libgdbm-dev liblzma-dev libncursesw5-dev libreadline-dev libsqlite3-dev tk-dev uuid-dev python3 ifupdown rsyslog
}

installPython() {
  local python_version="3.15.0"
  local python_prefix="/opt/python/${python_version}"
  local archive="/tmp/Python-${python_version}.tar.xz"
  local source_dir="/tmp/Python-${python_version}"
  local expected_sha256="ba4bed1ba346b916890b76d9e320451420aa69f6408997d33c66482eeae3d575"

  if [ ! -x "${python_prefix}/bin/python3.15" ]; then
    echo "Downloading CPython ${python_version} source..."
    curl -fsSL "https://www.python.org/ftp/python/${python_version}/Python-${python_version}.tar.xz" -o "${archive}"
    if ! printf '%s  %s\n' "${expected_sha256}" "${archive}" | sha256sum --check --status; then
      echo "CPython source archive checksum verification failed." >&2
      exit 1
    fi

    tar -xJf "${archive}" -C /tmp
    cd "${source_dir}"
    ./configure --prefix="${python_prefix}" --with-ensurepip=install
    make -j2
    make altinstall
    cd /opt
    rm -f "${archive}"
  fi

  PYTHON_BIN="${python_prefix}/bin/python3.15"
  "${PYTHON_BIN}" --version
}


# MAIN
# Exit if any error is detected
set -e

# Zeek package to install. The X.0 packages track an LTS series and receive its
# patch releases through apt; change series deliberately after testing.
ZEEK_PACKAGE="zeek-8.0"   # https://docs.zeek.org/en/lts/install.html

# Check if script is running with root privs
if [ "$(whoami)" != "root" ]; then
	echo "Sorry, you are not root."
	exit 1
fi

if [ ! -r /etc/os-release ]; then
  echo "Cannot determine the operating system version." >&2
  exit 1
fi

. /etc/os-release
if [ "${ID:-}" != "debian" ] || [ "${VERSION_ID:-}" != "13" ]; then
  echo "This installer targets Debian 13 (trixie) only." >&2
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
installRequirements
installPython

# Allow user to choose deployment mode
select_deployment_mode

# Allow the user to choose the network interfaces for Falcongate
chooseInterface

# The user selected two interfaces. Automatically assign their roles: the
# interface that currently has Internet access becomes the WAN (IFACE1, the
# uplink that gets NAT/MASQUERADE) and the other one becomes the LAN (IFACE0,
# which receives the static IP and runs the DHCP server for the clients).
SELECTED0=${optionsArray[0]}
SELECTED1=${optionsArray[1]}

WAN_IFACE=$(detectWanInterface "$SELECTED0" "$SELECTED1") || WAN_IFACE=""

if [ -z "$WAN_IFACE" ]; then
  echo "Could not automatically detect which interface has Internet access."
  WAN_IFACE=$(selectWanInterface "$SELECTED0" "$SELECTED1")
fi

if [ -z "$WAN_IFACE" ]; then
  echo "No WAN interface selected; defaulting to $SELECTED1 as the WAN interface." >&2
  WAN_IFACE="$SELECTED1"
fi

if [ "$WAN_IFACE" == "$SELECTED0" ]; then
  IFACE1="$SELECTED0"   # WAN (Internet uplink)
  IFACE0="$SELECTED1"   # LAN (static IP + DHCP server)
else
  IFACE1="$SELECTED1"   # WAN (Internet uplink)
  IFACE0="$SELECTED0"   # LAN (static IP + DHCP server)
fi

echo "WAN (Internet) interface: $IFACE1"
echo "LAN interface:            $IFACE0"
sleep 2

# shellcheck disable=SC2170
if [ "$deploymentMode" == "attached" ]; then
  # Find the default gateway reachable through the WAN interface
  GATE=$(ip route | awk 'match($0, /default\s+via\s+(.+)\s+dev\s+'"$IFACE1"'/, a) {print a[1]}')
  BASE=$(echo $GATE | awk 'match($0, /([0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+/, a) {print a[1]}')
  if [ -z "$BASE" ]; then
    echo "Could not find the default gateway on $IFACE1, which attached mode needs." >&2
    exit 1
  fi
  # IP address for IFACE0
  selectLanAddress "$BASE.2" "$deploymentMode" "$GATE" ""
  # IP address for IFACE1
  IP1="$BASE.3"
  # Gateway
  GATEWAY=$GATE
  # Network mask
  NETMASK="255.255.255.0"
else
  # IP address for IFACE0
  selectLanAddress "192.168.100.1" "$deploymentMode" "" "$(ip -4 -o addr show dev "$IFACE1" | awk '{print $4; exit}')"
fi

# DHCP range, on the LAN address's /24 network
DHCPSTART="${IP0%.*}.100"
DHCPEND="${IP0%.*}.200"

echo "Installing Falcongate in $deploymentMode configuration"
sleep 3

cd /opt

# Source of the Falcongate code. Override for development:
#   FG_SOURCE_DIR=/path/to/local/Falcongate  copy a local working tree (incl. uncommitted changes)
#   FG_REPO_URL=<url or path> FG_BRANCH=<branch>  clone a different repo and/or branch
FG_REPO_URL="${FG_REPO_URL:-https://github.com/A3sal0n/FalconGate.git}"
FG_BRANCH="${FG_BRANCH:-}"

if [[ -n "${FG_SOURCE_DIR:-}" ]]; then
  if [[ ! -f "${FG_SOURCE_DIR}/falcongate.py" ]]; then
    printf "FG_SOURCE_DIR (%s) does not look like a Falcongate checkout\\n" "${FG_SOURCE_DIR}"
    exit 1
  fi
  echo "Copying Falcongate from local source ${FG_SOURCE_DIR}..."
  mkdir -p /opt/Falcongate
  cp -a "${FG_SOURCE_DIR}/." /opt/Falcongate/
else
  echo "Cloning Falcongate repository ${FG_REPO_URL} ${FG_BRANCH:+(branch ${FG_BRANCH})}..."
  sleep 3
  git clone ${FG_BRANCH:+--branch "${FG_BRANCH}"} "${FG_REPO_URL}" Falcongate
fi

cd Falcongate/

# Give this machine its own TLS key and certificate for the web console. Always
# generated here, so no key is shared between installs or kept in the repository.
mkdir -p ssl
(umask 077 && openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650   -keyout ssl/nginx.key -out ssl/nginx.crt -subj "/CN=falcongate"   -addext "subjectAltName=DNS:falcongate,IP:${IP0}")

chmod +x falcongate.py

ln -s /opt/Falcongate/falcongate.py /sbin/falcongate

cd ../

echo "Creating Python3 virtual environment and installing dependencies..."
sleep 3

"${PYTHON_BIN}" -m venv --upgrade /opt/fg
/opt/fg/bin/python -m pip install --upgrade pip setuptools
/opt/fg/bin/python -m pip install -r Falcongate/install/Debian/Python/requirements.txt
/opt/fg/bin/python -m pip install --upgrade tzupdate
/opt/fg/bin/tzupdate

echo "Installing Zeek from the Zeek project's package repository..."
sleep 3

# Zeek is not available in the Debian stable repositories, so it comes from the
# repository the Zeek project publishes on the openSUSE Build Service. Its key is
# trusted for this repository only (signed-by). Packet capture uses Zeek's built-in
# AF_PACKET support, which needs no kernel module (see templates/node.cfg.tpl).
ZEEK_REPO_URL="https://download.opensuse.org/repositories/security:/zeek/Debian_${VERSION_ID}"
ZEEK_REPO_KEY="/usr/share/keyrings/security_zeek.gpg"

curl -fsSL "${ZEEK_REPO_URL}/Release.key" -o /tmp/security_zeek.key
gpg --batch --yes --dearmor -o "${ZEEK_REPO_KEY}" /tmp/security_zeek.key
rm -f /tmp/security_zeek.key
echo "deb [signed-by=${ZEEK_REPO_KEY}] ${ZEEK_REPO_URL}/ /" > /etc/apt/sources.list.d/security_zeek.list

apt-get update
apt-get install -y "${ZEEK_PACKAGE}"

echo "$PATH:/opt/zeek/bin" >/etc/environment

export PATH=/opt/zeek/bin:$PATH

echo "Copying configuration files..."
sleep 2

cd /opt

cp Falcongate/install/Debian/templates/zeek.service.tpl /etc/systemd/system/zeek.service
cp Falcongate/install/Debian/templates/local.zeek.tpl /opt/zeek/share/zeek/site/local.zeek
sed -e "s/IFACE0/$IFACE0/g" Falcongate/install/Debian/templates/node.cfg.tpl > /opt/zeek/etc/node.cfg
sed -e "s/IFACE0/$IFACE0/g" Falcongate/install/Debian/templates/config.ini.tpl > Falcongate/config.ini
sed -e "s/IFACE0/$IFACE0/g" -e "s/IFACE1/$IFACE1/g" Falcongate/install/Debian/fw/iptables.rules > /etc/iptables.rules
cp Falcongate/install/Debian/templates/user_config.ini.tpl Falcongate/html/user_config.ini
cp Falcongate/install/Debian/templates/pwd.db.tpl Falcongate/html/pwd.db
# Debian uses ifupdown (/etc/network/interfaces) rather than netplan.
if [ "$deploymentMode" == "attached" ]; then
  sed -e "s/IFACE0/$IFACE0/g" -e "s/IP0/$IP0/g" -e "s/IFACE1/$IFACE1/g" -e "s/IP1/$IP1/g" -e "s/GATEWAY/$GATEWAY/g" Falcongate/install/Debian/templates/interfaces.attached.tpl > /etc/network/interfaces
else
  sed -e "s/IFACE0/$IFACE0/g" -e "s/IP0/$IP0/g" -e "s/IFACE1/$IFACE1/g" Falcongate/install/Debian/templates/interfaces.router.tpl > /etc/network/interfaces
fi
systemctl enable networking.service 2>/dev/null || true

sed -e "s/IFACE0/$IFACE0/g" -e "s/IP0/$IP0/g" -e "s/DHCPSTART/$DHCPSTART/g" -e "s/DHCPEND/$DHCPEND/g" Falcongate/install/Debian/templates/dnsmasq.conf.tpl > /etc/dnsmasq.conf
# Detect the installed PHP-FPM socket instead of hard-coding the PHP version.
PHP_FPM_VERSION="$(ls /etc/php/ 2>/dev/null | sort -V | tail -1)"
PHP_FPM_SOCK="/run/php/php${PHP_FPM_VERSION}-fpm.sock"
echo "Using PHP-FPM socket: ${PHP_FPM_SOCK}"
sed -e "s#PHPFPMSOCK#${PHP_FPM_SOCK}#g" Falcongate/install/Debian/templates/nginx_default_site.tpl > /etc/nginx/conf.d/falcongate.conf
# Remove Debian's default site so Falcongate is served on port 80 as well.
rm -f /etc/nginx/sites-enabled/default
systemctl enable "php${PHP_FPM_VERSION}-fpm" 2>/dev/null || true
cp Falcongate/install/Debian/templates/falcongate.service.tpl /etc/systemd/system/falcongate.service
sed -e "s/IFACE0/$IFACE0/g" -e "s/IP0/$IP0/g" Falcongate/install/Debian/templates/dhcpcd.conf.tpl > /etc/dhcpcd.conf
# Debian 13 no longer reads /etc/sysctl.conf at boot, so these settings need their own file.
cp Falcongate/install/Debian/templates/sysctl.conf.tpl /etc/sysctl.d/90-falcongate.conf
cp Falcongate/install/Debian/templates/dnscrypt-proxy.toml.tpl /etc/dnscrypt-proxy/dnscrypt-proxy.toml

# Additional Zeek configuration
mkdir /opt/zeek/share/zeek/policy/Falcongate
cp -R Falcongate/common/zeek/rules/* /opt/zeek/share/zeek/policy/Falcongate/
cp Falcongate/install/Debian/templates/port-scan.zeek.tpl /opt/zeek/share/zeek/policy/Falcongate/port-scan.zeek
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
iptables-restore < /etc/iptables.rules
apt-get install iptables-persistent netfilter-persistent -y

# Point the appliance's own resolver at dnscrypt-proxy. systemd-resolved is not
# enabled by default on Debian, so disable it only if it happens to be present.
systemctl disable systemd-resolved.service 2>/dev/null || true
systemctl stop systemd-resolved 2>/dev/null || true
rm -f /etc/resolv.conf
echo "nameserver 127.0.2.1" > /etc/resolv.conf
echo "127.0.0.1 falcongate" >> /etc/hosts
echo "127.0.1.1 falcongate" >> /etc/hosts

# Other
touch /etc/dnsmasq.block
chown www-data:www-data Falcongate/html/user_config.ini
chown www-data:www-data Falcongate/html/pwd.db
systemctl enable falcongate.service

echo "All tasks finished!"
echo "Restart your system to enable the changes"
echo "After restart you can connect to your Falcongate system using the command below:"
echo "ssh <your-user>@$IP0"

exit
