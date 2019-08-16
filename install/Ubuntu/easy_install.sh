#!/bin/bash

set -e

# Check if script has root privs
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

apt-get install cmake make gcc g++ flex bison libpcap-dev libssl-dev libffi-dev dialog python-dev swig zlib1g-dev libgeoip-dev build-essential libelf-dev dnsmasq nginx php-fpm php-curl mailutils ipset git python3-pip python3-venv dnscrypt-proxy nmap hydra -y

# Allow user to choose deployment mode
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

clear
case $CHOICE in
        1)
            MODE="attached"
            ;;
        2)
            MODE="router"
            ;;
esac

echo $MODE

exit