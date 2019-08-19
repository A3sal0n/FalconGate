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

  clear
  case $CHOICE in
            1)
                MODE="attached"
                ;;
            2)
                MODE="router"
                ;;
  esac
}


get_available_interfaces() {
  # There may be more than one so it's all stored in a variable
  declare -a availableInterfaces
  global availableInterfaces
  interfaces=$(ip --oneline link show up | grep -v "lo" | awk '{print $2}' | cut -d':' -f1 | cut -d'@' -f1)
  availableInterfaces=($interfaces)
  echo "${#availableInterfaces[@]}"
}


chooseInterface() {
    # Exit if there are less than 2 interfaces
    echo "${#availableInterfaces[@]}"
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
      interfaceOptions+="${availableInterfaces[$i]} $i OFF";
      done
    options=$(dialog --backtitle "$BACKTITLE" --title "$TITLE" --checklist --output-fd 1 "Choose options:" 10 60 4 "${interfaceOptions[@]}")

    clear
    echo "${options[@]}"
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


# Update system software and install required packages
#installRequirements

# Allow user to choose deployment mode
select_deployment_mode

# Get active network interfaces
get_available_interfaces

# Allow the user to choose the network interfaces for Falcongate
chooseInterface

#if [[ $MODE == 'attached' ]]; then


exit
