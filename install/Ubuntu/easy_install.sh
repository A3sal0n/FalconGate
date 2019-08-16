#!/bin/bash

set -e

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
            echo "You chose Option 1"
            ;;
        2)
            echo "You chose Option 2"
            ;;
esac

exit