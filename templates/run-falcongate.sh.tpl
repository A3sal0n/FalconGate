#!/bin/sh
# falcongate launch script

cd $FALCONGATEDIR$

while true; do
    nohup /usr/bin/python falcongate.py > /dev/null
    sleep 5
done &
