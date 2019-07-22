#! /bin/sh
# /etc/init.d/broctl
#

# Some things that run always
touch /var/lock/broctl

# Carry out specific functions when asked to by the system
case "$1" in
  start)
    echo "Starting Bro service "
    nohup /opt/zeek/bin/zeekctl start > /dev/null
    ;;
  stop)
    echo "Stopping Bro service"
    nohup /opt/zeek/bin/zeekctl stop > /dev/null
    ;;
   restart)
    echo "Restarting Bro service"
    nohup /opt/zeek/bin/zeekctl restart > /dev/null
    ;;
  *)
    echo "Usage: /etc/init.d/broctl {start|stop|restart}"
    exit 1
    ;;
esac

exit 0