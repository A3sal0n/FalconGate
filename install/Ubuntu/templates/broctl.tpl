#! /bin/sh
# /etc/init.d/broctl
#

# Some things that run always
touch /var/lock/broctl

# Carry out specific functions when asked to by the system
case "$1" in
  start)
    echo "Starting Bro service "
    nohup /usr/local/bro/bin/broctl start > /dev/null
    ;;
  stop)
    echo "Stopping Bro service"
    nohup /usr/local/bro/bin/broctl stop > /dev/null
    ;;
   restart)
    echo "Restarting Bro service"
    nohup /usr/local/bro/bin/broctl restart > /dev/null
    ;;
  *)
    echo "Usage: /etc/init.d/blah {start|stop|restart}"
    exit 1
    ;;
esac

exit 0