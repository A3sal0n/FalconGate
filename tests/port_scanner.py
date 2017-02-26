import socket
import subprocess
import sys
from datetime import datetime


def main():
    target = 'scanme.nmap.org'
    target_ip = socket.gethostbyname(target)
    try:
        for port in range(1, 100):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                print "Port {}: 	 Open".format(port)
            sock.close()

    except KeyboardInterrupt:
        print "You pressed Ctrl+C"
        sys.exit()

    except socket.gaierror:
        print 'Hostname could not be resolved. Exiting'
        sys.exit()

    except socket.error:
        print "Couldn't connect to server"
        sys.exit()

    print 'Done!'
    print 'Have a nice day!'


if __name__ == '__main__':
    main()
