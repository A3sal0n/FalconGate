import random
import string
import socket
import time


def main():
    print 'Starting test...'
    time.sleep(1)
    test_domains = []
    print 'Generating random domains...'
    time.sleep(1)
    # Generating 30 random domains
    for n in range(30):
        domain = ''.join(random.choice(string.ascii_lowercase) for _ in range(15)) + '.com'
        test_domains.append(domain)

    print 'Resolving domains...'
    time.sleep(1)
    # Resolving test domains generated
    for domain in test_domains:
        print domain
        try:
            r = socket.gethostbyname(domain)
        except Exception:
            pass

        time.sleep(0.2)

    print 'Done!'
    print 'Have a nice day!'


if __name__ == '__main__':
    main()