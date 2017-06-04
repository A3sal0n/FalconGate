from ConfigParser import SafeConfigParser
import threading
import os
import time
import lib.utils as utils
import netifaces
from lib.logger import *


class CheckConfigFileModification(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self._cached_stamp_core = 0
        self._cached_stamp_user = 0
        self.core_conf_file = 'config.ini'
        self.user_conf_file = 'html/user_config.ini'

    def run(self):
        global homenet
        global lock

        counter = 0
        while 1:
            flag = False
            stamp = os.stat(self.core_conf_file).st_mtime
            if stamp != self._cached_stamp_core:
                flag = True
                self._cached_stamp_core = stamp
                # Reading core configuration file
                core_config = SafeConfigParser()
                core_config.read('config.ini')

                # main section
                with lock:
                    homenet.interface = core_config.get('main', 'iface')
                    homenet.fg_api_ip_blacklist = core_config.get('api_urls', 'fg_api_ip_blacklist').strip('"')
                    homenet.fg_api_domain_blacklist = core_config.get('api_urls', 'fg_api_domain_blacklist').strip('"')
                    homenet.vt_api_domain_url = core_config.get('api_urls', 'vt_api_domain_url').strip('"')
                    homenet.vt_api_ip_url = core_config.get('api_urls', 'vt_api_ip_url').strip('"')
                    homenet.vt_api_file_url = core_config.get('api_urls', 'vt_api_file_url').strip('"')
                    homenet.hibp_api_url = core_config.get('api_urls', 'hibp_api_url').strip('"')

                    for option in core_config.options('blacklists_ip'):
                        homenet.blacklist_sources_ip[option.capitalize()] = core_config.get('blacklists_ip', option).strip('"').split(',')

                    for option in core_config.options('blacklists_domain'):
                        homenet.blacklist_sources_domain[option.capitalize()] = core_config.get('blacklists_domain', option).strip('"').split(',')

            stamp = os.stat(self.user_conf_file).st_mtime
            if stamp != self._cached_stamp_user:
                flag = True
                self._cached_stamp_user = stamp
                # Reading user configuration file
                user_config = SafeConfigParser()
                user_config.read('html/user_config.ini')

                # main section
                homenet.dst_emails = (user_config.get('main', 'dst_emails').translate(None, '"\n\r ')).strip('"').split(",")
                homenet.email_watchlist = (user_config.get('main', 'email_watchlist').translate(None, '"\n\r ')).strip('"').split(",")
                homenet.fg_intel_key = user_config.get('main', 'fg_intel_key').translate(None, '"\n\r ').strip('"')
                homenet.vt_api_key = user_config.get('main', 'vt_api_key').translate(None, '"\n\r ').strip('"')
                homenet.blacklist = (user_config.get('main', 'blacklist').translate(None, '"\n\r ')).strip('"').split(",")
                homenet.whitelist = (user_config.get('main', 'whitelist').translate(None, '"\n\r ')).strip('"').split(",")
                homenet.mailer_mode = user_config.get('main', 'mailer_mode').translate(None, '"\n\r ').strip('"')
                homenet.mailer_address = user_config.get('main', 'mailer_address').translate(None, '"\n\r ').strip('"')
                homenet.mailer_pwd = user_config.get('main', 'mailer_pwd').translate(None, '"\n\r ').strip('"')

            if flag:
                counter += 1

            if counter > 1:
                utils.kill_falcongate(homenet.pid)

            time.sleep(5)


class CheckNetworkModifications(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID

    def run(self):
        global homenet
        global lock

        while 1:
            gws = netifaces.gateways()
            cgw = gws['default'][netifaces.AF_INET][0]
            if not homenet.gateway:
                homenet.gateway = cgw
            else:
                if homenet.gateway != cgw:
                    utils.reconfigure_network(homenet.gateway, cgw)
                    homenet.gateway = cgw
                    try:
                        with lock:
                            utils.save_pkl_object(homenet, "homenet.pkl")
                    except Exception as e:
                        log.debug('FG-ERROR ' + str(e.__doc__) + " - " + str(e.message))
                    utils.reboot_appliance()
                else:
                    pass
            time.sleep(10)
