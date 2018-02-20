#!/usr/bin/env python

from flask import Flask
from flask import request
from flask import abort
from flask import Response
import threading
import json
import lib.utils as utils
from lib.logger import *
from lib.settings import homenet, lock, country_stats

global app

app = Flask(__name__)


class FlaskAPI(threading.Thread):
    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID

    def run(self):
        app.run(host='127.0.0.1', port=5000, threaded=True)

    @staticmethod
    @app.route('/api/v1.0/falcongate/status', methods=['POST'])
    def get_status():
        if not request.json:
            abort(400)

        target = str(request.json['target'])
        try:
            if target == 'devices':
                data = utils.get_active_devices()
                resp = Response()
                resp.data = data
                resp.status_code = 200
                resp.mimetype = "application/json"
                return resp
            elif target == 'network':
                data = utils.get_network_config()
                resp = Response()
                resp.data = data
                resp.status_code = 200
                resp.mimetype = "application/json"
                return resp
            elif target == 'alerts':
                timeframe = str(request.json['timeframe'])
                rev_filter = str(request.json['filter'])
                if rev_filter == "all":
                    handledf = "all"
                elif rev_filter == "reviewed":
                    handledf = "1"
                elif rev_filter == "notreviewed":
                    handledf = "0"
                if timeframe == "alerts_week":
                    data = utils.get_alerts_within_time(604800, handledf)
                elif timeframe == "alerts_month":
                    data = utils.get_alerts_within_time(2592000, handledf)
                elif timeframe == "alerts_all":
                    data = utils.get_alerts_within_time(172800000, handledf)
                resp = Response()
                resp.data = data
                resp.status_code = 200
                resp.mimetype = "application/json"
                return resp
            elif target == 'alerts_review':
                alert_id = str(request.json['alert_id'])
                handled = str(request.json['handled'])
                data = utils.update_alert_handled(alert_id, handled)
                resp = Response()
                resp.data = data
                resp.status_code = 200
                resp.mimetype = "application/json"
                return resp
            elif target == 'logs':
                log_count = int(request.json['log_count'])
                data = utils.get_syslogs(log_count)
                resp = Response()
                resp.data = data
                resp.status_code = 200
                resp.mimetype = "application/json"
                return resp
            else:
                abort(400)
        except Exception as e:
            log.debug('FG-WARN: ' + str(e.__doc__) + " - " + str(e.message))
            resp = Response()
            resp.status_code = 500
            return resp

    @staticmethod
    @app.route('/api/v1.0/falcongate/response/host', methods=['POST'])
    def host_response():
        if not request.json:
            abort(400)

        action = str(request.json['action'])
        target = request.json['target']
        if action == 'blacklist':
            for entry in target:
                if utils.validate_domain(entry):
                    with lock:
                        if (entry not in homenet.user_domain_whitelist) and (entry not in homenet.user_domain_blacklist):
                            homenet.user_domain_blacklist.append(entry)
                            utils.add_domain_blacklist(entry)
                else:
                    utils.flush_ipset_list('blacklist-user')
                    with lock:
                        if (len(entry) >= 7) and (entry not in homenet.user_blacklist) and (entry not in homenet.user_whitelist):
                            homenet.user_blacklist.append(entry)
                            utils.add_ip_ipset_blacklist(entry, 'blacklist-user')

            resp = Response()
            resp.status_code = 200
            return resp
        elif action == 'unblock':
            for entry in target:
                if utils.validate_domain(entry):
                    with lock:
                        utils.del_domain_blacklist(entry)
                else:
                    with lock:
                        if (len(entry) >= 7) and (entry in homenet.user_blacklist):
                            utils.del_ip_ipset_blacklist(entry, 'blacklist-user')
            resp = Response()
            resp.status_code = 200
            return resp
        elif action == 'whitelist':
            for entry in target:
                if utils.validate_domain(entry):
                    with lock:
                        if entry not in homenet.user_domain_whitelist:
                            homenet.user_domain_whitelist.append(entry)
                            utils.del_domain_blacklist(entry)
                else:
                    if len(entry) >= 7:
                        utils.del_ip_ipset_blacklist(entry, 'blacklist')
                        utils.del_ip_ipset_blacklist(entry, 'blacklist-user')
                        with lock:
                            if entry not in homenet.user_whitelist:
                                homenet.user_whitelist.append(entry)
            resp = Response()
            resp.status_code = 200
            return resp
        elif action == 'list':
            data = utils.list_ipset_blacklist(target)
            data = {'content': data[7:-1]}
            data = json.dumps(data)
            resp = Response()
            resp.data = data
            resp.status_code = 200
            resp.mimetype = "application/json"
            return resp
        else:
            abort(400)

    @staticmethod
    @app.route('/api/v1.0/falcongate/admin/actions', methods=['POST'])
    def admin_actions():
        if not request.json:
            abort(400)

        action = str(request.json['action'])
        if action == 'reboot':
            utils.reboot_appliance()
            resp = Response()
            resp.status_code = 200
            return resp
        elif action == 'reset':
            utils.reset_appliance()
            resp = Response()
            resp.status_code = 200
            return resp
        else:
            abort(400)

    @app.route('/api/v1.0/falcongate/stats', methods=['POST'])
    def get_stats(self):
        if not request.json:
            abort(400)

        stype = str(request.json['stats_type'])
        stime = int(request.json['start_time'])
        etime = int(request.json['end_time'])
        if stype == 'country':
            data = self.get_country_stats(stime, etime)
            data = json.dumps(data)
            resp = Response()
            resp.data = data
            resp.status_code = 200
            resp.mimetype = "application/json"
            return resp
        else:
            abort(400)

    @staticmethod
    def get_country_stats(stime, etime):
        countries = {}
        for k in country_stats.keys():
                stats = country_stats[k].get_stats(stime, etime)
                if stats["nconn"] > 0:
                    countries[k] = stats
        return countries
