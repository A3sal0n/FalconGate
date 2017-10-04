#!/usr/bin/env python

from flask import Flask
from flask import request
from flask import abort
from flask import Response
import threading
import json
import lib.utils as utils
from lib.logger import *

global app
global homenet
global lock

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
            utils.flush_ipset_list('blacklist-user')
            for ip in target:
                with lock:
                    if (len(ip) >= 7) and (ip not in homenet.user_blacklist) and (ip not in homenet.user_whitelist):
                        homenet.user_blacklist.append(ip)
                        utils.add_ip_ipset_blacklist(ip, 'blacklist-user')
                        log.debug('FG-INFO: IP ' + ip + 'added to user blacklist')

            resp = Response()
            resp.status_code = 200
            return resp
        elif action == 'unblock':
            for ip in target:
                with lock:
                    if (len(ip) >= 7) and (ip in homenet.user_blacklist):
                        utils.del_ip_ipset_blacklist(ip, 'blacklist-user')
            resp = Response()
            resp.status_code = 200
            return resp
        elif action == 'whitelist':
            for ip in target:
                if len(ip) >= 7:
                    utils.del_ip_ipset_blacklist(ip, 'blacklist')
                    utils.del_ip_ipset_blacklist(ip, 'blacklist-user')
                    with lock:
                        if ip not in homenet.user_whitelist:
                            homenet.user_whitelist.append(ip)
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

    @staticmethod
    @app.route('/api/v1.0/falcongate/wit/ask', methods=['POST'])
    def wit_bot_ask():
        if not request.json:
            abort(400)

        resp = Response()
        resp.status_code = 200
        return resp

    @staticmethod
    def debug():
        assert app.debug is False
