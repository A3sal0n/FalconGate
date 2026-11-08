import logging.handlers

# Python has no level between INFO and WARNING, but syslog does.
NOTICE = 25
logging.addLevelName(NOTICE, 'NOTICE')

global log
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
handler = logging.handlers.SysLogHandler(address='/dev/log')
handler.priority_map = dict(handler.priority_map, NOTICE='notice')
formatter = logging.Formatter('%(module)s.%(funcName)s: %(message)s')
handler.setFormatter(formatter)
log.addHandler(handler)
