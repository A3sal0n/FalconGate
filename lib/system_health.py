"""Collects server health: CPU, memory, disk usage and the state of Falcongate's services."""
import glob
import json
import os
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

CPU_SAMPLE_SECONDS = 0.5

COMMAND_TIMEOUT_SECONDS = 8
# Read this many journal lines per service when looking for errors, and report this many.
JOURNAL_LINES = 2000
MAX_SERVICE_ERRORS = 5
MAX_ERROR_LENGTH = 400
# Used when systemd can't say when a service last tried to start.
DEFAULT_ERROR_WINDOW_SECONDS = 86400
ERROR_PRIORITY = 3

# Most programs log errors at normal priority, including Falcongate, which logs FG-ERROR at debug
# priority and whose Python tracebacks arrive through stderr. So the text is checked as well.
ERROR_TEXT = re.compile(r'error|fatal|failed|failure|traceback|exception', re.IGNORECASE)
NOT_AN_ERROR = re.compile(r'FG-(DEBUG|INFO|WARN)|\b(no|0) errors?\b', re.IGNORECASE)

# Oneshot services stay "active" after they exit, so Zeek also needs a running process.
SERVICES = (
    {'name': 'Falcongate', 'unit': 'falcongate.service', 'description': 'Detection engine and API'},
    {'name': 'Zeek', 'unit': 'zeek.service', 'description': 'Network traffic monitoring', 'process': 'zeek'},
    {'name': 'dnsmasq', 'unit': 'dnsmasq.service', 'description': 'DNS, DHCP and domain blocking'},
    {'name': 'dnscrypt-proxy', 'unit': 'dnscrypt-proxy.service', 'description': 'Encrypted DNS'},
    {'name': 'nginx', 'unit': 'nginx.service', 'description': 'Web console'},
    {'name': 'PHP-FPM', 'unit': None, 'description': 'Web console pages'},
    {'name': 'Firewall', 'unit': 'netfilter-persistent.service', 'description': 'Firewall rules'},
)


def read_cpu_times(path='/proc/stat'):
    """Return (idle, total) CPU time since boot, in kernel ticks."""
    with open(path) as stat:
        fields = stat.readline().split()
    # user nice system idle iowait irq softirq steal. Guest time is already part of user.
    times = [int(value) for value in fields[1:9]]
    return times[3] + times[4], sum(times)


def get_cpu_percent(interval=CPU_SAMPLE_SECONDS, path='/proc/stat'):
    idle_before, total_before = read_cpu_times(path)
    time.sleep(interval)
    idle_after, total_after = read_cpu_times(path)
    elapsed = total_after - total_before
    if elapsed <= 0:
        return 0.0
    return round(100.0 * (elapsed - (idle_after - idle_before)) / elapsed, 1)


def read_meminfo(path='/proc/meminfo'):
    """Return the /proc/meminfo values in bytes (the file reports kB)."""
    values = {}
    with open(path) as meminfo:
        for line in meminfo:
            match = re.match(r'(\w+):\s+(\d+) kB', line)
            if match:
                values[match.group(1)] = int(match.group(2)) * 1024
    return values


def usage(total, used):
    return {'total': total, 'used': used, 'free': total - used,
            'percent': round(100.0 * used / total, 1) if total else 0.0}


def unescape_mount_field(value):
    """Decode the octal escapes /proc/mounts uses for spaces and similar characters."""
    return re.sub(r'\\([0-7]{3})', lambda match: chr(int(match.group(1), 8)), value)


def get_disks(path='/proc/mounts'):
    """Return usage for each block device, once, ignoring pseudo filesystems and loop devices."""
    disks = []
    seen = set()
    with open(path) as mounts:
        for line in mounts:
            device, mount, fstype = line.split()[:3]
            if not device.startswith('/dev/') or device.startswith('/dev/loop') or device in seen:
                continue
            seen.add(device)
            mount = unescape_mount_field(mount)
            try:
                info = os.statvfs(mount)
            except OSError:
                continue
            total = info.f_blocks * info.f_frsize
            if total == 0:
                continue
            used = (info.f_blocks - info.f_bfree) * info.f_frsize
            free = info.f_bavail * info.f_frsize
            # Like df, leave out the blocks reserved for root, which nobody else can use.
            usable = used + free
            disks.append({'device': device, 'mount': mount, 'fstype': fstype, 'total': total, 'used': used,
                          'free': free, 'percent': round(100.0 * used / usable, 1) if usable else 0.0})
    return sorted(disks, key=lambda disk: disk['mount'])


def read_uptime(path='/proc/uptime'):
    with open(path) as uptime:
        return int(float(uptime.read().split()[0]))


def format_utc(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime('%Y/%m/%d %H:%M:%S UTC')


def run_command(arguments):
    """Run a read-only command with UTC, untranslated output and return what it printed."""
    environment = dict(os.environ, TZ='UTC', LC_ALL='C')
    result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=COMMAND_TIMEOUT_SECONDS,
                            env=environment, universal_newlines=True, errors='replace')
    return result.stdout


def get_unit_properties(unit):
    output = run_command(['systemctl', 'show', unit, '--property=LoadState,ActiveState,SubState,Result,NRestarts,'
                                                     'InactiveExitTimestamp,ActiveEnterTimestamp,TriggeredBy'])
    return dict(line.split('=', 1) for line in output.splitlines() if '=' in line)


def parse_systemd_time(value):
    """Convert a time printed by systemctl while TZ=UTC to a Unix timestamp, or None if there isn't one."""
    try:
        parsed = datetime.strptime(value, '%a %Y-%m-%d %H:%M:%S UTC')
    except (TypeError, ValueError):
        return None
    return int(parsed.replace(tzinfo=timezone.utc).timestamp())


def find_php_fpm_unit(pattern='/etc/php/*/'):
    """Return the unit of the installed PHP version, which varies by release."""
    versions = [os.path.basename(path.rstrip('/\\')) for path in glob.glob(pattern)]
    versions = [version for version in versions if re.fullmatch(r'\d+\.\d+', version)]
    if not versions:
        return 'php-fpm.service'
    newest = max(versions, key=lambda version: [int(part) for part in version.split('.')])
    return 'php' + newest + '-fpm.service'


def is_process_running(name, proc_root='/proc'):
    for path in glob.glob(os.path.join(proc_root, '[0-9]*', 'comm')):
        try:
            with open(path) as comm:
                if comm.read().strip() == name:
                    return True
        except OSError:
            continue
    return False


def describe_state(service, properties):
    """Translate a unit's state to a level (normal, high or critical) and a label."""
    load_state = properties.get('LoadState')
    active_state = properties.get('ActiveState')
    if load_state == 'not-found':
        return 'high', 'Not installed'
    if active_state == 'active':
        if service.get('process') and not is_process_running(service['process']):
            return 'critical', 'Process not running'
        return 'normal', 'Running'
    if active_state in ('activating', 'reloading'):
        return 'high', 'Starting'
    if active_state == 'deactivating':
        return 'high', 'Stopping'
    if active_state == 'failed':
        return 'critical', 'Failed'
    # A socket-activated service only runs once something connects to it.
    triggers = properties.get('TriggeredBy', '').split()
    if active_state == 'inactive' and triggers and get_unit_properties(triggers[0]).get('ActiveState') == 'active':
        return 'normal', 'Ready'
    return 'critical', 'Stopped'


def read_journal_message(entry):
    """Return a journal entry's text. journald sends text that isn't UTF-8 as a list of bytes."""
    message = entry.get('MESSAGE')
    if isinstance(message, list):
        return bytes(message).decode('utf-8', 'replace')
    return message if isinstance(message, str) else ''


def is_error_entry(entry, message):
    if NOT_AN_ERROR.search(message):
        return False
    try:
        if int(entry.get('PRIORITY', 6)) <= ERROR_PRIORITY:
            return True
    except ValueError:
        pass
    return ERROR_TEXT.search(message) is not None


def get_unit_errors(unit, since):
    """Return a unit's newest distinct errors since a time, with how often each one repeated."""
    output = run_command(['journalctl', '--unit', unit, '--since', '@' + str(since), '--lines', str(JOURNAL_LINES),
                          '--output', 'json', '--no-pager', '--quiet'])
    errors = {}
    for line in output.splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        message = read_journal_message(entry).strip()
        if is_error_entry(entry, message):
            found = errors.setdefault(message, {'message': message[:MAX_ERROR_LENGTH], 'count': 0})
            found['count'] += 1
            found['timestamp'] = int(entry.get('__REALTIME_TIMESTAMP', 0)) // 1000000
    newest = sorted(errors.values(), key=lambda error: error['timestamp'], reverse=True)[:MAX_SERVICE_ERRORS]
    return [{'time': format_utc(error['timestamp']), 'message': error['message'], 'count': error['count']} for error in newest]


def get_service_status(service):
    unit = service['unit'] or find_php_fpm_unit()
    status = {'name': service['name'], 'unit': unit, 'description': service['description']}
    try:
        properties = get_unit_properties(unit)
        status['level'], status['label'] = describe_state(service, properties)
    except (OSError, subprocess.SubprocessError, ValueError):
        return dict(status, level='high', label='Unknown', since=None, restarts=0, errors=[], errors_available=False)

    active_since = parse_systemd_time(properties.get('ActiveEnterTimestamp'))
    status['since'] = format_utc(active_since) if active_since and properties.get('ActiveState') == 'active' else None
    status['restarts'] = int(properties.get('NRestarts') or 0)

    start_attempt = parse_systemd_time(properties.get('InactiveExitTimestamp'))
    try:
        status['errors'] = get_unit_errors(unit, start_attempt or int(time.time()) - DEFAULT_ERROR_WINDOW_SECONDS)
        status['errors_available'] = True
    except (OSError, subprocess.SubprocessError):
        status['errors'] = []
        status['errors_available'] = False
    return status


def get_services_status():
    with ThreadPoolExecutor(max_workers=len(SERVICES)) as executor:
        services = list(executor.map(get_service_status, SERVICES))
    return {'updated': format_utc(time.time()), 'services': services}


def get_system_health():
    meminfo = read_meminfo()
    load_1, load_5, load_15 = os.getloadavg()
    return {
        'updated': datetime.now(timezone.utc).strftime('%Y/%m/%d %H:%M:%S UTC'),
        'uptime_seconds': read_uptime(),
        'cpu': {'percent': get_cpu_percent(), 'cores': os.cpu_count(),
                'load_1': round(load_1, 2), 'load_5': round(load_5, 2), 'load_15': round(load_15, 2)},
        'memory': usage(meminfo['MemTotal'], meminfo['MemTotal'] - meminfo['MemAvailable']),
        'swap': usage(meminfo.get('SwapTotal', 0), meminfo.get('SwapTotal', 0) - meminfo.get('SwapFree', 0)),
        'disks': get_disks(),
    }
