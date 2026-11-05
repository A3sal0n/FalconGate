"""Collects CPU, memory and disk usage from the Linux kernel's own interfaces."""
import os
import re
import time
from datetime import datetime, timezone

CPU_SAMPLE_SECONDS = 0.5


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
