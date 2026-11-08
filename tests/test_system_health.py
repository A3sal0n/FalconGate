import os
import tempfile
import unittest
from collections import namedtuple
from unittest.mock import patch

from lib import system_health

StatVfs = namedtuple('StatVfs', 'f_blocks f_bfree f_bavail f_frsize')


class SystemHealthTests(unittest.TestCase):
    def write_file(self, contents):
        handle, path = tempfile.mkstemp()
        self.addCleanup(os.remove, path)
        with os.fdopen(handle, 'w') as output:
            output.write(contents)
        return path

    def test_read_cpu_times_counts_iowait_as_idle(self):
        path = self.write_file('cpu  100 10 50 800 40 5 5 0 7 0\ncpu0 1 2 3 4 5 6 7 8 9 10\n')
        self.assertEqual(system_health.read_cpu_times(path), (840, 1010))

    def test_cpu_percent_is_the_busy_share_between_samples(self):
        samples = iter([(800, 1000), (830, 1100)])
        with patch.object(system_health, 'read_cpu_times', lambda path: next(samples)), \
                patch.object(system_health.time, 'sleep'):
            self.assertEqual(system_health.get_cpu_percent(), 70.0)

    def test_cpu_percent_handles_no_elapsed_time(self):
        with patch.object(system_health, 'read_cpu_times', lambda path: (800, 1000)), \
                patch.object(system_health.time, 'sleep'):
            self.assertEqual(system_health.get_cpu_percent(), 0.0)

    def test_read_meminfo_returns_bytes(self):
        path = self.write_file('MemTotal:       2048 kB\nMemAvailable:   1024 kB\nHugePages_Total:       0\n')
        self.assertEqual(system_health.read_meminfo(path), {'MemTotal': 2097152, 'MemAvailable': 1048576})

    def test_usage(self):
        self.assertEqual(system_health.usage(200, 50), {'total': 200, 'used': 50, 'free': 150, 'percent': 25.0})

    def test_usage_with_no_swap(self):
        self.assertEqual(system_health.usage(0, 0)['percent'], 0.0)

    def test_get_disks_keeps_real_partitions_once(self):
        path = self.write_file(
            'sysfs /sys sysfs rw 0 0\n'
            'tmpfs /run tmpfs rw 0 0\n'
            '/dev/sda2 / ext4 rw 0 0\n'
            '/dev/sda2 /var/bind ext4 rw 0 0\n'
            '/dev/loop3 /snap/core squashfs ro 0 0\n'
            '/dev/sda1 /boot/my\\040efi vfat rw 0 0\n')
        checked = []

        def statvfs(mount):
            checked.append(mount)
            return StatVfs(f_blocks=1000, f_bfree=300, f_bavail=200, f_frsize=4096)

        with patch.object(os, 'statvfs', statvfs, create=True):
            disks = system_health.get_disks(path)

        self.assertEqual(checked, ['/', '/boot/my efi'])
        self.assertEqual([disk['mount'] for disk in disks], ['/', '/boot/my efi'])
        self.assertEqual(disks[0]['total'], 4096000)
        self.assertEqual(disks[0]['used'], 2867200)
        self.assertEqual(disks[0]['free'], 819200)
        # Matches df: 700 used of the 900 blocks available to users.
        self.assertEqual(disks[0]['percent'], 77.8)

    def test_get_disks_skips_unreadable_and_empty_mounts(self):
        path = self.write_file('/dev/sda1 /gone ext4 rw 0 0\n/dev/sda2 /empty ext4 rw 0 0\n')

        def statvfs(mount):
            if mount == '/gone':
                raise OSError('not available')
            return StatVfs(f_blocks=0, f_bfree=0, f_bavail=0, f_frsize=4096)

        with patch.object(os, 'statvfs', statvfs, create=True):
            self.assertEqual(system_health.get_disks(path), [])


if __name__ == '__main__':
    unittest.main()
