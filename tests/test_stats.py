import os
import tempfile
import unittest
from unittest.mock import patch

from lib import stats
from lib.objects import Conn, Host, Network

HOUR = 1700000000 - 1700000000 % 3600


def make_conn(ts, country='US', direction='outbound', sent=100, received=200):
    conn = Conn()
    conn.ts = ts
    conn.direction = direction
    conn.dst_country_code = country
    conn.client_bytes = sent
    conn.server_bytes = received
    conn.client_packets = 1
    conn.server_packets = 2
    conn.counter = 1
    return conn


class StatsTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        patcher = patch.object(stats, 'STATS_DB', os.path.join(directory.name, 'stats.sqlite'))
        patcher.start()
        self.addCleanup(patcher.stop)
        stats.create_stats_db()

    def network(self, conns, mac='AA:AA:AA:AA:AA:AA'):
        network = Network()
        network.mac = 'FF:FF:FF:FF:FF:FF'
        host = Host()
        host.mac = mac
        host.conns = {str(i): conn for i, conn in enumerate(conns)}
        network.hosts = {'192.168.100.10': host}
        return network

    def test_stored_stats_survive_a_restart(self):
        stats.save_country_stats({HOUR: {'US': [100, 200, 1, 2, 3]}})

        # Every service start runs this, and it must keep the existing data.
        stats.create_stats_db()

        self.assertEqual(stats.get_country_stats(HOUR, HOUR + 60)['US'],
                         {'bytes_sent': 100, 'bytes_received': 200, 'pqt_sent': 1, 'pqt_received': 2, 'nconn': 3})

    def test_saving_again_replaces_an_hour_instead_of_adding_to_it(self):
        stats.save_country_stats({HOUR: {'US': [100, 200, 1, 2, 3]}})
        stats.save_country_stats({HOUR: {'US': [150, 250, 2, 3, 4]}})

        self.assertEqual(stats.get_country_stats(HOUR, HOUR)['US']['bytes_sent'], 150)

    def test_partial_data_after_a_restart_never_lowers_a_total(self):
        stats.save_country_stats({HOUR: {'US': [100, 200, 5, 6, 7]}})
        stats.save_country_stats({HOUR: {'US': [10, 20, 1, 1, 1]}})

        self.assertEqual(stats.get_country_stats(HOUR, HOUR)['US'],
                         {'bytes_sent': 100, 'bytes_received': 200, 'pqt_sent': 5, 'pqt_received': 6, 'nconn': 7})

    def test_time_range_adds_up_overlapping_hours_only(self):
        stats.save_country_stats({HOUR - 7200: {'US': [1, 1, 1, 1, 1]},
                                  HOUR - 3600: {'US': [10, 10, 10, 10, 10]},
                                  HOUR: {'US': [100, 100, 100, 100, 100], 'DE': [5, 5, 5, 5, 5]}})

        # Starting part-way through the previous hour includes that hour.
        result = stats.get_country_stats(HOUR - 1800, HOUR + 60)

        self.assertEqual(result['US']['bytes_sent'], 110)
        self.assertEqual(result['DE']['bytes_sent'], 5)

    def test_no_stats_returns_nothing(self):
        self.assertEqual(stats.get_country_stats(HOUR, HOUR + 60), {})

    def test_collect_groups_connections_by_hour_and_country(self):
        network = self.network([make_conn(HOUR + 10), make_conn(HOUR + 20), make_conn(HOUR + 30, 'DE'),
                                make_conn(HOUR - 10)])

        with patch.object(stats, 'homenet', network):
            totals = stats.collect_country_totals(HOUR + 100)

        self.assertEqual(totals[HOUR]['US'], [200, 400, 2, 4, 2])
        self.assertEqual(totals[HOUR]['DE'], [100, 200, 1, 2, 1])
        self.assertEqual(totals[HOUR - 3600]['US'], [100, 200, 1, 2, 1])

    def test_collect_skips_what_should_not_count(self):
        conns = [make_conn(HOUR + 10, direction='inbound'), make_conn(HOUR + 10, country=None),
                 make_conn(HOUR - 7200)]
        network = self.network(conns)

        with patch.object(stats, 'homenet', network):
            totals = stats.collect_country_totals(HOUR + 100)

        self.assertEqual(totals, {HOUR: {}, HOUR - 3600: {}})

    def test_collect_skips_the_appliance_itself(self):
        network = self.network([make_conn(HOUR + 10)], mac='FF:FF:FF:FF:FF:FF')

        with patch.object(stats, 'homenet', network):
            self.assertEqual(stats.collect_country_totals(HOUR + 100)[HOUR], {})

    def test_old_stats_are_deleted(self):
        now = HOUR + stats.RETENTION_SECONDS
        stats.save_country_stats({HOUR - 3600: {'US': [1, 1, 1, 1, 1]}, HOUR: {'DE': [1, 1, 1, 1, 1]}})

        stats.delete_old_stats(now)

        self.assertEqual(list(stats.get_country_stats(HOUR - 7200, now)), ['DE'])


if __name__ == '__main__':
    unittest.main()
