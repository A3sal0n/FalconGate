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


def conn_fields(uid='C1', src='192.168.100.10', dst='8.8.8.8', proto='tcp', port=443, ts=HOUR + 10.0, **extra):
    fields = {'uid': uid, 'id.orig_h': src, 'id.orig_p': 50000, 'id.resp_h': dst, 'id.resp_p': port, 'proto': proto,
              'ts': ts, 'duration': 5.0, 'orig_ip_bytes': 100, 'resp_ip_bytes': 200,
              'local_orig': True, 'local_resp': False}
    fields.update(extra)
    return fields


class StatsTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        patcher = patch.object(stats, 'STATS_DB', os.path.join(directory.name, 'stats.sqlite'))
        patcher.start()
        self.addCleanup(patcher.stop)
        stats.create_stats_db()
        del stats.pending_connections[:]
        self.addCleanup(stats.pending_connections.clear)

    def connections(self):
        con = stats.connect_stats_db()
        rows = con.execute("select src_ip, dst_ip, proto, dst_port, country, first_seen, last_seen, bytes_out, "
                           "bytes_in from connections order by dst_ip, proto").fetchall()
        con.close()
        return rows

    def test_only_outbound_internet_connections_qualify(self):
        self.assertTrue(stats.is_outbound_internet(conn_fields()))
        self.assertTrue(stats.is_outbound_internet(conn_fields(dst='2001:4860:4860::8888')))
        for fields in (conn_fields(local_resp=True), conn_fields(local_orig=False),
                       conn_fields(dst='10.0.0.1'), conn_fields(dst='192.168.1.1'), conn_fields(dst='172.16.0.1'),
                       conn_fields(dst='100.64.0.1'), conn_fields(dst='169.254.0.1'), conn_fields(dst='224.0.0.251'),
                       conn_fields(dst='ff02::fb'), conn_fields(dst='fe80::1'), conn_fields(dst='not-an-ip')):
            self.assertFalse(stats.is_outbound_internet(fields), fields['id.resp_h'])
        fields = conn_fields()
        del fields['local_orig']
        self.assertFalse(stats.is_outbound_internet(fields))

    def test_connection_is_stored_with_its_fields(self):
        stats.record_connection(conn_fields(), 'US')
        stats.save_connections(HOUR + 100)

        self.assertEqual(self.connections(), [('192.168.100.10', '8.8.8.8', 'tcp', 443, 'US', HOUR + 10.0, HOUR + 15.0, 100, 200)])

    def test_unknown_country_is_stored_as_not_available(self):
        for country in (None, ''):
            del stats.pending_connections[:]
            stats.record_connection(conn_fields(uid='U' + str(country)), country)
            stats.save_connections(HOUR + 100)
        self.assertEqual(self.connections()[0][4], 'N/A')

    def test_missing_optional_fields_count_as_zero(self):
        fields = conn_fields()
        for name in ('duration', 'orig_ip_bytes', 'resp_ip_bytes'):
            del fields[name]
        stats.record_connection(fields, 'US')
        stats.save_connections(HOUR + 100)

        row = self.connections()[0]
        self.assertEqual(row[5:], (HOUR + 10.0, HOUR + 10.0, 0, 0))

    def test_same_destination_port_is_one_row_whatever_the_source_port(self):
        stats.record_connection(conn_fields(uid='C1', ts=HOUR + 50.0), 'US')
        stats.record_connection(conn_fields(uid='C2', ts=HOUR + 10.0, **{'id.orig_p': 60000}), 'US')
        stats.save_connections(HOUR + 100)

        rows = self.connections()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][5:], (HOUR + 10.0, HOUR + 55.0, 200, 400))

    def test_protocols_and_ports_are_kept_apart(self):
        stats.record_connection(conn_fields(uid='C1', proto='tcp'), 'US')
        stats.record_connection(conn_fields(uid='C2', proto='udp'), 'US')
        stats.record_connection(conn_fields(uid='C3', port=80), 'US')
        stats.save_connections(HOUR + 100)

        self.assertEqual(len(self.connections()), 3)

    def test_rereading_the_log_does_not_count_twice(self):
        stats.record_connection(conn_fields(), 'US')
        stats.save_connections(HOUR + 100)

        # A restart reads the same line again, and the same line can also repeat within one save.
        stats.record_connection(conn_fields(), 'US')
        stats.record_connection(conn_fields(), 'US')
        stats.save_connections(HOUR + 400)

        self.assertEqual(self.connections()[0][7:], (100, 200))

    def test_failed_save_keeps_connections_and_counts_them_once(self):
        stats.record_connection(conn_fields(), 'US')
        with patch.object(stats, 'connect_stats_db', side_effect=stats.lite.OperationalError('database is locked')):
            with self.assertRaises(stats.lite.OperationalError):
                stats.save_connections(HOUR + 100)
        self.assertEqual(len(stats.pending_connections), 1)

        stats.save_connections(HOUR + 400)

        self.assertEqual(stats.pending_connections, [])
        self.assertEqual(self.connections()[0][7:], (100, 200))

    def test_connections_older_than_seven_days_are_deleted(self):
        now = HOUR + 8 * 86400
        stats.record_connection(conn_fields(uid='OLD', dst='8.8.8.8', ts=now - 7 * 86400 - 60.0), 'US')
        stats.record_connection(conn_fields(uid='NEW', dst='9.9.9.9', ts=now - 7 * 86400 + 60.0), 'US')
        stats.save_connections(now)

        stats.delete_old_connections(now)

        self.assertEqual([row[1] for row in self.connections()], ['9.9.9.9'])

    def test_uids_are_kept_only_long_enough_to_cover_a_reread(self):
        stats.record_connection(conn_fields(), 'US')
        stats.save_connections(HOUR)

        stats.delete_old_connections(HOUR + stats.CONNECTION_UID_RETENTION_SECONDS + 1)

        con = stats.connect_stats_db()
        self.assertEqual(con.execute("select count(*) from connection_uids").fetchone()[0], 0)
        con.close()

    def test_top_connections(self):
        network = Network()
        host = Host()
        host.hostname = 'laptop'
        network.hosts = {'192.168.100.10': host}
        rows = [conn_fields(uid='A', dst='8.8.8.8', orig_ip_bytes=500), conn_fields(uid='B', dst='8.8.8.8', port=80, orig_ip_bytes=100),
                conn_fields(uid='C', dst='1.1.1.1', orig_ip_bytes=300), conn_fields(uid='D', src='192.168.100.20', dst='1.1.1.1', orig_ip_bytes=50)]
        for row in rows:
            stats.record_connection(row, 'US' if row['id.resp_h'] == '8.8.8.8' else None)
        stats.save_connections(HOUR + 100)

        with patch.object(stats, 'homenet', network):
            top = stats.get_top_connections(HOUR, HOUR + 100)

        self.assertEqual(top['senders'], [{'label': 'laptop (192.168.100.10)', 'bytes': 900}, {'label': '192.168.100.20', 'bytes': 50}])
        self.assertEqual(top['destinations'], [{'label': '8.8.8.8 (US)', 'bytes': 600}, {'label': '1.1.1.1 (N/A)', 'bytes': 350}])
        self.assertEqual(top['pairs'][0], {'label': '192.168.100.10 → 8.8.8.8', 'bytes': 600})
        self.assertEqual(len(top['pairs']), 3)

    def test_top_connections_only_includes_the_time_range_and_top_ten(self):
        for i in range(12):
            stats.record_connection(conn_fields(uid=str(i), dst='8.8.8.' + str(i + 1), orig_ip_bytes=i + 1), 'US')
        stats.record_connection(conn_fields(uid='OLD', dst='9.9.9.9', ts=HOUR - 86400.0, orig_ip_bytes=9999), 'US')
        stats.save_connections(HOUR + 100)

        top = stats.get_top_connections(HOUR, HOUR + 100)

        self.assertEqual(len(top['destinations']), 10)
        self.assertEqual(top['destinations'][0]['label'], '8.8.8.12 (US)')
        self.assertNotIn('9.9.9.9 (US)', [row['label'] for row in top['destinations']])

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
