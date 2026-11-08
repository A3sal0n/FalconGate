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
        del stats.pending_dns[:]
        self.addCleanup(stats.pending_dns.clear)

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

    def dns_fields(self, query='www.evil.test', src='192.168.100.10', server='192.168.100.1', ts=HOUR + 10.0, port=53, line='1'):
        return {'uid': line, 'trans_id': 1, 'ts': ts, 'query': query, 'qtype_name': 'A', 'id.orig_h': src,
                'id.resp_h': server, 'id.resp_p': port}

    def dns_record(self, *args, rcode='NOERROR', category=None, **kwargs):
        fields = self.dns_fields(*args, **kwargs)
        stats.record_dns_lookup(fields, fields['query'], '.'.join(fields['query'].split('.')[-2:]), rcode, category)

    def dns_activity(self, start=HOUR, end=HOUR + 100):
        stats.save_dns_lookups(end)
        with patch.object(stats, 'homenet', Network()):
            return stats.get_dns_activity(start, end)

    def test_only_plain_dns_to_internet_servers_counts_as_external(self):
        self.assertTrue(stats.is_external_resolver(self.dns_fields(server='8.8.8.8')))
        for fields in (self.dns_fields(), self.dns_fields(server='8.8.8.8', port=5353),
                       self.dns_fields(server='224.0.0.251'), self.dns_fields(server='not-an-ip')):
            self.assertFalse(stats.is_external_resolver(fields), fields['id.resp_h'])

    def test_dns_summary_counts_lookups_failures_and_flags(self):
        self.dns_record(line='1')
        self.dns_record(line='2', rcode='NXDOMAIN', query='a.nope.test')
        self.dns_record(line='3', query='bad.evil2.test', category='phishing')
        self.dns_record(line='4')

        summary = self.dns_activity()['summary']

        self.assertEqual(summary, {'lookups': 4, 'domains': 3, 'flagged': 1, 'failed_percent': 25.0})

    def test_rereading_dns_log_does_not_count_twice(self):
        self.dns_record()
        stats.save_dns_lookups(HOUR + 50)
        self.dns_record()

        self.assertEqual(self.dns_activity()['summary']['lookups'], 1)

    def test_failed_dns_save_keeps_lookups(self):
        self.dns_record()
        with patch.object(stats, 'connect_stats_db', side_effect=stats.lite.OperationalError('database is locked')):
            with self.assertRaises(stats.lite.OperationalError):
                stats.save_dns_lookups(HOUR + 50)

        self.assertEqual(len(stats.pending_dns), 1)
        self.assertEqual(self.dns_activity()['summary']['lookups'], 1)

    def test_dns_timeline_splits_series_and_fills_empty_hours(self):
        self.dns_record(line='1', ts=HOUR - 3590.0)
        self.dns_record(line='2', ts=HOUR + 10.0, rcode='NXDOMAIN')
        self.dns_record(line='3', ts=HOUR + 20.0, category='gambling', query='x.bet.test')

        timeline = self.dns_activity(HOUR - 7200, HOUR + 100)['timeline']

        self.assertEqual(timeline['normal'], [0, 1, 0])
        self.assertEqual(timeline['failed'], [0, 0, 1])
        self.assertEqual(timeline['flagged'], [0, 0, 1])
        self.assertEqual(len(timeline['labels']), 3)

    def test_long_periods_are_limited_to_retained_days_and_grouped_by_day(self):
        self.dns_record()

        timeline = self.dns_activity(HOUR - 30 * 86400, HOUR + 100)['timeline']

        self.assertEqual(len(timeline['labels']), 8)
        self.assertEqual(sum(timeline['normal']), 1)

    def test_failed_and_flagged_are_grouped_by_device(self):
        self.dns_record(line='1', rcode='NXDOMAIN')
        self.dns_record(line='2', rcode='NXDOMAIN', query='b.nope.test', src='192.168.100.20')
        self.dns_record(line='3', rcode='NXDOMAIN', query='c.nope.test', src='192.168.100.20')
        self.dns_record(line='4', query='a.bad.test', category='malware')
        self.dns_record(line='5', query='a.bet.test', category='gambling')
        self.dns_record(line='6', query='b.bet.test', category='gambling', src='192.168.100.20')

        dns = self.dns_activity()

        self.assertEqual(dns['failed_by_device'][0], {'label': '192.168.100.20', 'count': 2})
        self.assertEqual(dns['flagged_by_device']['labels'], ['192.168.100.10', '192.168.100.20'])
        self.assertEqual(dns['flagged_by_device']['series'], {'gambling': [1, 1], 'malware': [1, 0]})

    def test_new_domains_skip_older_and_well_known_ones(self):
        self.dns_record(line='1', query='www.older.test', ts=HOUR - 7200.0)
        self.dns_record(line='2', query='cdn.older.test', ts=HOUR + 10.0)
        self.dns_record(line='3', query='www.popular.test', ts=HOUR + 20.0)
        self.dns_record(line='4', query='www.fresh.test', ts=HOUR + 30.0)
        self.dns_record(line='5', query='api.fresh.test', ts=HOUR + 40.0, src='192.168.100.20')

        with patch.object(stats, 'top_domains', {'popular.test'}):
            domains = self.dns_activity()['new_domains']

        self.assertEqual([row['domain'] for row in domains], ['fresh.test'])
        self.assertEqual(domains[0]['lookups'], 2)
        self.assertEqual(domains[0]['device'], '192.168.100.10 and 1 more')

    def test_external_resolvers_are_listed_per_device_and_server(self):
        self.dns_record(line='1', server='8.8.8.8')
        self.dns_record(line='2', server='8.8.8.8')
        self.dns_record(line='3')

        resolvers = self.dns_activity()['external_resolvers']

        self.assertEqual(len(resolvers), 1)
        self.assertEqual((resolvers[0]['device'], resolvers[0]['server'], resolvers[0]['lookups']), ('192.168.100.10', '8.8.8.8', 2))

    def test_dns_activity_is_empty_without_data(self):
        dns = self.dns_activity()

        self.assertEqual(dns['summary'], {'lookups': 0, 'domains': 0, 'flagged': 0, 'failed_percent': 0})
        self.assertEqual(dns['new_domains'], [])

    def test_old_dns_activity_is_deleted(self):
        now = HOUR + 8 * 86400
        self.dns_record(line='1', ts=HOUR + 10.0, server='8.8.8.8')
        self.dns_record(line='2', ts=now - 60.0)
        stats.save_dns_lookups(now)

        stats.delete_old_dns(now)

        con = stats.connect_stats_db()
        self.assertEqual(con.execute("select count(*) from dns_activity").fetchone()[0], 1)
        self.assertEqual(con.execute("select count(*) from dns_external_resolvers").fetchone()[0], 0)
        con.close()

    def test_old_stats_are_deleted(self):
        now = HOUR + stats.RETENTION_SECONDS
        stats.save_country_stats({HOUR - 3600: {'US': [1, 1, 1, 1, 1]}, HOUR: {'DE': [1, 1, 1, 1, 1]}})

        stats.delete_old_stats(now)

        self.assertEqual(list(stats.get_country_stats(HOUR - 7200, now)), ['DE'])


if __name__ == '__main__':
    unittest.main()
