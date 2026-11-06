import json
import os
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from lib import utils


class AlertTimeTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.db_path = os.path.join(directory.name, 'alerts.sqlite')

        connection = sqlite3.connect(self.db_path)
        connection.execute("create table alerts(id int, type text, fseen int, lseen int, lrep int, nrep int, "
                           "threat text, sip text, ind text, handled int, desc text, ref text)")
        connection.commit()
        connection.close()

        patcher = patch.object(utils, 'connect_alert_db', lambda: sqlite3.connect(self.db_path))
        patcher.start()
        self.addCleanup(patcher.stop)

    def add_alert(self, first_seen, last_seen):
        connection = sqlite3.connect(self.db_path)
        connection.execute("insert into alerts values (1, 'dga', ?, ?, 0, 0, 'Malware', '192.168.100.190', "
                           "'bad.example', 0, 'description', 'reference')", (first_seen, last_seen))
        connection.commit()
        connection.close()

    def test_format_utc_time(self):
        self.assertEqual(utils.format_utc_time(1700000000), '2023/11/14 22:13:20 UTC')

    def test_format_utc_time_drops_fractions_of_a_second(self):
        self.assertEqual(utils.format_utc_time(1700000000.75), '2023/11/14 22:13:20 UTC')

    def test_format_utc_time_ignores_the_local_time_zone(self):
        if not hasattr(time, 'tzset'):
            self.skipTest('Changing the time zone needs time.tzset')
        with patch.dict(os.environ, {'TZ': 'Asia/Tokyo'}):
            time.tzset()
            self.addCleanup(time.tzset)
            self.assertEqual(utils.format_utc_time(1700000000), '2023/11/14 22:13:20 UTC')

    def test_alerts_return_utc_times(self):
        first_seen = int(time.time()) - 60
        self.add_alert(first_seen, first_seen + 30.5)

        alert = json.loads(utils.get_alerts_within_time(3600, 'all'))[0]

        self.assertEqual(alert[2], utils.format_utc_time(first_seen))
        self.assertEqual(alert[3], utils.format_utc_time(first_seen + 30.5))
        self.assertEqual(alert[1], 'dga')
        self.assertEqual(alert[11], 'reference')

    def test_time_window_still_filters_on_the_stored_timestamp(self):
        self.add_alert(int(time.time()) - 7200, int(time.time()) - 7200)

        self.assertEqual(json.loads(utils.get_alerts_within_time(3600, 'all')), [])
        self.assertEqual(len(json.loads(utils.get_alerts_within_time(10800, 'all'))), 1)

    def test_handled_filter_still_applies(self):
        self.add_alert(int(time.time()) - 60, int(time.time()) - 60)

        self.assertEqual(len(json.loads(utils.get_alerts_within_time(3600, '0'))), 1)
        self.assertEqual(json.loads(utils.get_alerts_within_time(3600, '1')), [])

    def test_update_alert_handled_saves_and_reports_the_change(self):
        self.add_alert(int(time.time()) - 60, int(time.time()) - 60)

        self.assertEqual(json.loads(utils.update_alert_handled('1', '1')), {'updated': True})
        self.assertEqual(len(json.loads(utils.get_alerts_within_time(3600, '1'))), 1)

    def test_update_alert_handled_reports_an_alert_that_does_not_exist(self):
        self.assertEqual(json.loads(utils.update_alert_handled('999', '1')), {'updated': False})


if __name__ == '__main__':
    unittest.main()
