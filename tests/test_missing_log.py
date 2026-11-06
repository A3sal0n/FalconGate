import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from lib import system_health

# These tests don't use these packages, and they aren't installed in the CI job.
with patch.dict(sys.modules, {name: MagicMock() for name in ('GeoIP', 'requests', 'user_agents')}):
    from lib import logparser

DAY = logparser.MISSING_LOG_NOTICE_SECONDS
READERS = {
    logparser.ReadBroConn: 'bro_conn_log_path',
    logparser.ReadBroDNS: 'bro_dns_log_path',
    logparser.ReadBroNotice: 'bro_notice_log_path',
    logparser.ReadBroFiles: 'bro_files_log_path',
    logparser.ReadBroHTTP: 'bro_http_log_path',
}


class MissingLogTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = os.path.join(folder.name, 'test.log')

        for name, patcher in (('log', patch.object(logparser, 'log')),
                              ('monotonic', patch.object(logparser.time, 'monotonic', return_value=0))):
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)

    def make_reader(self, reader=logparser.ReadBroHTTP):
        with patch.object(logparser.GeoIP, 'new', create=True):
            thread = reader('test')
        setattr(thread, READERS[reader], self.path)
        return thread

    def poll_at(self, thread, seconds):
        self.monotonic.return_value = seconds
        return thread.get_new_lines()

    def test_every_reader_is_silent_while_a_log_is_briefly_missing(self):
        for reader in READERS:
            thread = self.make_reader(reader)
            self.assertFalse(self.poll_at(thread, 0))
            self.assertFalse(self.poll_at(thread, DAY))
        self.log.debug.assert_not_called()
        self.log.log.assert_not_called()

    def test_notice_after_more_than_24_hours(self):
        thread = self.make_reader()
        self.poll_at(thread, 0)
        self.poll_at(thread, DAY + 1)
        self.log.log.assert_called_once()
        level, message = self.log.log.call_args.args
        self.assertEqual(level, logparser.NOTICE)
        self.assertIn('FG-NOTICE', message)
        self.assertIn(thread.missing_log.path, message)

    def test_notice_repeats_only_once_a_day(self):
        thread = self.make_reader()
        self.poll_at(thread, 0)
        self.poll_at(thread, DAY + 1)
        self.poll_at(thread, DAY + 6)
        self.poll_at(thread, 2 * DAY + 1)
        self.assertEqual(self.log.log.call_count, 1)
        self.poll_at(thread, 2 * DAY + 2)
        self.assertEqual(self.log.log.call_count, 2)

    def test_the_log_returning_restarts_the_24_hours(self):
        thread = self.make_reader()
        self.poll_at(thread, 0)
        with open(self.path, 'w') as f:
            f.write('{}\n')
        self.assertTrue(self.poll_at(thread, DAY - 1))
        os.remove(self.path)
        self.poll_at(thread, DAY)
        self.poll_at(thread, DAY + 2)
        self.log.log.assert_not_called()

    def test_other_read_errors_are_still_logged(self):
        thread = self.make_reader()
        with patch('builtins.open', side_effect=PermissionError('denied')):
            self.assertFalse(self.poll_at(thread, 0))
        self.log.debug.assert_called_once()

    def test_notice_is_not_reported_as_a_service_error(self):
        self.assertTrue(system_health.NOT_AN_ERROR.search('logparser.missing: FG-NOTICE: /x/http.log has been missing'))


if __name__ == '__main__':
    unittest.main()
