import sys
import unittest
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

# These tests don't use this package, and it isn't installed in the CI job.
with patch.dict(sys.modules, {'requests': MagicMock()}):
    from lib import intel

Checker = intel.CheckVirusTotalIntel


def days_ago(days):
    return (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')


class EvalDomainTests(unittest.TestCase):
    def setUp(self):
        for name, patcher in (('log', patch.object(intel, 'log')),
                              ('session', patch.object(intel, 'session'))):
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)

    def evaluate(self, response):
        self.session.get.return_value.json.return_value = response
        return Checker.eval_vt_intel_domain('example.test')

    def test_response_without_optional_fields_is_clean_and_not_logged(self):
        self.assertIs(self.evaluate({'response_code': 0}), False)
        self.log.debug.assert_not_called()

    def test_detections_count_without_categories(self):
        recent = [{'scan_date': days_ago(1)}, {'scan_date': days_ago(2)}]
        self.assertIs(self.evaluate({'response_code': 1, 'detected_urls': recent}), True)

    def test_each_detection_field_can_flag_the_domain(self):
        recent = [{'date': days_ago(1)}, {'date': days_ago(2)}]
        for field in ('detected_communicating_samples', 'detected_downloaded_samples'):
            with self.subTest(field=field):
                self.assertIs(self.evaluate({field: recent}), True)

    def test_api_error_is_not_a_verdict(self):
        self.assertIsNone(self.evaluate({'response_code': -1, 'verbose_msg': 'error'}))

    def test_old_or_single_detections_do_not_flag_the_domain(self):
        old = [{'scan_date': days_ago(40)}, {'scan_date': days_ago(50)}]
        self.assertIs(self.evaluate({'detected_urls': old}), False)
        self.assertIs(self.evaluate({'detected_urls': [{'scan_date': days_ago(1)}]}), False)

    def test_malformed_entry_is_logged_and_other_fields_still_count(self):
        recent = [{'date': days_ago(1)}, {'date': days_ago(2)}]
        response = {'detected_urls': [{'wrong': 'shape'}], 'detected_downloaded_samples': recent}
        self.assertIs(self.evaluate(response), True)
        self.log.debug.assert_called_once()


class ApplyVerdictTests(unittest.TestCase):
    def test_verdict_reaches_every_entry_and_skips_removed_ones(self):
        entry = SimpleNamespace(bad=False)
        other = SimpleNamespace(bad=False)
        hosts = {'10.0.0.2': SimpleNamespace(dns={'www.example.test': entry}),
                 '10.0.0.3': SimpleNamespace(dns={'cdn.example.test': other})}
        entries = [('10.0.0.2', 'www.example.test'),
                   ('10.0.0.2', 'already-alerted.example.test'),
                   ('10.0.0.3', 'cdn.example.test')]

        with patch.object(intel, 'homenet', SimpleNamespace(hosts=hosts)):
            Checker.apply_domain_verdict(entries, True)

        self.assertTrue(entry.bad)
        self.assertTrue(other.bad)


class DomainCacheTests(unittest.TestCase):
    QUERY = 'www.example.test'
    SLD = 'example.test'

    def setUp(self):
        self.entry = SimpleNamespace(bad=False)
        self.entries = [('10.0.0.2', self.QUERY)]
        self.lookups = {self.SLD: self.entries}
        self.checker = Checker('test')

        hosts = {'10.0.0.2': SimpleNamespace(dns={self.QUERY: self.entry})}
        for name, patcher in (('homenet', patch.object(intel, 'homenet', SimpleNamespace(hosts=hosts))),
                              ('monotonic', patch.object(intel.time, 'monotonic', return_value=1000))):
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)

    def check(self, verdict):
        with patch.object(Checker, 'eval_vt_intel_domain', return_value=verdict) as lookup:
            self.checker.check_domain(self.SLD, self.entries)
        return lookup

    def test_unknown_domain_needs_a_lookup(self):
        self.assertEqual(self.checker.get_uncached_domains(self.lookups), [self.SLD])

    def test_clean_domain_is_not_looked_up_again_until_it_expires(self):
        self.check(False)
        self.assertEqual(self.checker.get_uncached_domains(self.lookups), [])
        self.assertFalse(self.entry.bad)

        self.monotonic.return_value = 1000 + self.checker.vt_cache_ttl - 1
        self.assertEqual(self.checker.get_uncached_domains(self.lookups), [])

        self.monotonic.return_value = 1000 + self.checker.vt_cache_ttl
        self.assertEqual(self.checker.get_uncached_domains(self.lookups), [self.SLD])

    def test_failed_lookup_is_retried(self):
        self.check(None)
        self.assertEqual(self.checker.get_uncached_domains(self.lookups), [self.SLD])
        self.assertFalse(self.entry.bad)

    def test_bad_domain_flags_later_entries_without_a_lookup(self):
        self.check(True)
        self.assertTrue(self.entry.bad)

        later = SimpleNamespace(bad=False)
        self.homenet.hosts['10.0.0.3'] = SimpleNamespace(dns={'cdn.example.test': later})
        lookups = {self.SLD: [('10.0.0.3', 'cdn.example.test')]}

        self.assertEqual(self.checker.get_uncached_domains(lookups), [])
        self.assertTrue(later.bad)


class EvalFileTests(unittest.TestCase):
    def setUp(self):
        for name, patcher in (('log', patch.object(intel, 'log')),
                              ('session', patch.object(intel, 'session'))):
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)

    def evaluate(self, response):
        self.session.get.return_value.json.return_value = response
        return Checker.eval_vt_intel_file('abc123')

    def test_known_file_returns_its_report(self):
        response = {'response_code': 1, 'positives': 3, 'permalink': 'https://report.test'}
        self.assertEqual(self.evaluate(response), {'positives': 3, 'report': 'https://report.test'})

    def test_unknown_file_is_not_a_failure(self):
        self.assertIs(self.evaluate({'response_code': 0}), False)
        self.log.debug.assert_not_called()

    def test_api_errors_are_failures(self):
        for response in ({'response_code': -1, 'verbose_msg': 'error'}, {'error': 'no response code'}):
            with self.subTest(response=response):
                self.assertIsNone(self.evaluate(response))


class FileCacheTests(unittest.TestCase):
    FHASH = 'abc123'

    def setUp(self):
        self.entry = SimpleNamespace(vt_flag=False, vt_positives=0, vt_report=None)
        self.lookups = {self.FHASH: ['10.0.0.2']}
        self.checker = Checker('test')

        hosts = {'10.0.0.2': SimpleNamespace(files={self.FHASH: self.entry})}
        for name, patcher in (('homenet', patch.object(intel, 'homenet', SimpleNamespace(hosts=hosts))),
                              ('monotonic', patch.object(intel.time, 'monotonic', return_value=1000))):
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)

    def check(self, result):
        with patch.object(Checker, 'eval_vt_intel_file', return_value=result):
            self.checker.check_file(self.FHASH, self.lookups[self.FHASH])

    def test_unknown_file_is_not_looked_up_again_until_it_expires(self):
        self.check(False)
        self.assertEqual(self.checker.get_uncached_files(self.lookups), [])
        self.assertFalse(self.entry.vt_flag)

        self.monotonic.return_value = 1000 + self.checker.vt_cache_ttl - 1
        self.assertEqual(self.checker.get_uncached_files(self.lookups), [])

        self.monotonic.return_value = 1000 + self.checker.vt_cache_ttl
        self.assertEqual(self.checker.get_uncached_files(self.lookups), [self.FHASH])

    def test_failed_lookup_is_retried(self):
        self.check(None)
        self.assertEqual(self.checker.get_uncached_files(self.lookups), [self.FHASH])
        self.assertFalse(self.entry.vt_flag)

    def test_report_reaches_remaining_hosts_after_a_removed_entry(self):
        self.lookups[self.FHASH] = ['10.0.0.9', '10.0.0.2']
        self.homenet.hosts['10.0.0.9'] = SimpleNamespace(files={})

        self.check({'positives': 3, 'report': 'https://report.test'})

        self.assertTrue(self.entry.vt_flag)
        self.assertEqual(self.entry.vt_positives, 3)
        self.assertEqual(self.entry.vt_report, 'https://report.test')


if __name__ == '__main__':
    unittest.main()
