import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

# These tests don't use this package, and it isn't installed in the CI job.
with patch.dict(sys.modules, {'requests': MagicMock()}):
    from lib import alerts

from lib.objects import DNSRequest, HostAlertTemplate

HOST = '10.0.0.2'


def lookup(query, category, ts=100.0):
    dns = DNSRequest()
    dns.query = query
    dns.category = category
    dns.bad = True
    dns.ts = ts
    return dns


class AlertTestCase(unittest.TestCase):
    def setUp(self):
        self.host = SimpleNamespace(dns={}, alerts=[], hostname='h', mac='m', vendor='v', os_family=[],
                                    device_family=[])
        self.homenet = SimpleNamespace(hosts={HOST: self.host})
        for name, patcher in (('homenet_patch', patch.object(alerts, 'homenet', self.homenet)),
                              ('add_alert', patch.object(alerts.utils, 'add_alert_to_db', return_value=7))):
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)

    def saved_alert(self):
        return self.add_alert.call_args[0][0]


class RoutingTests(unittest.TestCase):
    def test_categories_are_split_between_immediate_and_bundled(self):
        for category in ('malware', 'ransomware', 'phishing', 'fraud', 'scam', 'abuse'):
            with self.subTest(category=category):
                self.assertTrue(alerts.is_immediate(lookup('a.test', category)))
                self.assertFalse(alerts.is_bundled(lookup('a.test', category)))
        for category in ('crypto', 'drugs', 'gambling', 'vaping'):
            with self.subTest(category=category):
                self.assertFalse(alerts.is_immediate(lookup('a.test', category)))
                self.assertTrue(alerts.is_bundled(lookup('a.test', category)))

    def test_virustotal_hits_have_no_category_and_are_not_bundled(self):
        self.assertFalse(alerts.is_bundled(lookup('a.test', None)))

    def test_every_category_has_its_own_description(self):
        categories = alerts.IMMEDIATE_CATEGORIES + ('crypto', 'drugs', 'gambling', 'vaping')
        self.assertEqual(set(alerts.CATEGORY_DESCRIPTIONS), set(categories))
        self.assertEqual(len(set(alerts.CATEGORY_DESCRIPTIONS.values())), len(categories))


class ImmediateAlertTests(AlertTestCase):
    def test_alert_carries_its_category(self):
        self.host.dns['bad.test'] = lookup('bad.test', 'phishing')

        alerts.create_bad_domain_alert(HOST, 'bad.test', 500)

        alert = self.saved_alert()
        self.assertEqual(alert[1], 'phishing')
        self.assertEqual(alert[6], 'Phishing')
        self.assertEqual(alert[8], 'Category: phishing|bad.test')
        self.assertIn(alerts.CATEGORY_DESCRIPTIONS['phishing'], alert[10])
        self.assertEqual(self.host.alerts, [7])

    def test_virustotal_hit_stays_a_malware_alert(self):
        self.host.dns['bad.test'] = lookup('bad.test', None)

        alerts.create_bad_domain_alert(HOST, 'bad.test', 500)

        self.assertEqual(self.saved_alert()[6], 'Malware')
        self.assertEqual(self.saved_alert()[8], 'bad.test')


class BundledAlertTests(AlertTestCase):
    def setUp(self):
        super().setUp()
        self.hourly = alerts.HourlyAlerts('test')
        self.hourly.ctime = 9000

    def test_device_gets_one_alert_covering_all_its_categories(self):
        self.host.dns['v.test'] = lookup('v.test', 'vaping', ts=300.0)
        self.host.dns['g.test'] = lookup('g.test', 'gambling', ts=200.0)

        self.hourly.create_bundled_domain_alert(HOST)

        self.add_alert.assert_called_once()
        alert = self.saved_alert()
        self.assertEqual(alert[1], 'bundled_domains')
        self.assertEqual(alert[2], 200)
        self.assertEqual(alert[3], 9000)
        self.assertEqual(alert[6], 'Gambling, Vaping')
        self.assertEqual(alert[8], 'Gambling: g.test|Vaping: v.test')
        for category in ('gambling', 'vaping'):
            self.assertIn(alerts.CATEGORY_DESCRIPTIONS[category], alert[10])

    def test_nothing_is_sent_without_new_bundled_lookups(self):
        self.host.dns['p.test'] = lookup('p.test', 'phishing')
        self.host.dns['clean.test'] = lookup('clean.test', 'gambling')
        self.host.dns['clean.test'].bad = False

        self.hourly.create_bundled_domain_alert(HOST)

        self.add_alert.assert_not_called()

    def test_a_domain_is_only_bundled_once(self):
        self.host.dns['g.test'] = lookup('g.test', 'gambling')

        self.hourly.create_bundled_domain_alert(HOST)
        self.hourly.create_bundled_domain_alert(HOST)

        self.add_alert.assert_called_once()
        self.assertIn('g.test', self.host.dns)

    def test_failed_save_leaves_domains_for_the_next_hour(self):
        self.host.dns['g.test'] = lookup('g.test', 'gambling')
        self.add_alert.side_effect = RuntimeError('database is locked')

        with self.assertRaises(RuntimeError):
            self.hourly.create_bundled_domain_alert(HOST)

        self.assertFalse(self.host.dns['g.test'].bundled)


class EmailTemplateTests(AlertTestCase):
    def render(self, threat):
        alert = [1, 'x', 1, 1, 0, 0, threat, HOST, 'Category: x|bad.test', 0, 'Text for this category', 'ref']
        template = HostAlertTemplate(self.homenet, alert)
        template.create_body()
        return template

    def test_subject_and_body_name_the_category(self):
        template = self.render('Gambling')
        self.assertEqual(template.subject, 'A Gambling alert was reported for host ' + HOST)
        self.assertIn('reported a Gambling alert', template.body)
        self.assertIn('Description: Text for this category', template.body)

    def test_categories_starting_with_a_vowel_read_correctly(self):
        template = self.render('Abuse')
        self.assertEqual(template.subject, 'An Abuse alert was reported for host ' + HOST)
        self.assertIn('reported an Abuse alert', template.body)


if __name__ == '__main__':
    unittest.main()
