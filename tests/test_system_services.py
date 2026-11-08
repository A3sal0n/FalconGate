import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from lib import system_health

FALCONGATE = system_health.SERVICES[0]
ZEEK = system_health.SERVICES[1]
ACTIVE = {'LoadState': 'loaded', 'ActiveState': 'active', 'SubState': 'running', 'NRestarts': '0',
          'ActiveEnterTimestamp': 'Tue 2023-11-14 22:13:20 UTC', 'InactiveExitTimestamp': 'Tue 2023-11-14 22:13:19 UTC'}


def journal_line(message, priority=6, timestamp=1700000000):
    return json.dumps({'MESSAGE': message, 'PRIORITY': str(priority), '__REALTIME_TIMESTAMP': str(timestamp * 1000000)})


class SystemServicesTests(unittest.TestCase):
    def errors_from(self, *lines):
        with patch.object(system_health, 'run_command', return_value='\n'.join(lines)):
            return system_health.get_unit_errors('falcongate.service', 1700000000)

    def test_parse_systemd_time(self):
        self.assertEqual(system_health.parse_systemd_time('Tue 2023-11-14 22:13:20 UTC'), 1700000000)
        for value in ('', 'n/a', None, 'not a time'):
            self.assertIsNone(system_health.parse_systemd_time(value))

    def test_states(self):
        cases = [({'LoadState': 'not-found', 'ActiveState': 'inactive'}, ('high', 'Not installed')),
                 ({'LoadState': 'loaded', 'ActiveState': 'active'}, ('normal', 'Running')),
                 ({'LoadState': 'loaded', 'ActiveState': 'activating'}, ('high', 'Starting')),
                 ({'LoadState': 'loaded', 'ActiveState': 'reloading'}, ('high', 'Starting')),
                 ({'LoadState': 'loaded', 'ActiveState': 'deactivating'}, ('high', 'Stopping')),
                 ({'LoadState': 'loaded', 'ActiveState': 'failed'}, ('critical', 'Failed')),
                 ({'LoadState': 'loaded', 'ActiveState': 'inactive'}, ('critical', 'Stopped'))]
        for properties, expected in cases:
            self.assertEqual(system_health.describe_state(FALCONGATE, properties), expected, properties)

    def test_active_oneshot_service_needs_its_process(self):
        properties = {'LoadState': 'loaded', 'ActiveState': 'active', 'SubState': 'exited'}
        with patch.object(system_health, 'is_process_running', return_value=False):
            self.assertEqual(system_health.describe_state(ZEEK, properties), ('critical', 'Process not running'))
        with patch.object(system_health, 'is_process_running', return_value=True):
            self.assertEqual(system_health.describe_state(ZEEK, properties), ('normal', 'Running'))

    def test_socket_activated_service_waiting_for_a_client_is_ready(self):
        properties = {'LoadState': 'loaded', 'ActiveState': 'inactive', 'TriggeredBy': 'dnscrypt-proxy.socket'}
        with patch.object(system_health, 'get_unit_properties', return_value={'ActiveState': 'active'}) as show:
            self.assertEqual(system_health.describe_state(FALCONGATE, properties), ('normal', 'Ready'))
        show.assert_called_once_with('dnscrypt-proxy.socket')
        with patch.object(system_health, 'get_unit_properties', return_value={'ActiveState': 'failed'}):
            self.assertEqual(system_health.describe_state(FALCONGATE, properties), ('critical', 'Stopped'))

    def test_find_php_fpm_unit_picks_the_newest_version(self):
        with tempfile.TemporaryDirectory() as directory:
            pattern = os.path.join(directory, '*', '')
            self.assertEqual(system_health.find_php_fpm_unit(pattern), 'php-fpm.service')
            for version in ('8.3', '8.10', '7.4', 'conf.d'):
                os.mkdir(os.path.join(directory, version))
            self.assertEqual(system_health.find_php_fpm_unit(pattern), 'php8.10-fpm.service')

    def test_is_process_running(self):
        with tempfile.TemporaryDirectory() as directory:
            os.mkdir(os.path.join(directory, '42'))
            with open(os.path.join(directory, '42', 'comm'), 'w') as comm:
                comm.write('zeek\n')
            self.assertTrue(system_health.is_process_running('zeek', directory))
            self.assertFalse(system_health.is_process_running('nginx', directory))

    def test_errors_found_by_priority_or_text(self):
        errors = self.errors_from(journal_line('segfault at 0', priority=2, timestamp=1700000005),
                                  journal_line('utils.send: FG-ERROR: No such table', timestamp=1700000004),
                                  journal_line('Traceback (most recent call last):', timestamp=1700000003),
                                  journal_line("KeyError: 'x'", timestamp=1700000002),
                                  journal_line('falcongate.service: Failed with result exit-code.', priority=4, timestamp=1700000001))
        self.assertEqual([error['message'] for error in errors],
                         ['segfault at 0', 'utils.send: FG-ERROR: No such table', 'Traceback (most recent call last):',
                          "KeyError: 'x'", 'falcongate.service: Failed with result exit-code.'])

    def test_normal_messages_are_not_errors(self):
        self.assertEqual(self.errors_from(journal_line('Started Falcongate.'),
                                          journal_line('utils.x: FG-INFO: main.py started'),
                                          journal_line('parser: FG-DEBUG: error reading the log'),
                                          journal_line('api: FG-WARN: Common base class for all exceptions'),
                                          journal_line('check finished with 0 errors'),
                                          journal_line('no errors found'),
                                          journal_line('Deactivated successfully.')), [])

    def test_repeated_errors_are_grouped_and_show_the_latest_time(self):
        errors = self.errors_from(journal_line('Connection failed', timestamp=1700000000),
                                  journal_line('Connection failed', timestamp=1700000060))
        self.assertEqual(errors, [{'time': '2023/11/14 22:14:20 UTC', 'message': 'Connection failed', 'count': 2}])

    def test_only_the_newest_errors_are_kept_and_long_ones_shortened(self):
        lines = [journal_line('error ' + str(i), timestamp=1700000000 + i) for i in range(8)]
        errors = self.errors_from(*(lines + [journal_line('error ' + 'x' * 900, timestamp=1700000100)]))
        self.assertEqual(len(errors), system_health.MAX_SERVICE_ERRORS)
        self.assertEqual(len(errors[0]['message']), system_health.MAX_ERROR_LENGTH)
        self.assertEqual(errors[1]['message'], 'error 7')

    def test_journal_oddities_are_handled(self):
        binary = json.dumps({'MESSAGE': list('error é'.encode('latin-1')), 'PRIORITY': '6', '__REALTIME_TIMESTAMP': '1700000000000000'})
        errors = self.errors_from('not json', json.dumps({'PRIORITY': '3'}), binary)
        self.assertEqual(errors[0]['message'], 'error �')

    def test_errors_are_read_from_the_last_start_attempt(self):
        with patch.object(system_health, 'get_unit_properties', return_value=ACTIVE), \
                patch.object(system_health, 'run_command', return_value='') as run:
            status = system_health.get_service_status(FALCONGATE)
        arguments = run.call_args[0][0]
        self.assertEqual(arguments[arguments.index('--since') + 1], '@1699999999')
        self.assertEqual(arguments[arguments.index('--unit') + 1], 'falcongate.service')
        self.assertEqual(status['since'], '2023/11/14 22:13:20 UTC')
        self.assertEqual((status['level'], status['label'], status['errors_available']), ('normal', 'Running', True))

    def test_stopped_service_has_no_since_time(self):
        properties = dict(ACTIVE, ActiveState='failed', NRestarts='3')
        with patch.object(system_health, 'get_unit_properties', return_value=properties), \
                patch.object(system_health, 'run_command', return_value=journal_line('boom', priority=3)):
            status = system_health.get_service_status(FALCONGATE)
        self.assertIsNone(status['since'])
        self.assertEqual(status['restarts'], 3)
        self.assertEqual(status['errors'][0]['message'], 'boom')

    def test_missing_tools_are_reported_without_failing(self):
        with patch.object(system_health, 'run_command', side_effect=FileNotFoundError('systemctl')):
            status = system_health.get_service_status(FALCONGATE)
        self.assertEqual((status['level'], status['label'], status['errors_available']), ('high', 'Unknown', False))

    def test_journal_timeout_keeps_the_service_state(self):
        with patch.object(system_health, 'get_unit_properties', return_value=ACTIVE), \
                patch.object(system_health, 'run_command', side_effect=subprocess.TimeoutExpired('journalctl', 8)):
            status = system_health.get_service_status(FALCONGATE)
        self.assertEqual((status['label'], status['errors_available']), ('Running', False))

    def test_all_services_are_reported(self):
        with patch.object(system_health, 'get_unit_properties', return_value=ACTIVE), \
                patch.object(system_health, 'run_command', return_value=''), \
                patch.object(system_health, 'is_process_running', return_value=True):
            result = system_health.get_services_status()
        self.assertEqual([service['name'] for service in result['services']],
                         ['Falcongate', 'Zeek', 'dnsmasq', 'dnscrypt-proxy', 'nginx', 'PHP-FPM', 'Firewall'])
        self.assertTrue(json.dumps(result))


if __name__ == '__main__':
    unittest.main()
