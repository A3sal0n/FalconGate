import json
import unittest
from unittest.mock import patch

from lib.network import get_default_gateway, get_interface_config


class NetworkTests(unittest.TestCase):
    @patch("lib.network.subprocess.run")
    def test_get_interface_config_returns_ipv4_network_and_mac(self, run):
        run.return_value.stdout = json.dumps(
            [
                {
                    "address": "00:11:22:33:44:55",
                    "addr_info": [
                        {
                            "family": "inet",
                            "local": "192.0.2.10",
                            "prefixlen": 24,
                        }
                    ],
                }
            ]
        )

        self.assertEqual(
            get_interface_config("eth0"),
            {
                "ip": "192.0.2.10",
                "netmask": "255.255.255.0",
                "network": "192.0.2.0/24",
                "mac": "00:11:22:33:44:55",
            },
        )
        run.assert_called_once_with(
            ["ip", "-j", "address", "show", "dev", "eth0"],
            check=True,
            capture_output=True,
            text=True,
        )

    @patch("lib.network.subprocess.run")
    def test_get_interface_config_requires_an_ipv4_address(self, run):
        run.return_value.stdout = json.dumps(
            [{"address": "00:11:22:33:44:55", "addr_info": []}]
        )

        with self.assertRaisesRegex(RuntimeError, "No IPv4 address"):
            get_interface_config("eth0")

    @patch("lib.network.subprocess.run")
    def test_get_default_gateway_uses_first_ipv4_default_route(self, run):
        run.return_value.stdout = json.dumps(
            [
                {"dst": "default", "dev": "eth0"},
                {"dst": "default", "gateway": "192.0.2.1", "dev": "eth0"},
            ]
        )

        self.assertEqual(get_default_gateway(), "192.0.2.1")

    @patch("lib.network.subprocess.run")
    def test_get_default_gateway_reports_missing_route(self, run):
        run.return_value.stdout = "[]"

        with self.assertRaisesRegex(RuntimeError, "No default IPv4 gateway"):
            get_default_gateway()


if __name__ == "__main__":
    unittest.main()
