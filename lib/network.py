import ipaddress
import json
import subprocess


def get_interface_config(interface):
    result = subprocess.run(
        ["ip", "-j", "address", "show", "dev", interface],
        check=True,
        capture_output=True,
        text=True,
    )
    interfaces = json.loads(result.stdout)
    if not interfaces:
        raise RuntimeError("No network interface data returned for {}".format(interface))

    details = interfaces[0]
    ipv4_address = next(
        (
            address
            for address in details.get("addr_info", [])
            if address.get("family") == "inet"
        ),
        None,
    )
    if ipv4_address is None:
        raise RuntimeError("No IPv4 address found for {}".format(interface))

    network = ipaddress.IPv4Interface(
        "{}/{}".format(ipv4_address["local"], ipv4_address["prefixlen"])
    )
    mac_address = details.get("address")
    if not mac_address:
        raise RuntimeError("No MAC address found for {}".format(interface))

    return {
        "ip": str(network.ip),
        "netmask": str(network.network.netmask),
        "network": str(network.network),
        "mac": mac_address,
    }


def get_default_gateway():
    result = subprocess.run(
        ["ip", "-j", "route", "show", "default"],
        check=True,
        capture_output=True,
        text=True,
    )
    routes = json.loads(result.stdout)
    route = next((route for route in routes if route.get("gateway")), None)
    if route is None:
        raise RuntimeError("No default IPv4 gateway found")
    return route["gateway"]
