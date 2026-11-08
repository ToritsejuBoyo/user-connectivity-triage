#!/usr/bin/env python3
"""
Synthetic Fixture Generator for user-connectivity-triage.
Generates 7 distinct network diagnostic scenarios representing common L1 helpdesk complaints
using 100% synthetic RFC 5737 / RFC 3849 test IP blocks and obvious mock identifiers.
Complies with Rule 7 (Zero-Emoji) and Rule 9 (Obvious Synthetic Mock Identifiers).
"""

import json
from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
FIXTURES_DIR.mkdir(parents=True, exist_ok=True)


def create_healthy_fixture():
    data = {
        "timestamp": "2026-11-08T14:00:00Z",
        "hostname": "synthetic-laptop-01.corp.example.com",
        "os": "Windows 11 Enterprise (23H2)",
        "airplane_mode": False,
        "adapters": [
            {
                "name": "Wi-Fi",
                "type": "Wireless80211",
                "status": "Up",
                "mac_address": "00:11:22:33:44:55",
                "ipv4_addresses": ["192.0.2.145"],
                "subnet_mask": "255.255.255.0",
                "ipv6_addresses": ["2001:db8::145"],
                "default_gateways": ["192.0.2.1"],
                "dns_servers": ["192.0.2.10", "192.0.2.11"],
                "dhcp_enabled": True,
                "dhcp_lease_obtained": "2026-11-08T08:00:00Z",
                "dhcp_lease_expires": "2026-11-08T16:00:00Z",
                "dhcp_server": "192.0.2.1"
            }
        ],
        "wifi": {
            "connected": True,
            "ssid": "Corp-Secure-WiFi",
            "bssid": "00:11:22:aa:bb:cc",
            "signal_percent": 88,
            "radio_type": "802.11ax",
            "channel": 36,
            "authentication": "WPA3-Enterprise",
            "cipher": "CCMP"
        },
        "gateway_reachability": {
            "gateway_ip": "192.0.2.1",
            "packets_sent": 4,
            "packets_received": 4,
            "packet_loss_percent": 0.0,
            "avg_rtt_ms": 3.2
        },
        "dns_tests": [
            {
                "target": "gateway.local",
                "server": "192.0.2.10",
                "resolved": True,
                "resolved_ips": ["192.0.2.1"],
                "rtt_ms": 2.1
            },
            {
                "target": "portal.corp.example.com",
                "server": "192.0.2.10",
                "resolved": True,
                "resolved_ips": ["192.0.2.50"],
                "rtt_ms": 4.5
            },
            {
                "target": "dns.google",
                "server": "192.0.2.10",
                "resolved": True,
                "resolved_ips": ["8.8.8.8", "8.8.4.4"],
                "rtt_ms": 14.2
            }
        ],
        "http_probe": {
            "url": "http://www.msftconnecttest.com/connecttest.txt",
            "status_code": 200,
            "response_body_snippet": "Microsoft Connect Test",
            "is_captive_portal": False,
            "redirect_url": None
        },
        "vpn": {
            "client_installed": "Cisco AnyConnect",
            "connected": False,
            "adapter_name": None,
            "assigned_ip": None,
            "tunnel_routes": []
        }
    }
    with open(FIXTURES_DIR / "fixture-healthy-enterprise-lan.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def create_apipa_fixture():
    data = {
        "timestamp": "2026-11-08T14:05:00Z",
        "hostname": "synthetic-laptop-02.corp.example.com",
        "os": "Windows 11 Enterprise (23H2)",
        "airplane_mode": False,
        "adapters": [
            {
                "name": "Ethernet",
                "type": "Ethernet",
                "status": "Up",
                "mac_address": "00:11:22:33:44:66",
                "ipv4_addresses": ["169.254.45.120"],
                "subnet_mask": "255.255.0.0",
                "ipv6_addresses": [],
                "default_gateways": [],
                "dns_servers": [],
                "dhcp_enabled": True,
                "dhcp_lease_obtained": None,
                "dhcp_lease_expires": None,
                "dhcp_server": None
            }
        ],
        "wifi": {
            "connected": False,
            "ssid": None,
            "bssid": None,
            "signal_percent": 0,
            "radio_type": None,
            "channel": 0,
            "authentication": None,
            "cipher": None
        },
        "gateway_reachability": {
            "gateway_ip": None,
            "packets_sent": 0,
            "packets_received": 0,
            "packet_loss_percent": 100.0,
            "avg_rtt_ms": None
        },
        "dns_tests": [
            {
                "target": "dns.google",
                "server": None,
                "resolved": False,
                "resolved_ips": [],
                "rtt_ms": None,
                "error": "No DNS servers configured"
            }
        ],
        "http_probe": {
            "url": "http://www.msftconnecttest.com/connecttest.txt",
            "status_code": 0,
            "response_body_snippet": None,
            "is_captive_portal": False,
            "redirect_url": None,
            "error": "Network unreachable"
        },
        "vpn": {
            "client_installed": "None",
            "connected": False,
            "adapter_name": None,
            "assigned_ip": None,
            "tunnel_routes": []
        }
    }
    with open(FIXTURES_DIR / "fixture-apipa-dhcp-failure.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def create_wifi_weak_fixture():
    data = {
        "timestamp": "2026-11-08T14:10:00Z",
        "hostname": "synthetic-laptop-03.corp.example.com",
        "os": "Windows 11 Enterprise (23H2)",
        "airplane_mode": False,
        "adapters": [
            {
                "name": "Wi-Fi",
                "type": "Wireless80211",
                "status": "Up",
                "mac_address": "00:11:22:33:44:77",
                "ipv4_addresses": ["192.0.2.188"],
                "subnet_mask": "255.255.255.0",
                "ipv6_addresses": [],
                "default_gateways": ["192.0.2.1"],
                "dns_servers": ["192.0.2.10"],
                "dhcp_enabled": True,
                "dhcp_lease_obtained": "2026-11-08T08:00:00Z",
                "dhcp_lease_expires": "2026-11-08T16:00:00Z",
                "dhcp_server": "192.0.2.1"
            }
        ],
        "wifi": {
            "connected": True,
            "ssid": "Corp-Secure-WiFi",
            "bssid": "00:11:22:aa:bb:99",
            "signal_percent": 12,
            "radio_type": "802.11n",
            "channel": 1,
            "authentication": "WPA2-Enterprise",
            "cipher": "CCMP"
        },
        "gateway_reachability": {
            "gateway_ip": "192.0.2.1",
            "packets_sent": 10,
            "packets_received": 3,
            "packet_loss_percent": 70.0,
            "avg_rtt_ms": 420.5
        },
        "dns_tests": [
            {
                "target": "portal.corp.example.com",
                "server": "192.0.2.10",
                "resolved": False,
                "resolved_ips": [],
                "rtt_ms": None,
                "error": "Query timed out"
            }
        ],
        "http_probe": {
            "url": "http://www.msftconnecttest.com/connecttest.txt",
            "status_code": 0,
            "response_body_snippet": None,
            "is_captive_portal": False,
            "redirect_url": None,
            "error": "Connection timed out"
        },
        "vpn": {
            "client_installed": "None",
            "connected": False,
            "adapter_name": None,
            "assigned_ip": None,
            "tunnel_routes": []
        }
    }
    with open(FIXTURES_DIR / "fixture-wifi-weak-signal.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def create_gateway_unreachable_fixture():
    data = {
        "timestamp": "2026-11-08T14:15:00Z",
        "hostname": "synthetic-laptop-04.corp.example.com",
        "os": "Windows 11 Enterprise (23H2)",
        "airplane_mode": False,
        "adapters": [
            {
                "name": "Ethernet",
                "type": "Ethernet",
                "status": "Up",
                "mac_address": "00:11:22:33:44:88",
                "ipv4_addresses": ["192.0.2.210"],
                "subnet_mask": "255.255.255.0",
                "ipv6_addresses": [],
                "default_gateways": ["192.0.2.1"],
                "dns_servers": ["192.0.2.10"],
                "dhcp_enabled": False,
                "dhcp_lease_obtained": None,
                "dhcp_lease_expires": None,
                "dhcp_server": None
            }
        ],
        "wifi": {
            "connected": False,
            "ssid": None,
            "bssid": None,
            "signal_percent": 0,
            "radio_type": None,
            "channel": 0,
            "authentication": None,
            "cipher": None
        },
        "gateway_reachability": {
            "gateway_ip": "192.0.2.1",
            "packets_sent": 4,
            "packets_received": 0,
            "packet_loss_percent": 100.0,
            "avg_rtt_ms": None
        },
        "dns_tests": [
            {
                "target": "dns.google",
                "server": "192.0.2.10",
                "resolved": False,
                "resolved_ips": [],
                "rtt_ms": None,
                "error": "Destination host unreachable"
            }
        ],
        "http_probe": {
            "url": "http://www.msftconnecttest.com/connecttest.txt",
            "status_code": 0,
            "response_body_snippet": None,
            "is_captive_portal": False,
            "redirect_url": None,
            "error": "Host unreachable"
        },
        "vpn": {
            "client_installed": "None",
            "connected": False,
            "adapter_name": None,
            "assigned_ip": None,
            "tunnel_routes": []
        }
    }
    with open(FIXTURES_DIR / "fixture-gateway-unreachable.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def create_dns_failure_fixture():
    data = {
        "timestamp": "2026-11-08T14:20:00Z",
        "hostname": "synthetic-laptop-05.corp.example.com",
        "os": "Windows 11 Enterprise (23H2)",
        "airplane_mode": False,
        "adapters": [
            {
                "name": "Wi-Fi",
                "type": "Wireless80211",
                "status": "Up",
                "mac_address": "00:11:22:33:44:99",
                "ipv4_addresses": ["192.0.2.75"],
                "subnet_mask": "255.255.255.0",
                "ipv6_addresses": [],
                "default_gateways": ["192.0.2.1"],
                "dns_servers": ["192.0.2.253"],
                "dhcp_enabled": True,
                "dhcp_lease_obtained": "2026-11-08T08:00:00Z",
                "dhcp_lease_expires": "2026-11-08T16:00:00Z",
                "dhcp_server": "192.0.2.1"
            }
        ],
        "wifi": {
            "connected": True,
            "ssid": "Corp-Secure-WiFi",
            "bssid": "00:11:22:aa:bb:cc",
            "signal_percent": 90,
            "radio_type": "802.11ax",
            "channel": 40,
            "authentication": "WPA3-Enterprise",
            "cipher": "CCMP"
        },
        "gateway_reachability": {
            "gateway_ip": "192.0.2.1",
            "packets_sent": 4,
            "packets_received": 4,
            "packet_loss_percent": 0.0,
            "avg_rtt_ms": 2.5
        },
        "dns_tests": [
            {
                "target": "portal.corp.example.com",
                "server": "192.0.2.253",
                "resolved": False,
                "resolved_ips": [],
                "rtt_ms": None,
                "error": "Server failure (SERVFAIL) / Timeout"
            },
            {
                "target": "dns.google",
                "server": "192.0.2.253",
                "resolved": False,
                "resolved_ips": [],
                "rtt_ms": None,
                "error": "Server failure (SERVFAIL) / Timeout"
            }
        ],
        "http_probe": {
            "url": "http://www.msftconnecttest.com/connecttest.txt",
            "status_code": 0,
            "response_body_snippet": None,
            "is_captive_portal": False,
            "redirect_url": None,
            "error": "Could not resolve host: www.msftconnecttest.com"
        },
        "vpn": {
            "client_installed": "None",
            "connected": False,
            "adapter_name": None,
            "assigned_ip": None,
            "tunnel_routes": []
        }
    }
    with open(FIXTURES_DIR / "fixture-dns-resolution-timeout.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def create_captive_portal_fixture():
    data = {
        "timestamp": "2026-11-08T14:25:00Z",
        "hostname": "synthetic-laptop-06.corp.example.com",
        "os": "Windows 11 Enterprise (23H2)",
        "airplane_mode": False,
        "adapters": [
            {
                "name": "Wi-Fi",
                "type": "Wireless80211",
                "status": "Up",
                "mac_address": "00:11:22:33:44:aa",
                "ipv4_addresses": ["192.0.2.222"],
                "subnet_mask": "255.255.255.0",
                "ipv6_addresses": [],
                "default_gateways": ["192.0.2.1"],
                "dns_servers": ["192.0.2.1"],
                "dhcp_enabled": True,
                "dhcp_lease_obtained": "2026-11-08T14:20:00Z",
                "dhcp_lease_expires": "2026-11-08T15:20:00Z",
                "dhcp_server": "192.0.2.1"
            }
        ],
        "wifi": {
            "connected": True,
            "ssid": "Hotel-Guest-WiFi",
            "bssid": "00:11:22:bb:cc:dd",
            "signal_percent": 82,
            "radio_type": "802.11ac",
            "channel": 6,
            "authentication": "Open",
            "cipher": "None"
        },
        "gateway_reachability": {
            "gateway_ip": "192.0.2.1",
            "packets_sent": 4,
            "packets_received": 4,
            "packet_loss_percent": 0.0,
            "avg_rtt_ms": 4.1
        },
        "dns_tests": [
            {
                "target": "login.hotelportal.example",
                "server": "192.0.2.1",
                "resolved": True,
                "resolved_ips": ["192.0.2.1"],
                "rtt_ms": 3.0
            },
            {
                "target": "dns.google",
                "server": "192.0.2.1",
                "resolved": True,
                "resolved_ips": ["192.0.2.1"],
                "rtt_ms": 2.9
            }
        ],
        "http_probe": {
            "url": "http://www.msftconnecttest.com/connecttest.txt",
            "status_code": 302,
            "response_body_snippet": "<html><body>Redirecting to login portal...</body></html>",
            "is_captive_portal": True,
            "redirect_url": "https://wifi.hotelportal.example/login?mac=00-11-22-33-44-aa"
        },
        "vpn": {
            "client_installed": "Cisco AnyConnect",
            "connected": False,
            "adapter_name": None,
            "assigned_ip": None,
            "tunnel_routes": []
        }
    }
    with open(FIXTURES_DIR / "fixture-captive-portal-hotel.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def create_vpn_split_tunnel_fixture():
    data = {
        "timestamp": "2026-11-08T14:30:00Z",
        "hostname": "synthetic-laptop-07.corp.example.com",
        "os": "Windows 11 Enterprise (23H2)",
        "airplane_mode": False,
        "adapters": [
            {
                "name": "Wi-Fi",
                "type": "Wireless80211",
                "status": "Up",
                "mac_address": "00:11:22:33:44:bb",
                "ipv4_addresses": ["192.0.2.133"],
                "subnet_mask": "255.255.255.0",
                "ipv6_addresses": [],
                "default_gateways": ["192.0.2.1"],
                "dns_servers": ["1.1.1.1"],
                "dhcp_enabled": True,
                "dhcp_lease_obtained": "2026-11-08T08:00:00Z",
                "dhcp_lease_expires": "2026-11-08T16:00:00Z",
                "dhcp_server": "192.0.2.1"
            },
            {
                "name": "Palo Alto GlobalProtect Virtual Network Adapter",
                "type": "VirtualTunnel",
                "status": "Up",
                "mac_address": "00:11:22:99:88:77",
                "ipv4_addresses": ["198.51.100.45"],
                "subnet_mask": "255.255.255.255",
                "ipv6_addresses": [],
                "default_gateways": [],
                "dns_servers": ["198.51.100.10"],
                "dhcp_enabled": False,
                "dhcp_lease_obtained": None,
                "dhcp_lease_expires": None,
                "dhcp_server": None
            }
        ],
        "wifi": {
            "connected": True,
            "ssid": "Home-Network-5G",
            "bssid": "00:11:22:cc:dd:ee",
            "signal_percent": 94,
            "radio_type": "802.11ax",
            "channel": 149,
            "authentication": "WPA3-Personal",
            "cipher": "CCMP"
        },
        "gateway_reachability": {
            "gateway_ip": "192.0.2.1",
            "packets_sent": 4,
            "packets_received": 4,
            "packet_loss_percent": 0.0,
            "avg_rtt_ms": 3.8
        },
        "dns_tests": [
            {
                "target": "intranet.corp.example.com",
                "server": "1.1.1.1",
                "resolved": False,
                "resolved_ips": [],
                "rtt_ms": None,
                "error": "NXDOMAIN (Non-Existent Domain returned by public DNS)"
            },
            {
                "target": "dns.google",
                "server": "1.1.1.1",
                "resolved": True,
                "resolved_ips": ["8.8.8.8"],
                "rtt_ms": 11.4
            }
        ],
        "http_probe": {
            "url": "http://www.msftconnecttest.com/connecttest.txt",
            "status_code": 200,
            "response_body_snippet": "Microsoft Connect Test",
            "is_captive_portal": False,
            "redirect_url": None
        },
        "vpn": {
            "client_installed": "Palo Alto GlobalProtect",
            "connected": True,
            "adapter_name": "Palo Alto GlobalProtect Virtual Network Adapter",
            "assigned_ip": "198.51.100.45",
            "tunnel_routes": ["198.51.100.0/24"],
            "missing_corporate_routes": ["10.0.0.0/8", "172.16.0.0/12"],
            "split_dns_leak": True
        }
    }
    with open(FIXTURES_DIR / "fixture-vpn-split-tunnel-leak.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


if __name__ == "__main__":
    create_healthy_fixture()
    create_apipa_fixture()
    create_wifi_weak_fixture()
    create_gateway_unreachable_fixture()
    create_dns_failure_fixture()
    create_captive_portal_fixture()
    create_vpn_split_tunnel_fixture()
    print("Generated all 7 synthetic user connectivity fixtures successfully.")
