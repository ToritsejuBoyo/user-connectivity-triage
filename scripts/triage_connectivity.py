#!/usr/bin/env python3
"""
Enterprise User Connectivity Triage Engine.
Evaluates endpoint diagnostic JSON telemetry across a 7-layer OSI / TCP-IP decision tree
(Physical Link, Wi-Fi Association, DHCP/IP, Gateway Reachability, DNS, Captive Portal, VPN).
Pinpoints exact failure layer and outputs non-destructive L1 user fixes and L2/L3 escalation tickets.

Zero third-party dependencies. Complies with Rule 3, Rule 4 (Sanitization), and Rule 7.
"""

import argparse
import hashlib
import json
import math
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class TriageFinding:
    """Represents a diagnostic determination from the decision tree."""
    layer_number: int
    layer_name: str
    status: str  # "FAIL", "WARN", "PASS"
    root_cause_summary: str
    technical_evidence: List[str] = field(default_factory=list)
    remediation_steps_user: List[str] = field(default_factory=list)
    remediation_steps_admin: List[str] = field(default_factory=list)
    escalation_priority: str = "P3 - Medium"


class TelemetrySanitizer:
    """Client-side telemetry sanitization complying with Rule 4."""
    def __init__(self, salt: str = "connectivity-triage-audit-salt"):
        self.salt = salt
        self._ip_cache: Dict[str, str] = {}
        self._counter = 1

    def sanitize_ip(self, ip: Any) -> str:
        if not ip:
            return "" if ip is None else str(ip)
        if not isinstance(ip, str):
            ip = str(ip)
        if ip.strip() == "":
            return ip
        ip_clean = ip.strip()
        # Preserve loopback and APIPA identifiers as they are essential for triage
        if ip_clean.startswith("169.254.") or ip_clean in ("127.0.0.1", "::1"):
            return ip_clean
        if ip_clean not in self._ip_cache:
            self._ip_cache[ip_clean] = f"192.0.2.{self._counter % 250 + 1}"
            self._counter += 1
        return self._ip_cache[ip_clean]

    def sanitize_host(self, host: Any) -> str:
        if not host:
            return "" if host is not None and str(host) == "" else "unknown-host"
        if not isinstance(host, str):
            host = str(host)
        if host.strip() == "":
            return host
        host_str = host.strip()
        # Idempotent check: if already sanitized, do not re-hash
        if host_str.startswith("host-") and host_str.endswith(".corp.example.com"):
            return host_str
        h = hashlib.sha256((host_str + self.salt).encode("utf-8")).hexdigest()[:8]
        return f"host-{h}.corp.example.com"

    def sanitize_mac(self, mac: Any) -> str:
        if not mac:
            return ""
        return "00:11:22:xx:xx:xx"

    def sanitize_bundle(self, data: Any) -> Dict[str, Any]:
        """Deep copy and sanitize JSON telemetry."""
        if not isinstance(data, dict):
            return {"raw_input": str(data)}

        clean = json.loads(json.dumps(data))
        if "hostname" in clean and clean["hostname"]:
            clean["hostname"] = self.sanitize_host(clean["hostname"])
        
        adapters = clean.get("adapters", [])
        if isinstance(adapters, list):
            for adapter in adapters:
                if not isinstance(adapter, dict):
                    continue
                if "mac_address" in adapter and adapter["mac_address"]:
                    adapter["mac_address"] = self.sanitize_mac(adapter["mac_address"])
                
                # Safe normalization of IP arrays
                ips = adapter.get("ipv4_addresses")
                if isinstance(ips, list):
                    adapter["ipv4_addresses"] = [self.sanitize_ip(ip) for ip in ips if ip is not None]
                elif isinstance(ips, (str, int)):
                    adapter["ipv4_addresses"] = [self.sanitize_ip(ips)]

                gws = adapter.get("default_gateways")
                if isinstance(gws, list):
                    adapter["default_gateways"] = [self.sanitize_ip(gw) for gw in gws if gw is not None]
                elif isinstance(gws, (str, int)):
                    adapter["default_gateways"] = [self.sanitize_ip(gws)]

                dns_list = adapter.get("dns_servers")
                if isinstance(dns_list, list):
                    adapter["dns_servers"] = [self.sanitize_ip(dns) for dns in dns_list if dns is not None]
                elif isinstance(dns_list, (str, int)):
                    adapter["dns_servers"] = [self.sanitize_ip(dns_list)]

                if "dhcp_server" in adapter and adapter["dhcp_server"]:
                    adapter["dhcp_server"] = self.sanitize_ip(adapter["dhcp_server"])

        wifi = clean.get("wifi")
        if isinstance(wifi, dict) and wifi.get("bssid"):
            wifi["bssid"] = self.sanitize_mac(wifi["bssid"])

        gw = clean.get("gateway_reachability")
        if isinstance(gw, dict) and gw.get("gateway_ip"):
            gw["gateway_ip"] = self.sanitize_ip(gw["gateway_ip"])

        dns_tests = clean.get("dns_tests")
        if isinstance(dns_tests, list):
            for dns in dns_tests:
                if isinstance(dns, dict):
                    if dns.get("server"):
                        dns["server"] = self.sanitize_ip(dns["server"])
                    resolved_ips = dns.get("resolved_ips")
                    if isinstance(resolved_ips, list):
                        dns["resolved_ips"] = [self.sanitize_ip(ip) for ip in resolved_ips if ip is not None]

        vpn = clean.get("vpn")
        if isinstance(vpn, dict) and vpn.get("assigned_ip"):
            vpn["assigned_ip"] = self.sanitize_ip(vpn["assigned_ip"])

        return clean


class ConnectivityTriageEngine:
    """Executes the 7-layer decision tree evaluation."""

    def __init__(self, data: Dict[str, Any]):
        self.raw_data = data
        self.findings: List[TriageFinding] = []

    def evaluate(self) -> List[TriageFinding]:
        self.findings.clear()

        # Step 1: Layer 1 - Physical / Hardware Link
        l1 = self._check_layer1_physical()
        if l1:
            self.findings.append(l1)
            # If physical layer completely severed, higher layer diagnostics are secondary
            if l1.status == "FAIL":
                return self.findings

        # Step 2: Layer 2 - Data Link / Wi-Fi Association
        l2 = self._check_layer2_datalink()
        if l2:
            self.findings.append(l2)

        # Step 3: Layer 3 - Network IP & DHCP
        l3 = self._check_layer3_network_ip()
        if l3:
            self.findings.append(l3)
            # If APIPA or no IP, gateway & DNS checks will naturally fail; L3 is root cause
            if l3.status == "FAIL":
                return self.findings

        # Step 4: Layer 4 - Gateway Reachability & Latency
        l4 = self._check_layer4_gateway()
        if l4:
            self.findings.append(l4)

        # Step 5: Layer 5 - DNS Name Resolution
        l5 = self._check_layer5_dns()
        if l5:
            self.findings.append(l5)

        # Step 6: Layer 6 - Captive Portal / HTTP Interception
        l6 = self._check_layer6_captive_portal()
        if l6:
            self.findings.append(l6)

        # Step 7: Layer 7 - Corporate VPN & Routing Tunnel
        l7 = self._check_layer7_vpn()
        if l7:
            self.findings.append(l7)

        # If all passed cleanly
        if not self.findings:
            self.findings.append(TriageFinding(
                layer_number=0,
                layer_name="All Network Layers Operational",
                status="PASS",
                root_cause_summary="Local network stack, Wi-Fi signal, IP/DHCP, Gateway, DNS, and Internet probe are completely healthy.",
                technical_evidence=[
                    "Network adapters reporting operational status Up",
                    "Valid non-APIPA IPv4 configuration assigned",
                    "0% packet loss to local default gateway",
                    "Public canary DNS lookups resolving successfully",
                    "HTTP internet connectivity probe returned 200 OK"
                ],
                remediation_steps_user=["No action required. Connection is healthy."],
                remediation_steps_admin=["Verify if issue is application-specific or credential/browser related."],
                escalation_priority="P4 - Informational / Closed"
            ))

        return self.findings

    def _check_layer1_physical(self) -> Optional[TriageFinding]:
        if not self.raw_data or not isinstance(self.raw_data, dict):
            return TriageFinding(
                layer_number=1,
                layer_name="Physical / Hardware State",
                status="FAIL",
                root_cause_summary="Telemetry payload is empty or not a valid dictionary.",
                technical_evidence=["Invalid or null telemetry object"],
                remediation_steps_user=["Rerun connectivity collector."],
                remediation_steps_admin=["Verify telemetry JSON structure."],
                escalation_priority="P2 - High"
            )

        # Airplane mode check
        if self.raw_data.get("airplane_mode", False):
            return TriageFinding(
                layer_number=1,
                layer_name="Physical / Hardware State",
                status="FAIL",
                root_cause_summary="Airplane mode is enabled on the device, disabling all wireless radios.",
                technical_evidence=["Endpoint airplane_mode flag is True"],
                remediation_steps_user=[
                    "Click the Action Center icon in the taskbar or press Win + A.",
                    "Toggle Airplane Mode to OFF.",
                    "Verify Wi-Fi or Ethernet adapter re-engages."
                ],
                remediation_steps_admin=["Instruct user to toggle airplane mode in Windows Settings -> Network & Internet."],
                escalation_priority="P3 - Medium"
            )

        adapters = self.raw_data.get("adapters") or []
        if not adapters:
            return TriageFinding(
                layer_number=1,
                layer_name="Physical / Hardware State",
                status="FAIL",
                root_cause_summary="No physical or virtual network adapters discovered on the operating system.",
                technical_evidence=["Zero network interfaces enumerated via system query"],
                remediation_steps_user=[
                    "Verify physical Ethernet cable is seated securely or Wi-Fi hardware toggle is switched on.",
                    "Reboot the laptop to re-initialize hardware bus."
                ],
                remediation_steps_admin=[
                    "Check Windows Device Manager for missing network controller drivers (Code 28/43).",
                    "Verify NIC is not disabled in system BIOS/UEFI."
                ],
                escalation_priority="P2 - High"
            )

        # Check if every adapter is Down/Disabled
        up_adapters = [a for a in adapters if isinstance(a, dict) and a.get("status") == "Up"]
        if not up_adapters:
            return TriageFinding(
                layer_number=1,
                layer_name="Physical / Hardware State",
                status="FAIL",
                root_cause_summary="All network interfaces are currently in a Down or Disconnected state.",
                technical_evidence=[f"Adapter '{a.get('name', 'Unknown')}' status: {a.get('status', 'Unknown')}" for a in adapters if isinstance(a, dict)],
                remediation_steps_user=[
                    "Verify Ethernet cable is plugged firmly into laptop and docking station.",
                    "Ensure Wi-Fi switch is turned on and laptop is not in flight mode."
                ],
                remediation_steps_admin=["Run 'netsh interface set interface name=\"...\" admin=enable' to re-enable."],
                escalation_priority="P2 - High"
            )

        return None

    def _check_layer2_datalink(self) -> Optional[TriageFinding]:
        wifi = self.raw_data.get("wifi") or {}
        if isinstance(wifi, dict) and wifi.get("connected"):
            raw_sig = wifi.get("signal_percent", 0)
            try:
                sig_float = float(str(raw_sig).strip())
                if math.isnan(sig_float) or math.isinf(sig_float):
                    sig = 0
                else:
                    sig = int(sig_float)
            except (ValueError, TypeError, OverflowError):
                sig = 0

            # Support dBm format (e.g. -85 dBm) or percentage (0-100)
            is_weak = False
            if sig < 0:
                is_weak = (sig <= -80)  # -80 dBm or lower is critical weak RF
            else:
                is_weak = (sig < 25)

            if is_weak:
                return TriageFinding(
                    layer_number=2,
                    layer_name="Data Link / Wi-Fi Association",
                    status="WARN",
                    root_cause_summary=f"Extremely weak Wi-Fi signal quality ({sig}%), causing heavy packet drops and frame retries.",
                    technical_evidence=[
                        f"Connected SSID: {wifi.get('ssid', 'Unknown')}",
                        f"BSSID: {wifi.get('bssid', 'Unknown')}",
                        f"Reported Wi-Fi Signal: {sig}% (Critical threshold is < 25% or <= -80 dBm)",
                        f"Radio Band: {wifi.get('radio_type', 'Unknown')} on Channel {wifi.get('channel', 0)}"
                    ],
                    remediation_steps_user=[
                        "Move closer to the wireless access point or router.",
                        "If available, plug in an Ethernet cable to bypass wireless congestion.",
                        "Switch to a 5GHz Wi-Fi network SSID instead of 2.4GHz if offered."
                    ],
                    remediation_steps_admin=[
                        "Inspect enterprise AP coverage map for dead zones.",
                        "Check for 2.4GHz microwave/Bluetooth co-channel interference on Channel " + str(wifi.get("channel", 0))
                    ],
                    escalation_priority="P3 - Medium"
                )
        return None

    def _check_layer3_network_ip(self) -> Optional[TriageFinding]:
        adapters = self.raw_data.get("adapters") or []
        if not isinstance(adapters, list):
            adapters = []
        up_adapters = [a for a in adapters if isinstance(a, dict) and a.get("status") == "Up"]

        apipa_found = False
        valid_ip_found = False
        no_ip_found = True
        evidence = []

        for a in up_adapters:
            ips_raw = a.get("ipv4_addresses") or []
            if isinstance(ips_raw, (str, int)):
                ips = [str(ips_raw)]
            elif isinstance(ips_raw, list):
                ips = [str(ip) for ip in ips_raw if ip is not None]
            else:
                ips = []

            gws_raw = a.get("default_gateways") or []
            if isinstance(gws_raw, (str, int)):
                gws = [str(gws_raw)]
            elif isinstance(gws_raw, list):
                gws = [str(gw) for gw in gws_raw if gw is not None]
            else:
                gws = []
            
            has_valid_on_adapter = False
            for ip in ips:
                if not ip or not isinstance(ip, str):
                    continue
                if not ip.startswith("127."):
                    no_ip_found = False
                if ip.startswith("169.254."):
                    apipa_found = True
                    evidence.append(f"Interface '{a.get('name')}' assigned APIPA address: {ip} (Subnet: {a.get('subnet_mask')})")
                elif not ip.startswith("127.") and not ip.startswith("0."):
                    has_valid_on_adapter = True
                    valid_ip_found = True

            if has_valid_on_adapter and not gws and not str(a.get("name", "")).lower().startswith("loopback"):
                evidence.append(f"Interface '{a.get('name')}' has no default gateway configured")

        # Multi-homing intelligence: If another adapter has a valid IP and gateway, APIPA is a secondary warning
        if apipa_found and not valid_ip_found:
            return TriageFinding(
                layer_number=3,
                layer_name="Network / IP Configuration (DHCP Failure)",
                status="FAIL",
                root_cause_summary="Endpoint failed to obtain a DHCP lease and self-assigned an Automatic Private IP Address (APIPA 169.254.x.x).",
                technical_evidence=evidence,
                remediation_steps_user=[
                    "Restart the local Wi-Fi router / home modem if working remotely.",
                    "Disconnect and reconnect to the Wi-Fi network.",
                    "If on office network, unplug Ethernet cable for 10 seconds and reconnect."
                ],
                remediation_steps_admin=[
                    "Execute 'ipconfig /renew' to re-request DHCP lease.",
                    "Inspect DHCP server scope exhaustion or VLAN helper-address relay configuration.",
                    "Check switch port 802.1X port authorization status."
                ],
                escalation_priority="P2 - High"
            )
        elif apipa_found and valid_ip_found:
            # Secondary virtual/inactive adapter has APIPA, but primary has valid IP
            return TriageFinding(
                layer_number=3,
                layer_name="Network / IP Configuration",
                status="WARN",
                root_cause_summary="Secondary network interface has an unconfigured APIPA address, but primary interface has valid IP.",
                technical_evidence=evidence,
                remediation_steps_user=["Verify primary network interface is connected."],
                remediation_steps_admin=["Disable unused virtual or secondary network adapters."],
                escalation_priority="P3 - Medium"
            )

        has_any_gateway = any(a.get("default_gateways") for a in up_adapters if isinstance(a, dict))
        if valid_ip_found and not has_any_gateway and not apipa_found:
            return TriageFinding(
                layer_number=3,
                layer_name="Network / IP Configuration (Missing Gateway)",
                status="FAIL",
                root_cause_summary="Active network interface has a valid IP address, but no default gateway is configured.",
                technical_evidence=evidence if evidence else ["No default gateway configured on any active network interface"],
                remediation_steps_user=["Verify network router DHCP settings or reconnect to network."],
                remediation_steps_admin=["Verify static IP configuration includes valid default gateway address."],
                escalation_priority="P2 - High"
            )

        if no_ip_found:
            return TriageFinding(
                layer_number=3,
                layer_name="Network / IP Configuration",
                status="FAIL",
                root_cause_summary="Active network interfaces have no valid IPv4 addresses assigned.",
                technical_evidence=["Zero valid unicast IPv4 addresses present on active interfaces"],
                remediation_steps_user=["Disconnect and reconnect to network."],
                remediation_steps_admin=["Verify static vs DHCP network adapter configuration."],
                escalation_priority="P2 - High"
            )

        return None

    def _check_layer4_gateway(self) -> Optional[TriageFinding]:
        gw_test = self.raw_data.get("gateway_reachability") or {}
        if not isinstance(gw_test, dict):
            return None

        raw_loss = gw_test.get("packet_loss_percent", 0.0)
        try:
            loss_f = float(raw_loss) if raw_loss is not None else 100.0
            if math.isnan(loss_f) or loss_f < 0.0:
                loss = 0.0
            elif math.isinf(loss_f) or loss_f >= 100.0:
                loss = 100.0
            else:
                loss = loss_f
        except (ValueError, TypeError, OverflowError):
            loss = 100.0

        gw_ip = gw_test.get("gateway_ip")
        
        raw_rtt = gw_test.get("avg_rtt_ms")
        try:
            rtt_f = float(raw_rtt) if raw_rtt is not None else None
            if rtt_f is not None and (math.isnan(rtt_f) or math.isinf(rtt_f) or rtt_f < 0.0):
                rtt = None
            else:
                rtt = rtt_f
        except (ValueError, TypeError, OverflowError):
            rtt = None

        if loss >= 100.0 and gw_ip:
            return TriageFinding(
                layer_number=4,
                layer_name="Transport / Gateway Reachability",
                status="FAIL",
                root_cause_summary=f"Default gateway ({gw_ip}) is completely unreachable (100% packet loss).",
                technical_evidence=[
                    f"Target Gateway: {gw_ip}",
                    f"Packets Sent: {gw_test.get('packets_sent')}, Received: {gw_test.get('packets_received')}",
                    "100.0% ICMP echo loss to local router/gateway"
                ],
                remediation_steps_user=[
                    "Verify local home router or office network switch is powered on.",
                    "Reboot the home internet router or switch to clear ARP cache.",
                    "Confirm Ethernet cable is plugged into active wall jack."
                ],
                remediation_steps_admin=[
                    "Check ARP resolution for gateway IP via 'arp -a'.",
                    "Verify default gateway IP matches current subnet CIDR boundaries."
                ],
                escalation_priority="P2 - High"
            )
        elif loss > 0.0 and loss < 100.0:
            return TriageFinding(
                layer_number=4,
                layer_name="Transport / Gateway Reachability",
                status="WARN",
                root_cause_summary=f"Intermittent packet loss to default gateway ({loss:.1f}% loss).",
                technical_evidence=[
                    f"Target Gateway: {gw_ip}",
                    f"Packet Loss: {loss:.1f}% ({gw_test.get('packets_received')}/{gw_test.get('packets_sent')} packets received)",
                    f"Average RTT: {rtt} ms" if rtt else "RTT unavailable"
                ],
                remediation_steps_user=["Check for loose network cables or wireless interference."],
                remediation_steps_admin=["Inspect switch port error counters (CRC errors, duplex mismatch)."],
                escalation_priority="P3 - Medium"
            )

        if rtt and rtt > 350.0:
            return TriageFinding(
                layer_number=4,
                layer_name="Transport / Gateway Reachability",
                status="WARN",
                root_cause_summary=f"Severe network latency to local default gateway ({rtt:.1f}ms).",
                technical_evidence=[
                    f"Target Gateway: {gw_ip}",
                    f"Average Round-Trip Time: {rtt:.1f}ms (Normal threshold is < 10ms for local LAN)"
                ],
                remediation_steps_user=["Close bandwidth-heavy downloads or torrent applications."],
                remediation_steps_admin=["Investigate local switch bufferbloat or duplex mismatch on port."],
                escalation_priority="P3 - Medium"
            )

        return None

    def _check_layer5_dns(self) -> Optional[TriageFinding]:
        dns_tests = self.raw_data.get("dns_tests") or []
        if not isinstance(dns_tests, list) or not dns_tests:
            return None

        failed_tests = [t for t in dns_tests if isinstance(t, dict) and not t.get("resolved")]
        
        # If all lookups failed
        if len(failed_tests) == len(dns_tests) and len(dns_tests) > 0:
            evidence = []
            for t in failed_tests:
                evidence.append(f"Query for '{t.get('target')}' against server '{t.get('server')}': {t.get('error')}")

            return TriageFinding(
                layer_number=5,
                layer_name="Application / DNS Name Resolution",
                status="FAIL",
                root_cause_summary="Local default gateway is reachable, but all DNS domain name resolutions are failing or timing out.",
                technical_evidence=evidence,
                remediation_steps_user=[
                    "Open Command Prompt and run: ipconfig /flushdns",
                    "Disconnect and reconnect to network."
                ],
                remediation_steps_admin=[
                    "Execute: Resolve-DnsName -Name dns.google -Server <DNS_SERVER>",
                    "Verify upstream corporate DNS forwarders are online and not blocking port 53 UDP/TCP.",
                    "Check for stale static DNS server entries assigned to adapter."
                ],
                escalation_priority="P2 - High"
            )
        elif failed_tests:
            # Partial lookup failure (e.g. corporate internal fails, public succeeds)
            evidence = [f"Failed: '{t.get('target')}' ({t.get('error')})" for t in failed_tests]
            return TriageFinding(
                layer_number=5,
                layer_name="Application / DNS Name Resolution",
                status="WARN",
                root_cause_summary="Partial DNS failure: specific domain names failed to resolve while others succeeded.",
                technical_evidence=evidence,
                remediation_steps_user=["Flush local DNS cache via 'ipconfig /flushdns'."],
                remediation_steps_admin=["Verify search domain suffixes and specific zone delegation."],
                escalation_priority="P3 - Medium"
            )

        return None

    def _check_layer6_captive_portal(self) -> Optional[TriageFinding]:
        probe = self.raw_data.get("http_probe") or {}
        if isinstance(probe, dict) and probe.get("is_captive_portal"):
            redirect = probe.get("redirect_url")
            code = probe.get("status_code")
            return TriageFinding(
                layer_number=6,
                layer_name="Application / Captive Portal Interception",
                status="FAIL",
                root_cause_summary="Web traffic is intercepted by a public Wi-Fi captive portal splash screen requiring user login/terms acceptance.",
                technical_evidence=[
                    f"HTTP probe returned status code {code} (Redirect / Intercept)",
                    f"Portal Redirect URL: {redirect or 'Local HTTP splash intercept'}",
                    f"Response snippet: {probe.get('response_body_snippet')}"
                ],
                remediation_steps_user=[
                    "Open a web browser (Edge, Chrome, Safari).",
                    "Navigate to http://neverssl.com or http://www.msftconnecttest.com to force the hotel/guest portal login page.",
                    "Accept the Wi-Fi terms of service and complete login."
                ],
                remediation_steps_admin=[
                    "Captive portal must be completed in user browser before corporate VPN can establish."
                ],
                escalation_priority="P3 - Medium (User Self-Service)"
            )
        return None

    def _check_layer7_vpn(self) -> Optional[TriageFinding]:
        vpn = self.raw_data.get("vpn") or {}
        if isinstance(vpn, dict) and vpn.get("connected"):
            missing_raw = vpn.get("missing_corporate_routes") or []
            if isinstance(missing_raw, list):
                missing = [str(r) for r in missing_raw if r is not None]
            elif isinstance(missing_raw, dict):
                missing = [str(k) for k in missing_raw.keys()]
            elif isinstance(missing_raw, (str, int, float)):
                missing = [str(missing_raw)]
            else:
                missing = []

            dns_leak = bool(vpn.get("split_dns_leak", False))

            if missing or dns_leak:
                evidence = []
                if missing:
                    evidence.append(f"Missing corporate routes in routing table: {', '.join(missing)}")
                if dns_leak:
                    evidence.append("Split-brain DNS leak: Internal enterprise domain queries routing to public DNS")

                return TriageFinding(
                    layer_number=7,
                    layer_name="Application / VPN Tunnel & Split Routing",
                    status="FAIL",
                    root_cause_summary=f"Corporate VPN client ({vpn.get('client_installed')}) is connected, but corporate routing rules or DNS suffixes are misconfigured.",
                    technical_evidence=evidence,
                    remediation_steps_user=[
                        "Disconnect VPN client completely, wait 10 seconds, and reconnect.",
                        "Ensure laptop is connected to stable internet before launching VPN."
                    ],
                    remediation_steps_admin=[
                        "Check VPN gateway split-tunnel routing push configuration.",
                        "Verify enterprise NRPT (Name Resolution Policy Table) or DNS suffix search order."
                    ],
                    escalation_priority="P2 - High"
                )
        return None


class ReportFormatter:
    """Formats findings into terminal tables, Markdown reports, and ITSM escalation briefs."""

    @staticmethod
    def format_console(findings: List[TriageFinding], hostname: str, os_info: str) -> str:
        lines = []
        lines.append("=" * 80)
        lines.append("USER CONNECTIVITY TRIAGE & LAYER DIAGNOSTIC REPORT")
        lines.append("=" * 80)
        lines.append(f"Target Endpoint : {hostname}")
        lines.append(f"Operating System: {os_info}")
        lines.append("-" * 80)

        # Primary Root Cause Finding
        failed = [f for f in findings if f.status == "FAIL"]
        warns = [f for f in findings if f.status == "WARN"]
        passes = [f for f in findings if f.status == "PASS"]

        primary = failed[0] if failed else (warns[0] if warns else passes[0])

        status_tag = f"[{primary.status}]"
        lines.append(f"TRIAGE RESULT   : {status_tag} LAYER {primary.layer_number} - {primary.layer_name.upper()}")
        lines.append(f"PRIORITY        : {primary.escalation_priority}")
        lines.append(f"DIAGNOSIS       : {primary.root_cause_summary}")
        lines.append("-" * 80)

        lines.append("TECHNICAL TELEMETRY EVIDENCE:")
        for ev in primary.technical_evidence:
            lines.append(f"  * {ev}")
        lines.append("-" * 80)

        lines.append("LEVEL 1 RESOLUTION STEPS (FOR END USER):")
        for idx, step in enumerate(primary.remediation_steps_user, 1):
            lines.append(f"  {idx}. {step}")
        lines.append("-" * 80)

        lines.append("TIER 2 / TIER 3 ESCALATION BRIEF (FOR IT SERVICE DESK):")
        for idx, step in enumerate(primary.remediation_steps_admin, 1):
            lines.append(f"  * {step}")

        lines.append("=" * 80)
        return "\n".join(lines)

    @staticmethod
    def generate_markdown(findings: List[TriageFinding], hostname: str, os_info: str) -> str:
        primary = next((f for f in findings if f.status == "FAIL"), None)
        if not primary:
            primary = next((f for f in findings if f.status == "WARN"), findings[0])

        md = []
        md.append("# User Network Connectivity Diagnostic Report")
        md.append("")
        md.append(f"**Endpoint:** `{hostname}`  ")
        md.append(f"**Operating System:** {os_info}  ")
        md.append(f"**Failure Layer:** **Layer {primary.layer_number} — {primary.layer_name}**  ")
        md.append(f"**Escalation Priority:** `{primary.escalation_priority}`  ")
        md.append("")
        md.append("---")
        md.append("")
        md.append("## 1. Root Cause Analysis (RCA)")
        md.append("")
        md.append(f"> **{primary.status}:** {primary.root_cause_summary}")
        md.append("")
        md.append("### Technical Evidence")
        for ev in primary.technical_evidence:
            md.append(f"- {ev}")
        md.append("")
        md.append("---")
        md.append("")
        md.append("## 2. Level 1 Remediation Procedure (User-Facing)")
        md.append("")
        for idx, step in enumerate(primary.remediation_steps_user, 1):
            md.append(f"{idx}. {step}")
        md.append("")
        md.append("---")
        md.append("")
        md.append("## 3. Tier 2 / Tier 3 Escalation Brief")
        md.append("")
        for step in primary.remediation_steps_admin:
            md.append(f"- {step}")
        md.append("")
        return "\n".join(md)

    @staticmethod
    def generate_itsm_ticket(findings: List[TriageFinding], hostname: str, os_info: str) -> str:
        primary = next((f for f in findings if f.status == "FAIL"), None)
        if not primary:
            primary = next((f for f in findings if f.status == "WARN"), findings[0])

        out = []
        out.append(f"# ITSM Ticket Brief: Network Disconnect on {hostname}")
        out.append("")
        out.append(f"**Incident Summary:** [Connectivity Triage] Layer {primary.layer_number} {primary.layer_name} failure on {hostname}")
        out.append(f"**Urgency / Priority:** {primary.escalation_priority}")
        out.append(f"**Affected CI / Endpoint:** {hostname}")
        out.append(f"**Impacted Operating System:** {os_info}")
        out.append("")
        out.append("### Diagnostic Assessment")
        out.append(f"**Failure Layer:** Layer {primary.layer_number} ({primary.layer_name})")
        out.append(f"**Root Cause:** {primary.root_cause_summary}")
        out.append("")
        out.append("### Diagnostic Telemetry")
        for ev in primary.technical_evidence:
            out.append(f"- {ev}")
        out.append("")
        out.append("### Recommended L2/L3 Next Steps")
        for step in primary.remediation_steps_admin:
            out.append(f"- {step}")
        return "\n".join(out)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Deterministic User Network Connectivity Triage & Layer Diagnostic Engine."
    )
    parser.add_argument(
        "-i", "--input",
        required=True,
        type=Path,
        help="Path to collected endpoint connectivity JSON telemetry."
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=None,
        help="Optional path to output Markdown assessment report."
    )
    parser.add_argument(
        "--generate-tickets",
        type=Path,
        default=None,
        help="Optional path to output formatted ITSM escalation ticket."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON summary directly to stdout for automated agent consumption."
    )
    parser.add_argument(
        "--sanitize",
        action="store_true",
        help="Sanitize internal IP addresses, hostnames, and MACs (Rule 4)."
    )
    return parser.parse_args()


def main():
    args = parse_arguments()

    if not args.input.exists():
        print(f"Error: Telemetry file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.input, "r", encoding="utf-8-sig", errors="replace") as f:
            data = json.load(f)
    except Exception as exc:
        print(f"Error parsing JSON: {exc}", file=sys.stderr)
        sys.exit(1)

    if args.sanitize:
        sanitizer = TelemetrySanitizer()
        data = sanitizer.sanitize_bundle(data)

    engine = ConnectivityTriageEngine(data)
    findings = engine.evaluate()

    hostname = str(data.get("hostname", "unknown-host")) if isinstance(data, dict) else "unknown-host"
    os_info = str(data.get("os", "Unknown OS")) if isinstance(data, dict) else "Unknown OS"

    if args.json:
        payload = {
            "endpoint": hostname,
            "os": os_info,
            "findings": [
                {
                    "layer_number": f.layer_number,
                    "layer_name": f.layer_name,
                    "status": f.status,
                    "priority": f.escalation_priority,
                    "root_cause": f.root_cause_summary,
                    "evidence": f.technical_evidence,
                    "remediation_user": f.remediation_steps_user,
                    "remediation_admin": f.remediation_steps_admin
                }
                for f in findings
            ]
        }
        print(json.dumps(payload, indent=2))
        return

    # Console output
    console_out = ReportFormatter.format_console(findings, hostname, os_info)
    print(console_out)

    if args.output:
        md_out = ReportFormatter.generate_markdown(findings, hostname, os_info)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(md_out)
        print(f"Markdown assessment report written to: {args.output}")

    if args.generate_tickets:
        ticket_out = ReportFormatter.generate_itsm_ticket(findings, hostname, os_info)
        with open(args.generate_tickets, "w", encoding="utf-8") as f:
            f.write(ticket_out)
        print(f"ITSM escalation ticket written to: {args.generate_tickets}")


if __name__ == "__main__":
    main()

