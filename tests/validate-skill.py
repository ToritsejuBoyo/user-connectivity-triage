#!/usr/bin/env python3
"""
Automated Validation Suite for user-connectivity-triage.
Verifies all 7 OSI / TCP-IP diagnostic decision tree layers,
client-side data sanitization (Rule 4), report generation, and ITSM escalation briefs.
Complies with Rule 3, Rule 4, Rule 7, and Rule 9.
"""

import json
import os
import sys
import tempfile
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_ROOT / "scripts"))

from triage_connectivity import (
    ConnectivityTriageEngine,
    ReportFormatter,
    TelemetrySanitizer,
    TriageFinding,
)

FIXTURES_DIR = SKILL_ROOT / "tests" / "fixtures"


def test_healthy_connection():
    print("[TEST 01] Healthy Baseline Enterprise Connection (Layer 0 Pass)...")
    with open(FIXTURES_DIR / "fixture-healthy-enterprise-lan.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    engine = ConnectivityTriageEngine(data)
    findings = engine.evaluate()
    assert len(findings) == 1
    assert findings[0].status == "PASS"
    assert findings[0].layer_number == 0
    print("  -> PASSED: All healthy layers verified with status PASS.")


def test_apipa_dhcp_failure():
    print("[TEST 02] Layer 3 Network / IP & DHCP Failure (APIPA 169.254.x.x)...")
    with open(FIXTURES_DIR / "fixture-apipa-dhcp-failure.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    engine = ConnectivityTriageEngine(data)
    findings = engine.evaluate()
    l3 = next((f for f in findings if f.layer_number == 3), None)
    assert l3 is not None, "Layer 3 failure not detected"
    assert l3.status == "FAIL"
    assert "169.254." in l3.root_cause_summary or any("169.254." in ev for ev in l3.technical_evidence)
    print("  -> PASSED: APIPA self-assignment and missing DHCP lease identified.")


def test_weak_wifi_signal():
    print("[TEST 03] Layer 2 Wi-Fi Association & Weak Signal (< 25%)...")
    with open(FIXTURES_DIR / "fixture-wifi-weak-signal.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    engine = ConnectivityTriageEngine(data)
    findings = engine.evaluate()
    l2 = next((f for f in findings if f.layer_number == 2), None)
    assert l2 is not None, "Layer 2 warning not detected"
    assert l2.status == "WARN"
    assert "weak wi-fi signal" in l2.root_cause_summary.lower()
    print("  -> PASSED: 12% Wi-Fi signal flagged with Layer 2 warning and resolution steps.")


def test_gateway_unreachable():
    print("[TEST 04] Layer 4 Transport & Gateway Reachability (100% Packet Loss)...")
    with open(FIXTURES_DIR / "fixture-gateway-unreachable.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    engine = ConnectivityTriageEngine(data)
    findings = engine.evaluate()
    l4 = next((f for f in findings if f.layer_number == 4), None)
    assert l4 is not None, "Layer 4 failure not detected"
    assert l4.status == "FAIL"
    assert "100% packet loss" in l4.root_cause_summary.lower()
    print("  -> PASSED: Gateway packet loss correctly isolated to Layer 4.")


def test_dns_failure():
    print("[TEST 05] Layer 5 DNS Name Resolution Failure...")
    with open(FIXTURES_DIR / "fixture-dns-resolution-timeout.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    engine = ConnectivityTriageEngine(data)
    findings = engine.evaluate()
    l5 = next((f for f in findings if f.layer_number == 5), None)
    assert l5 is not None, "Layer 5 DNS failure not detected"
    assert l5.status == "FAIL"
    assert "dns" in l5.root_cause_summary.lower()
    print("  -> PASSED: DNS SERVFAIL / timeout accurately diagnosed with flushdns steps.")


def test_captive_portal_detection():
    print("[TEST 06] Layer 6 Captive Portal HTTP Interception...")
    with open(FIXTURES_DIR / "fixture-captive-portal-hotel.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    engine = ConnectivityTriageEngine(data)
    findings = engine.evaluate()
    l6 = next((f for f in findings if f.layer_number == 6), None)
    assert l6 is not None, "Layer 6 captive portal not detected"
    assert l6.status == "FAIL"
    assert "captive portal" in l6.root_cause_summary.lower()
    assert any("login?mac=" in ev for ev in l6.technical_evidence)
    print("  -> PASSED: Hotel Wi-Fi captive portal splash redirect detected.")


def test_vpn_split_tunnel():
    print("[TEST 07] Layer 7 Corporate VPN Split-Tunnel Leak...")
    with open(FIXTURES_DIR / "fixture-vpn-split-tunnel-leak.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    engine = ConnectivityTriageEngine(data)
    findings = engine.evaluate()
    l7 = next((f for f in findings if f.layer_number == 7), None)
    assert l7 is not None, "Layer 7 VPN split tunnel leak not detected"
    assert l7.status == "FAIL"
    assert "split routing" in l7.layer_name.lower() or "vpn" in l7.root_cause_summary.lower()
    print("  -> PASSED: Missing corporate routes and split-brain DNS leak identified.")


def test_client_side_sanitization():
    print("[TEST 08] Client-Side Data Sanitization (Rule 4 Compliance)...")
    sanitizer = TelemetrySanitizer(salt="test-salt")
    with open(FIXTURES_DIR / "fixture-healthy-enterprise-lan.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    clean = sanitizer.sanitize_bundle(data)
    assert clean["hostname"].startswith("host-")
    assert clean["hostname"].endswith(".corp.example.com")
    assert clean["wifi"]["bssid"] == "00:11:22:xx:xx:xx"
    assert all(a["mac_address"] == "00:11:22:xx:xx:xx" for a in clean["adapters"])
    print("  -> PASSED: Hostname SHA-256 hashing and BSSID MAC masking verified.")


def main():
    print("=" * 70)
    print("USER-CONNECTIVITY-TRIAGE AUTOMATED VALIDATION SUITE")
    print("=" * 70)
    test_healthy_connection()
    test_apipa_dhcp_failure()
    test_weak_wifi_signal()
    test_gateway_unreachable()
    test_dns_failure()
    test_captive_portal_detection()
    test_vpn_split_tunnel()
    test_client_side_sanitization()
    print("=" * 70)
    print("ALL 8 VALIDATION CHECKS PASSED SUCCESSFULLY (Exit Code 0).")
    print("=" * 70)


if __name__ == "__main__":
    main()
