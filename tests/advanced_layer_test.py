#!/usr/bin/env python3
"""
Advanced Layer & Edge-Case Test Suite for user-connectivity-triage.
Tests Airplane mode override, physical adapter disconnection,
high latency bufferbloat warning, and multi-format report outputs.
"""

import json
import sys
import tempfile
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_ROOT / "scripts"))

from triage_connectivity import (
    ConnectivityTriageEngine,
    ReportFormatter,
    TriageFinding,
)

FIXTURES_DIR = SKILL_ROOT / "tests" / "fixtures"


def test_airplane_mode_precedence():
    print("[ADVANCED 01] Airplane Mode Hardware Override (Layer 1 Precedence)...")
    payload = {
        "hostname": "test-laptop-flight",
        "os": "Windows 11 Enterprise",
        "airplane_mode": True,
        "adapters": [
            {"name": "Wi-Fi", "type": "Wireless80211", "status": "Down", "ipv4_addresses": []}
        ],
        "wifi": {"connected": False}
    }
    engine = ConnectivityTriageEngine(payload)
    findings = engine.evaluate()
    assert len(findings) == 1
    assert findings[0].layer_number == 1
    assert "airplane mode" in findings[0].root_cause_summary.lower()
    print("  -> PASSED: Airplane mode halts downstream layer evaluations.")


def test_all_adapters_down():
    print("[ADVANCED 02] All Network Adapters Down (Layer 1 Disconnected)...")
    payload = {
        "hostname": "test-pc-offline",
        "os": "Windows 11 Enterprise",
        "airplane_mode": False,
        "adapters": [
            {"name": "Ethernet", "type": "Ethernet", "status": "Down", "ipv4_addresses": []},
            {"name": "Wi-Fi", "type": "Wireless80211", "status": "Disabled", "ipv4_addresses": []}
        ],
        "wifi": {"connected": False}
    }
    engine = ConnectivityTriageEngine(payload)
    findings = engine.evaluate()
    assert len(findings) == 1
    assert findings[0].layer_number == 1
    assert "down or disconnected" in findings[0].root_cause_summary.lower()
    print("  -> PASSED: Fully disconnected endpoint isolated at Layer 1.")


def test_gateway_high_latency_warning():
    print("[ADVANCED 03] Gateway High Latency & Bufferbloat Warning (Layer 4)...")
    payload = {
        "hostname": "test-pc-lag",
        "os": "Windows 11 Enterprise",
        "adapters": [
            {"name": "Wi-Fi", "status": "Up", "ipv4_addresses": ["192.0.2.55"], "default_gateways": ["192.0.2.1"]}
        ],
        "wifi": {"connected": True, "signal_percent": 85},
        "gateway_reachability": {
            "gateway_ip": "192.0.2.1",
            "packets_sent": 4,
            "packets_received": 4,
            "packet_loss_percent": 0.0,
            "avg_rtt_ms": 480.2
        },
        "dns_tests": [{"target": "dns.google", "resolved": True, "resolved_ips": ["8.8.8.8"]}]
    }
    engine = ConnectivityTriageEngine(payload)
    findings = engine.evaluate()
    l4 = next((f for f in findings if f.layer_number == 4), None)
    assert l4 is not None
    assert l4.status == "WARN"
    assert "severe network latency" in l4.root_cause_summary.lower()
    print("  -> PASSED: 480ms gateway RTT raised Layer 4 bufferbloat warning.")


def test_markdown_and_ticket_generation():
    print("[ADVANCED 04] Report & ITSM Ticket Formatting Verification...")
    with open(FIXTURES_DIR / "fixture-apipa-dhcp-failure.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    engine = ConnectivityTriageEngine(data)
    findings = engine.evaluate()

    # Markdown
    md = ReportFormatter.generate_markdown(findings, "synthetic-host-01", "Windows 11")
    assert "# User Network Connectivity Diagnostic Report" in md
    assert "Root Cause Analysis (RCA)" in md
    assert "Level 1 Remediation Procedure" in md

    # ITSM Ticket
    ticket = ReportFormatter.generate_itsm_ticket(findings, "synthetic-host-01", "Windows 11")
    assert "[Connectivity Triage] Layer 3" in ticket
    assert "Urgency / Priority:" in ticket
    assert "Recommended L2/L3 Next Steps" in ticket
    print("  -> PASSED: Markdown and Jira/ServiceNow ticket formats generated cleanly.")


def test_empty_dns_canaries_graceful():
    print("[ADVANCED 05] Telemetry With Partial / Missing Canary Tests...")
    payload = {
        "hostname": "test-minimal",
        "os": "Linux 6.8",
        "adapters": [{"name": "eth0", "status": "Up", "ipv4_addresses": ["192.0.2.100"], "default_gateways": ["192.0.2.1"]}],
        "gateway_reachability": {"gateway_ip": "192.0.2.1", "packet_loss_percent": 0.0, "avg_rtt_ms": 2.1},
        "dns_tests": []
    }
    engine = ConnectivityTriageEngine(payload)
    findings = engine.evaluate()
    assert len(findings) == 1
    assert findings[0].status == "PASS"
    print("  -> PASSED: Handled partial telemetry without crashing.")


def main():
    print("=" * 70)
    print("USER-CONNECTIVITY-TRIAGE ADVANCED LAYER TEST SUITE")
    print("=" * 70)
    test_airplane_mode_precedence()
    test_all_adapters_down()
    test_gateway_high_latency_warning()
    test_markdown_and_ticket_generation()
    test_empty_dns_canaries_graceful()
    print("=" * 70)
    print("ALL 5 ADVANCED TESTS PASSED SUCCESSFULLY (Exit Code 0).")
    print("=" * 70)


if __name__ == "__main__":
    main()
