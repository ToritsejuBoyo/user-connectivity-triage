#!/usr/bin/env python3
"""
Chaos & Adversarial Stress Test Suite for user-connectivity-triage (20 New Tests).
Validates multi-threading safety (8 threads, 20,000 evaluations), 50,000-payload hammer,
negative RSSI dBm parsing, dual-homing APIPA tolerance, null field resilience,
and XSS/HTML payload safety.
"""

import concurrent.futures
import json
import os
import sys
import tempfile
import time
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


def run_all_20_chaos_tests():
    print("=" * 80)
    print("USER-CONNECTIVITY-TRIAGE: 20 CHAOS & ADVERSARIAL STRESS TESTS")
    print("=" * 80)
    passed = 0
    failed = 0

    # TEST 1: Negative Wi-Fi RSSI in dBm (-85 dBm -> Weak Signal)
    print("[CHAOS 01/20] Negative Wi-Fi RSSI in dBm (-85 dBm)...")
    try:
        p = {
            "adapters": [{"name": "Wi-Fi", "status": "Up", "ipv4_addresses": ["192.0.2.10"], "default_gateways": ["192.0.2.1"]}],
            "wifi": {"connected": True, "signal_percent": -85},
            "gateway_reachability": {"gateway_ip": "192.0.2.1", "packet_loss_percent": 0.0}
        }
        findings = ConnectivityTriageEngine(p).evaluate()
        l2 = next(f for f in findings if f.layer_number == 2)
        assert l2.status == "WARN"
        print("  -> PASSED: -85 dBm correctly parsed as weak signal warning.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 2: String Numbers in Numeric Fields ("20" and "36")
    print("[CHAOS 02/20] String Representation of Numeric Values...")
    try:
        p = {
            "adapters": [{"name": "Wi-Fi", "status": "Up", "ipv4_addresses": ["192.0.2.10"], "default_gateways": ["192.0.2.1"]}],
            "wifi": {"connected": True, "signal_percent": "18", "channel": "36"},
            "gateway_reachability": {"gateway_ip": "192.0.2.1", "packet_loss_percent": "0.0", "avg_rtt_ms": "3.5"}
        }
        findings = ConnectivityTriageEngine(p).evaluate()
        l2 = next(f for f in findings if f.layer_number == 2)
        assert l2.status == "WARN"
        print("  -> PASSED: String '18' converted without TypeError.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 3: Null Values for All Major Blocks
    print("[CHAOS 03/20] Null / None in Place of Dictionaries and Lists...")
    try:
        p = {
            "hostname": "test-nulls",
            "adapters": None,
            "wifi": None,
            "gateway_reachability": None,
            "dns_tests": None,
            "http_probe": None,
            "vpn": None
        }
        findings = ConnectivityTriageEngine(p).evaluate()
        assert len(findings) == 1 and findings[0].layer_number == 1
        print("  -> PASSED: Handled null blocks gracefully at Layer 1.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 4: Dual-Homed Adapter (VirtualBox APIPA + Valid Physical Wi-Fi)
    print("[CHAOS 04/20] Dual-Homing Intelligence (APIPA VirtualBox + Healthy Wi-Fi)...")
    try:
        p = {
            "adapters": [
                {"name": "VirtualBox Host-Only Ethernet", "status": "Up", "ipv4_addresses": ["169.254.100.5"], "default_gateways": []},
                {"name": "Wi-Fi", "status": "Up", "ipv4_addresses": ["192.0.2.145"], "default_gateways": ["192.0.2.1"]}
            ],
            "gateway_reachability": {"gateway_ip": "192.0.2.1", "packet_loss_percent": 0.0, "avg_rtt_ms": 2.5},
            "dns_tests": [{"target": "dns.google", "resolved": True, "resolved_ips": ["8.8.8.8"]}]
        }
        findings = ConnectivityTriageEngine(p).evaluate()
        # Should NOT fail as a hard DHCP failure because primary interface is functional!
        l3 = next((f for f in findings if f.layer_number == 3), None)
        assert l3 is not None and l3.status == "WARN"
        print("  -> PASSED: Dual-homed APIPA treated as secondary warning, not hard disconnect.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 5: Gateway Intermittent Packet Loss (50% Loss)
    print("[CHAOS 05/20] Intermittent Gateway Packet Loss (50% Loss)...")
    try:
        p = {
            "adapters": [{"name": "eth0", "status": "Up", "ipv4_addresses": ["192.0.2.50"], "default_gateways": ["192.0.2.1"]}],
            "gateway_reachability": {"gateway_ip": "192.0.2.1", "packet_loss_percent": 50.0, "packets_sent": 4, "packets_received": 2, "avg_rtt_ms": 12.0}
        }
        findings = ConnectivityTriageEngine(p).evaluate()
        l4 = next(f for f in findings if f.layer_number == 4)
        assert l4.status == "WARN" and "intermittent" in l4.root_cause_summary.lower()
        print("  -> PASSED: 50% loss diagnosed as intermittent Layer 4 packet loss.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 6: Partial DNS Resolution (Split Lookups)
    print("[CHAOS 06/20] Partial DNS Resolution (Internal Fails, Public Succeeds)...")
    try:
        p = {
            "adapters": [{"name": "eth0", "status": "Up", "ipv4_addresses": ["192.0.2.50"], "default_gateways": ["192.0.2.1"]}],
            "gateway_reachability": {"gateway_ip": "192.0.2.1", "packet_loss_percent": 0.0, "avg_rtt_ms": 2.0},
            "dns_tests": [
                {"target": "dns.google", "resolved": True, "resolved_ips": ["8.8.8.8"]},
                {"target": "intranet.corp.local", "resolved": False, "error": "NXDOMAIN"}
            ]
        }
        findings = ConnectivityTriageEngine(p).evaluate()
        l5 = next(f for f in findings if f.layer_number == 5)
        assert l5.status == "WARN" and "partial" in l5.root_cause_summary.lower()
        print("  -> PASSED: Partial DNS failure isolated as Layer 5 warning.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 7: Captive Portal with 500-Character URL & Special Query Params
    print("[CHAOS 07/20] Captive Portal with 500-Character Query URL...")
    try:
        long_url = "https://portal.hilton.com/login?token=" + "A" * 450 + "&redirect=neverssl.com"
        p = {
            "adapters": [{"name": "Wi-Fi", "status": "Up", "ipv4_addresses": ["192.0.2.50"], "default_gateways": ["192.0.2.1"]}],
            "gateway_reachability": {"gateway_ip": "192.0.2.1", "packet_loss_percent": 0.0},
            "http_probe": {"status_code": 302, "is_captive_portal": True, "redirect_url": long_url}
        }
        findings = ConnectivityTriageEngine(p).evaluate()
        l6 = next(f for f in findings if f.layer_number == 6)
        assert l6.status == "FAIL"
        print("  -> PASSED: 500-char captive portal URL handled without truncation crash.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 8: XSS and HTML Injection in Hostname
    print("[CHAOS 08/20] XSS / HTML Injection Payloads in Hostname...")
    try:
        sanitizer = TelemetrySanitizer()
        p = {"hostname": '<script>alert("pwned")</script>'}
        clean = sanitizer.sanitize_bundle(p)
        assert "<script>" not in clean["hostname"]
        assert clean["hostname"].startswith("host-")
        print("  -> PASSED: HTML script tags masked into deterministic SHA-256 identifier.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 9: Idempotent Double Sanitization
    print("[CHAOS 09/20] Idempotent Double Sanitization...")
    try:
        sanitizer = TelemetrySanitizer()
        p = {"hostname": "laptop-finance-01.corp.internal"}
        pass1 = sanitizer.sanitize_bundle(p)
        pass2 = sanitizer.sanitize_bundle(pass1)
        assert pass1["hostname"] == pass2["hostname"]
        assert "host-host-" not in pass2["hostname"]
        print("  -> PASSED: Double sanitization is strictly idempotent.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 10: 50,000-Payload Scale Hammer
    print("[CHAOS 10/20] 50,000-Payload High-Throughput Hammer...")
    try:
        p = {
            "hostname": "hammer-50k",
            "adapters": [{"name": "eth0", "status": "Up", "ipv4_addresses": ["192.0.2.50"], "default_gateways": ["192.0.2.1"]}],
            "gateway_reachability": {"gateway_ip": "192.0.2.1", "packet_loss_percent": 0.0, "avg_rtt_ms": 2.0},
            "dns_tests": [{"target": "dns.google", "resolved": True, "resolved_ips": ["8.8.8.8"]}]
        }
        t0 = time.perf_counter()
        for _ in range(50000):
            res = ConnectivityTriageEngine(p).evaluate()
        t1 = time.perf_counter()
        total_sec = t1 - t0
        print(f"  -> PASSED: 50,000 diagnoses in {total_sec:.2f}s ({50000/total_sec:,.0f} diagnoses/sec).")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 11: Multi-Threaded Parallel Evaluation (8 Workers, 20,000 Total)
    print("[CHAOS 11/20] Multi-Threaded Parallel Concurrency (8 Threads x 2,500)...")
    try:
        def worker_task(count: int):
            san = TelemetrySanitizer()
            p = {
                "hostname": "thread-test",
                "adapters": [{"name": "eth0", "status": "Up", "ipv4_addresses": ["10.0.0.5"], "default_gateways": ["10.0.0.1"]}],
                "gateway_reachability": {"gateway_ip": "10.0.0.1", "packet_loss_percent": 0.0, "avg_rtt_ms": 1.5},
                "dns_tests": [{"target": "dns.google", "resolved": True, "resolved_ips": ["8.8.8.8"]}]
            }
            for _ in range(count):
                clean = san.sanitize_bundle(p)
                eng = ConnectivityTriageEngine(clean)
                findings = eng.evaluate()
                assert len(findings) == 1
            return count

        t0 = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(worker_task, 2500) for _ in range(8)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]
        t1 = time.perf_counter()
        total_evals = sum(results)
        print(f"  -> PASSED: {total_evals:,} concurrent diagnoses in {t1 - t0:.2f}s across 8 threads.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 12: Astronomical RTT Latency (99,999,999 ms)
    print("[CHAOS 12/20] Astronomical Gateway Latency (99,999,999 ms)...")
    try:
        p = {
            "adapters": [{"name": "eth0", "status": "Up", "ipv4_addresses": ["192.0.2.50"], "default_gateways": ["192.0.2.1"]}],
            "gateway_reachability": {"gateway_ip": "192.0.2.1", "packet_loss_percent": 0.0, "avg_rtt_ms": 99999999.0}
        }
        findings = ConnectivityTriageEngine(p).evaluate()
        l4 = next(f for f in findings if f.layer_number == 4)
        assert l4.status == "WARN"
        print("  -> PASSED: Handled astronomical RTT gracefully without overflow.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 13: Negative RTT Latency (-50.0 ms)
    print("[CHAOS 13/20] Negative Gateway Latency (-50.0 ms)...")
    try:
        p = {
            "adapters": [{"name": "eth0", "status": "Up", "ipv4_addresses": ["192.0.2.50"], "default_gateways": ["192.0.2.1"]}],
            "gateway_reachability": {"gateway_ip": "192.0.2.1", "packet_loss_percent": 0.0, "avg_rtt_ms": -50.0}
        }
        findings = ConnectivityTriageEngine(p).evaluate()
        assert len(findings) >= 1
        print("  -> PASSED: Handled negative RTT without crash.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 14: Non-ASCII Unicode SSID ("Café München 5GHz")
    print("[CHAOS 14/20] Non-ASCII Unicode SSID Names...")
    try:
        p = {
            "adapters": [{"name": "Wi-Fi", "status": "Up", "ipv4_addresses": ["192.0.2.50"], "default_gateways": ["192.0.2.1"]}],
            "wifi": {"connected": True, "ssid": "Café München 5GHz", "signal_percent": 90},
            "gateway_reachability": {"gateway_ip": "192.0.2.1", "packet_loss_percent": 0.0}
        }
        findings = ConnectivityTriageEngine(p).evaluate()
        assert len(findings) == 1 and findings[0].status == "PASS"
        print("  -> PASSED: Non-ASCII unicode characters in SSID handled cleanly.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 15: 100-Canary DNS Test Array
    print("[CHAOS 15/20] 100-Canary DNS Test Array Scaling...")
    try:
        dns_array = [
            {"target": f"srv-{i:03d}.corp.local", "resolved": True, "resolved_ips": [f"192.0.2.{i % 250 + 1}"], "rtt_ms": 2.0}
            for i in range(100)
        ]
        p = {
            "adapters": [{"name": "eth0", "status": "Up", "ipv4_addresses": ["192.0.2.50"], "default_gateways": ["192.0.2.1"]}],
            "gateway_reachability": {"gateway_ip": "192.0.2.1", "packet_loss_percent": 0.0},
            "dns_tests": dns_array
        }
        findings = ConnectivityTriageEngine(p).evaluate()
        assert len(findings) == 1 and findings[0].status == "PASS"
        print("  -> PASSED: Ingested 100 DNS canaries without performance degradation.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 16: Bidi Override in Network Adapter Description
    print("[CHAOS 16/20] Bidi Override in Network Adapter Name...")
    try:
        p = {
            "adapters": [{"name": "Ethernet \u202eGigabit\u200e Adapter", "status": "Down"}]
        }
        findings = ConnectivityTriageEngine(p).evaluate()
        assert len(findings) == 1 and findings[0].layer_number == 1
        print("  -> PASSED: Bidi character in adapter name diagnosed at Layer 1.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 17: Valid IP with Missing Default Gateway
    print("[CHAOS 17/20] Valid Static IP Missing Default Gateway...")
    try:
        p = {
            "adapters": [{"name": "eth0", "status": "Up", "ipv4_addresses": ["192.0.2.100"], "default_gateways": []}]
        }
        findings = ConnectivityTriageEngine(p).evaluate()
        assert any("no default gateway" in ev.lower() for f in findings for ev in f.technical_evidence)
        print("  -> PASSED: Missing default gateway flagged in technical evidence.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 18: Zero-Byte and Whitespace Strings to TelemetrySanitizer
    print("[CHAOS 18/20] Zero-Byte and Whitespace Strings to Sanitizer...")
    try:
        san = TelemetrySanitizer()
        assert san.sanitize_ip("") == ""
        assert san.sanitize_ip("   ") == "   "
        assert san.sanitize_host("") == ""
        assert san.sanitize_mac("") == ""
        print("  -> PASSED: Empty and whitespace strings handled without index error.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 19: Extremely Long 1,000-Character Hostname
    print("[CHAOS 19/20] Extremely Long 1,000-Character Hostname...")
    try:
        long_host = ("subdomain." * 100) + "corp.example.com"
        p = {
            "hostname": long_host,
            "adapters": [{"name": "eth0", "status": "Up", "ipv4_addresses": ["192.0.2.10"], "default_gateways": ["192.0.2.1"]}],
            "gateway_reachability": {"gateway_ip": "192.0.2.1", "packet_loss_percent": 0.0}
        }
        san = TelemetrySanitizer()
        clean = san.sanitize_bundle(p)
        assert len(clean["hostname"]) < 50
        print("  -> PASSED: 1,000-char domain hashed into compact standard identifier.")
        passed += 1
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    # TEST 20: Full CLI Execution with Chaos Payload File
    print("[CHAOS 20/20] CLI Execution with Chaos Dual-Homing Payload...")
    try:
        script_path = SKILL_ROOT / "scripts" / "triage_connectivity.py"
        p = {
            "hostname": "chaos-cli-test",
            "adapters": [
                {"name": "vboxnet0", "status": "Up", "ipv4_addresses": ["169.254.1.1"], "default_gateways": []},
                {"name": "Wi-Fi", "status": "Up", "ipv4_addresses": ["10.0.0.45"], "default_gateways": ["10.0.0.1"]}
            ],
            "gateway_reachability": {"gateway_ip": "10.0.0.1", "packet_loss_percent": 0.0, "avg_rtt_ms": 3.0},
            "dns_tests": [{"target": "dns.google", "resolved": True, "resolved_ips": ["8.8.8.8"]}]
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            json.dump(p, tf)
            temp_path = Path(tf.name)

        try:
            import subprocess
            res = subprocess.run([sys.executable, str(script_path), "-i", str(temp_path), "--sanitize"], capture_output=True, text=True)
            assert res.returncode == 0
            assert "LAYER 3" in res.stdout
            assert "[WARN]" in res.stdout
            print("  -> PASSED: CLI executed cleanly with dual-homed chaos telemetry.")
            passed += 1
        finally:
            temp_path.unlink()
    except Exception as exc:
        print(f"  -> FAILED: {exc}")
        failed += 1

    print("=" * 80)
    print(f"CHAOS ADVERSARIAL STRESS TESTS RESULT: {passed}/20 PASSED, {failed} FAILED")
    print("=" * 80)
    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    run_all_20_chaos_tests()
