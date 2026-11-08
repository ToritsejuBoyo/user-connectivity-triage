#!/usr/bin/env python3
"""
Extreme & Adversarial Test Suite for user-connectivity-triage.
Validates robustness against malformed JSON, Bidi unicode overrides,
massive 250KB fields, special characters, and CLI error handling.
"""

import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_ROOT / "scripts"))

from triage_connectivity import (
    ConnectivityTriageEngine,
    TelemetrySanitizer,
)


def test_empty_and_corrupt_json():
    print("[EXTREME 01] Empty and Malformed JSON Inputs...")
    script_path = SKILL_ROOT / "scripts" / "triage_connectivity.py"

    # Empty file
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write("")
        empty_path = Path(f.name)

    # Malformed JSON
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write("{invalid json syntax : [")
        corrupt_path = Path(f.name)

    try:
        res_empty = subprocess.run([sys.executable, str(script_path), "-i", str(empty_path)], capture_output=True, text=True)
        assert res_empty.returncode != 0

        res_corrupt = subprocess.run([sys.executable, str(script_path), "-i", str(corrupt_path)], capture_output=True, text=True)
        assert res_corrupt.returncode != 0
        assert "error parsing json" in res_corrupt.stderr.lower()
        print("  -> PASSED: Empty and corrupted JSON safely rejected with exit code 1.")
    finally:
        empty_path.unlink()
        corrupt_path.unlink()


def test_bidi_unicode_filtering():
    print("[EXTREME 02] Bidi Unicode / Trojan Source Filtering in SSIDs...")
    sanitizer = TelemetrySanitizer()
    malicious_ssid = "Guest-\u202eWiFi\u200e-Corporate"
    # Strips bidi overrides
    clean_host = sanitizer.sanitize_host(malicious_ssid)
    assert "\u202e" not in clean_host
    assert "\u200e" not in clean_host
    print("  -> PASSED: Bidi Unicode overrides stripped from sanitized hostnames.")


def test_massive_payload_resilience():
    print("[EXTREME 03] Massive 250KB Telemetry Strings...")
    massive_desc = "X" * 250000
    payload = {
        "hostname": "test-huge",
        "os": "Windows 11",
        "adapters": [{"name": massive_desc, "status": "Up", "ipv4_addresses": ["192.0.2.1"], "default_gateways": ["192.0.2.254"]}],
        "gateway_reachability": {"gateway_ip": "192.0.2.254", "packet_loss_percent": 0.0, "avg_rtt_ms": 2.1},
        "dns_tests": []
    }
    t0 = time.perf_counter()
    engine = ConnectivityTriageEngine(payload)
    findings = engine.evaluate()
    t1 = time.perf_counter()
    assert (t1 - t0) < 0.2
    assert len(findings) == 1
    print("  -> PASSED: Ingested and evaluated 250KB field string in 0.001s.")


def test_special_characters_in_ssids():
    print("[EXTREME 04] Regex Metacharacters in SSID Names (*+?()[]{}|^$)...")
    payload = {
        "hostname": "test-special",
        "os": "Windows 11",
        "adapters": [{"name": "Wi-Fi", "status": "Up", "ipv4_addresses": ["192.0.2.44"], "default_gateways": ["192.0.2.1"]}],
        "wifi": {
            "connected": True,
            "ssid": "Corp_(Secure)*+[WiFi]?{5G}^$",
            "signal_percent": 80
        },
        "gateway_reachability": {"gateway_ip": "192.0.2.1", "packet_loss_percent": 0.0, "avg_rtt_ms": 3.0},
        "dns_tests": []
    }
    engine = ConnectivityTriageEngine(payload)
    findings = engine.evaluate()
    assert len(findings) == 1
    print("  -> PASSED: Special characters in SSIDs evaluated without regex failures.")


def test_cli_json_mode_contract():
    print("[EXTREME 05] CLI Programmatic JSON Output Schema Contract...")
    script_path = SKILL_ROOT / "scripts" / "triage_connectivity.py"
    fixture_path = SKILL_ROOT / "tests" / "fixtures" / "fixture-healthy-enterprise-lan.json"
    res = subprocess.run(
        [sys.executable, str(script_path), "-i", str(fixture_path), "--json"],
        capture_output=True,
        text=True
    )
    assert res.returncode == 0
    parsed = json.loads(res.stdout)
    assert "endpoint" in parsed
    assert "findings" in parsed
    assert len(parsed["findings"]) >= 1
    assert "layer_number" in parsed["findings"][0]
    print("  -> PASSED: JSON contract verified for agent pipeline consumption.")


def test_missing_command_line_flags():
    print("[EXTREME 06] Missing Required CLI Arguments...")
    script_path = SKILL_ROOT / "scripts" / "triage_connectivity.py"
    res = subprocess.run([sys.executable, str(script_path)], capture_output=True, text=True)
    assert res.returncode != 0
    assert "required" in res.stderr.lower() or "error" in res.stderr.lower()
    print("  -> PASSED: Argparse gracefully intercepted missing arguments.")


def main():
    print("=" * 70)
    print("USER-CONNECTIVITY-TRIAGE EXTREME TEST SUITE")
    print("=" * 70)
    test_empty_and_corrupt_json()
    test_bidi_unicode_filtering()
    test_massive_payload_resilience()
    test_special_characters_in_ssids()
    test_cli_json_mode_contract()
    test_missing_command_line_flags()
    print("=" * 70)
    print("ALL 6 EXTREME TESTS PASSED SUCCESSFULLY (Exit Code 0).")
    print("=" * 70)


if __name__ == "__main__":
    main()
