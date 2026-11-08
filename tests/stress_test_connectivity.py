#!/usr/bin/env python3
"""
High-Volume Stress Benchmark for user-connectivity-triage.
Triages 10,000 full network diagnostic JSON payloads across 7 failure scenarios.
Asserts total evaluation time is under 2.0 seconds (> 5,000 payloads/second).
"""

import json
import sys
import time
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_ROOT / "scripts"))

from triage_connectivity import (
    ConnectivityTriageEngine,
    TelemetrySanitizer,
)

FIXTURES_DIR = SKILL_ROOT / "tests" / "fixtures"


def run_benchmark():
    print("=" * 70)
    print("USER-CONNECTIVITY-TRIAGE HIGH-VOLUME STRESS BENCHMARK (10,000 PAYLOADS)")
    print("=" * 70)

    # Load 7 synthetic fixture templates
    templates = []
    for p in FIXTURES_DIR.glob("*.json"):
        with open(p, "r", encoding="utf-8") as f:
            templates.append(json.load(f))

    assert len(templates) >= 7, f"Expected 7 fixture templates, got {len(templates)}"

    # Generate 10,000 payloads in memory
    print(f"[STEP 1] Generating 10,000 diverse network diagnostic payloads...")
    t0_gen = time.perf_counter()
    payloads = []
    for i in range(10000):
        base = json.loads(json.dumps(templates[i % len(templates)]))
        base["hostname"] = f"synthetic-node-{i:05d}.corp.example.com"
        payloads.append(base)
    t1_gen = time.perf_counter()
    print(f"  -> Generated 10,000 payloads in {t1_gen - t0_gen:.3f}s")

    print("[STEP 2] Triaging 10,000 payloads through 7-layer decision tree with sanitization...")
    sanitizer = TelemetrySanitizer(salt="stress-benchmark-salt")
    t0_triage = time.perf_counter()
    for p in payloads:
        clean = sanitizer.sanitize_bundle(p)
        engine = ConnectivityTriageEngine(clean)
        findings = engine.evaluate()
        assert len(findings) >= 1
    t1_triage = time.perf_counter()

    duration = t1_triage - t0_triage
    throughput = 10000 / duration
    print("-" * 70)
    print(f"TOTAL TRIAGE EXECUTION TIME: {duration:.3f}s")
    print(f"THROUGHPUT: {throughput:,.0f} diagnoses/second")
    print("-" * 70)

    # SLA assertion: under 2.0 seconds
    assert duration < 2.0, f"Benchmark exceeded 2.0s SLA limit: {duration:.3f}s"
    print("PERFORMANCE BENCHMARK PASSED: Under 2.0s SLA met.")
    print("=" * 70)
    print("STRESS TEST COMPLETED SUCCESSFULLY (Exit Code 0).")
    print("=" * 70)


if __name__ == "__main__":
    run_benchmark()
