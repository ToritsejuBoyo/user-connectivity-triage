---
name: user-connectivity-triage
description: >-
  Diagnoses endpoint Wi-Fi, DHCP, DNS, Captive Portal, and VPN failures across a 7-layer decision
  tree from read-only telemetry. Use when a user cannot reach the network or a specific
  application, Wi-Fi associates but has no traffic, DHCP or DNS resolution fails, a captive portal
  blocks corporate access, or a VPN tunnel fails or leaks DNS.
license: MIT
version: 1.0.0
metadata:
  standard: agentskills.io
  dependencies: none (Python standard library only)
  access: read-only collectors; no state is modified on target systems
---

# User Connectivity Triage (`user-connectivity-triage`)

A deterministic, offline Level 1 Help Desk diagnostic skill and decision-tree engine that pinpoints network disconnects from endpoint telemetry. Evaluates network adapter state, Wi-Fi signal/auth, DHCP/APIPA addressing, gateway ping reachability, DNS query latency, captive portal redirection, and VPN tunnel routing to produce plain-English root cause analyses, step-by-step user resolution instructions, and pre-formatted L2/L3 escalation tickets.

---

## 1. Capabilities & Supported Triage Layers

1. **Layer 1: Physical Link & Radio Hardware:**
   - Detects airplane mode, disabled network adapters, unplugged Ethernet cables, and missing NIC controller drivers.
2. **Layer 2: Data Link / Wi-Fi Association:**
   - Evaluates Wi-Fi connection state, RSSI signal percentage ($< 25\%$ critical threshold), channel interference, and 802.1X enterprise authentication failures.
3. **Layer 3: Network / IP & DHCP Configuration:**
   - Flags Automatic Private IP Addressing (`169.254.x.x` APIPA), missing default gateways, and expired DHCP leases.
4. **Layer 4: Transport & Gateway Reachability:**
   - Analyzes ICMP ping loss to local default gateway (100% loss vs high latency $> 350\text{ms}$ bufferbloat).
5. **Layer 5: Application / DNS Name Resolution:**
   - Validates local gateway reachability against public and corporate canary DNS queries (`dns.google`, internal FQDNs). Diagnoses `SERVFAIL`, `NXDOMAIN`, and resolver timeouts.
6. **Layer 6: Application / Captive Portal Interception:**
   - Detects hotel, airport, and coffee shop Wi-Fi captive portal splash redirects (HTTP 301/302/307 or HTML login bodies) that block corporate VPN handshakes.
7. **Layer 7: Application / Corporate VPN Tunnel:**
   - Inspects Cisco AnyConnect, Palo Alto GlobalProtect, Fortinet, and WireGuard virtual adapters for missing corporate routing tables and split-brain DNS leaks.

---

## 2. Command Reference

### Step 1: Endpoint Telemetry Collection (Read-Only)

**On Windows PowerShell:**
```powershell
# Collect read-only diagnostic bundle with client-side sanitization
powershell -ExecutionPolicy Bypass -File scripts/collect-connectivity.ps1 -Sanitize -OutputPath telemetry.json
```

**On Cross-Platform Python (Windows, macOS, Linux):**
```bash
python scripts/collect_connectivity.py --sanitize -o telemetry.json
```

### Step 2: Diagnostic Evaluation & Ticket Generation

**Console Summary:**
```bash
python scripts/triage_connectivity.py -i telemetry.json
```

**Full Triage with Markdown Report & ITSM Escalation Ticket:**
```bash
python scripts/triage_connectivity.py \
  -i telemetry.json \
  --sanitize \
  -o connectivity_report.md \
  --generate-tickets escalation_ticket.md
```

**Programmatic JSON Mode for Autonomous Agent Integration:**
```bash
python scripts/triage_connectivity.py -i telemetry.json --json
```

---

## 3. Autonomous Agent Execution Guidelines

When an agent receives user complaints such as "My internet is down", "I can't open company websites", or "VPN won't connect":
1. Execute or request execution of `collect-connectivity.ps1 -Sanitize` or `collect_connectivity.py --sanitize`.
2. Ingest the resulting JSON with `triage_connectivity.py --json`.
3. Read the `layer_number`, `status`, and `root_cause`.
4. Provide the user with the exact 3-step non-destructive self-service commands from `remediation_user`.
5. If the failure requires network engineering intervention (e.g. DHCP pool exhaustion, gateway outage, DNS forwarder crash), generate the pre-formatted L2/L3 ticket from `remediation_admin`.

---

## Bundled Resources

Load these on demand — they hold the decision logic behind the 7-layer triage tree.

- **7-Layer Decision Tree:** [`references/7-layer-connectivity-decision-tree.md`](references/7-layer-connectivity-decision-tree.md) — Authoritative specification of the decision heuristics used to diagnose network disruptions from endpoint telemetry. **Consult before issuing any layer verdict.**
- **Captive Portal Rubric:** [`references/captive-portal-detection-rubric.md`](references/captive-portal-detection-rubric.md) — How hotel/airport/cafe splash screens are detected and distinguished from DNS and VPN failures.
- **VPN Split-Tunnel Guide:** [`references/vpn-split-tunnel-triage-guide.md`](references/vpn-split-tunnel-triage-guide.md) — Enterprise VPN failure modes and DNS leak analysis. **Consult for any Layer 7 verdict.**
- **Diagnostic Report Template:** [`assets/connectivity-report-template.md`](assets/connectivity-report-template.md) — Structured user connectivity diagnostic report.
- **L2 Escalation Template:** [`assets/l2-escalation-ticket-template.md`](assets/l2-escalation-ticket-template.md) — ITSM L2/L3 escalation brief.

---

## Data Handling & Sanitization

Sanitization runs **client-side, before any output is produced**, so credentials and
personal data are removed on the operator's machine rather than being sent to a model
or pasted into a ticket.

Two layers apply:

1. This skill's own domain-aware masking (hostnames, accounts, and the identifiers
   specific to this domain).
2. A shared residual pass, [`scripts/sanitizer.py`](scripts/sanitizer.py), vendored
   identically across every skill in the library. It is the common floor: private keys,
   cloud provider keys, JWTs and bearer tokens, connection-string passwords, assigned
   secrets, emails, IPv4/IPv6 addresses, MAC addresses, GUIDs, SSNs, payment card
   numbers, and phone numbers.

The contract is enforced by `tests/sanitizer_conformance_test.py`, which runs the same
adversarial corpus in every skill. Documentation placeholders (RFC 5737/3849 addresses,
RFC 7042 MAC ranges, `example.com` names, and existing `[REDACTED-*]` tokens) are
preserved, so the pass is safe to apply more than once.

Sanitization is thorough and tested, but it is not a substitute for reading output
before sharing it outside your organization.
