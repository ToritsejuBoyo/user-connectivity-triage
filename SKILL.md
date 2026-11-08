---
name: user-connectivity-triage
description: Diagnoses endpoint Wi-Fi, DHCP, DNS, Captive Portal, and VPN failures across a 7-layer decision tree from read-only telemetry.
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
