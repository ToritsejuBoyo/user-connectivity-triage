# 7-Layer Connectivity Diagnostic Decision Tree

This reference specifies the decision heuristics utilized by `user-connectivity-triage` to systematically diagnose network disruptions from endpoint telemetry.

---

## 1. Decision Flowchart

```text
[ START TELEMETRY INTAKE ]
          │
          ▼
[ Check Airplane Mode / Disabled NICs? ] ── YES ──> [ FAIL: Layer 1 (Physical / Radio Off) ]
          │ NO
          ▼
[ Wi-Fi Connected with Signal < 25%? ]   ── YES ──> [ WARN: Layer 2 (Weak Signal / RSSI Low) ]
          │ NO
          ▼
[ IP is 169.254.x.x (APIPA) or Missing? ] ─ YES ──> [ FAIL: Layer 3 (DHCP Scope Exhaustion) ]
          │ NO
          ▼
[ Gateway Ping 100% Loss or RTT > 350ms? ] ─ YES ──> [ FAIL/WARN: Layer 4 (Gateway Unreachable) ]
          │ NO
          ▼
[ All DNS Lookups Failing / Timing Out? ] ── YES ──> [ FAIL: Layer 5 (DNS Resolver Failure) ]
          │ NO
          ▼
[ HTTP Probe Returning 302 Redirect? ]    ── YES ──> [ FAIL: Layer 6 (Captive Portal Intercept) ]
          │ NO
          ▼
[ VPN Connected but Missing Route Table? ] ── YES ──> [ FAIL: Layer 7 (VPN Split Tunnel / Route Leak) ]
          │ NO
          ▼
[ ALL NETWORK LAYERS OPERATIONAL (PASS) ]
```

---

## 2. Layer-by-Layer Heuristic Rubric

### Layer 1: Physical Link & Radio Hardware
- **Failure Condition:** `airplane_mode == True` or `all(adapter.status != 'Up')` or `len(adapters) == 0`.
- **Operational Meaning:** No physical electron flow or radio frequency connection exists between the NIC and the medium.
- **Immediate L1 Action:** Toggle Airplane Mode off; verify docking cable / Ethernet cable; check Windows Device Manager.

### Layer 2: Data Link / Wi-Fi Association
- **Failure Condition:** `wifi.connected == True` and `wifi.signal_percent < 25`.
- **Operational Meaning:** Excessive RF attenuation, multi-path fading, or AP distance causing frame retransmission timeouts.
- **Immediate L1 Action:** Move closer to access point; switch from 2.4GHz to 5GHz band; connect to Ethernet.

### Layer 3: Network / IP & DHCP Configuration
- **Failure Condition:** IPv4 starts with `169.254.` (APIPA) or `len(ipv4_addresses) == 0`.
- **Operational Meaning:** Windows failed to receive a `DHCPOFFER` / `DHCPACK` response within 60 seconds and fell back to Automatic Private IP Addressing.
- **Immediate L1 Action:** Power-cycle local modem/router; execute `ipconfig /renew`; verify switch port VLAN helper.

### Layer 4: Transport & Gateway Reachability
- **Failure Condition:** Default gateway packet loss $\ge 100\%$ or `avg_rtt_ms > 350.0`.
- **Operational Meaning:** The endpoint has a valid IP address on the subnet, but cannot resolve ARP or transmit frames to the next-hop default router.
- **Immediate L1 Action:** Verify gateway IP matches subnet mask; clear ARP cache (`arp -d *`); verify router power.

### Layer 5: Application / DNS Resolution
- **Failure Condition:** Gateway reachable, but all canary DNS lookups (`dns.google`, corporate FQDN) fail with `SERVFAIL`, `NXDOMAIN`, or timeout.
- **Operational Meaning:** Local network stack functions, but name-to-address translation is blocked or misconfigured.
- **Immediate L1 Action:** Run `ipconfig /flushdns`; verify DNS IP configuration; test `Resolve-DnsName -Server 1.1.1.1`.

### Layer 6: Application / Captive Portal Interception
- **Failure Condition:** `http_probe.is_captive_portal == True` (returns HTTP 301/302 redirect or non-Microsoft HTML body).
- **Operational Meaning:** Upstream router intercepts outbound port 80/443 traffic and directs browser to an unauthenticated billing/terms portal.
- **Immediate L1 Action:** Navigate user browser to `http://neverssl.com` to force hotel/airport authentication.

### Layer 7: Application / Corporate VPN Tunnel
- **Failure Condition:** VPN adapter reports `Up`, but corporate subnets are missing from the routing table or DNS lookups leak to public resolvers.
- **Operational Meaning:** Virtual interface established, but split-tunnel policy or default route push failed.
- **Immediate L1 Action:** Reconnect VPN profile; verify client version; inspect gateway route push configuration.
