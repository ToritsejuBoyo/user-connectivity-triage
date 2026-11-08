# VPN Split-Tunnel & DNS Leak Triage Guide

This reference details common enterprise VPN failure modes diagnosed by `user-connectivity-triage` at Layer 7.

---

## 1. Full Tunnel vs Split Tunnel

Enterprise remote access VPNs (Cisco AnyConnect, Palo Alto GlobalProtect, Fortinet FortiClient, Zscaler Private Access) operate in two primary modes:

| Mode | Traffic Flow | Failure Symptom |
| :--- | :--- | :--- |
| **Full Tunnel** | 100% of endpoint traffic traverses the encrypted tunnel through the enterprise datacenter. | User loses all internet access if corporate egress proxy fails or MTU blackhole occurs. |
| **Split Tunnel** | Only corporate CIDR blocks (`10.0.0.0/8`, `172.16.0.0/12`) traverse the tunnel; public traffic egresses the local home router. | User can browse Google, but internal portals (`intranet.corp.local`) fail to load. |

---

## 2. Common Layer 7 VPN Failures

### 1. Missing Corporate Route Push
- **Symptom:** VPN client status says "Connected", but pinging internal server `10.50.2.1` fails with `General Failure` or routes to the local home gateway.
- **Root Cause:** The VPN headend gateway failed to push static routing table entries to the endpoint virtual interface.
- **Verification:** Run `route print` or `Get-NetRoute` to inspect if target enterprise subnets exist with interface index matching the VPN adapter.

### 2. Split-Brain DNS Leak
- **Symptom:** Pinging internal server by IP works, but pinging `intranet.corp.example.com` returns `NXDOMAIN`.
- **Root Cause:** The endpoint's primary Wi-Fi adapter DNS server (`1.1.1.1` or `192.168.1.1`) is queried ahead of the VPN virtual adapter's DNS server (`10.0.0.10`). Because public DNS does not know internal enterprise hostnames, the lookup fails.
- **Verification:** Run `Resolve-DnsName intranet.corp.example.com` and inspect which server answered.

### 3. MTU Blackhole
- **Symptom:** Small ping packets (64 bytes) succeed, but large file transfers, Outlook sync, and web portal logins freeze or hang indefinitely.
- **Root Cause:** Encrypted VPN packet overhead causes packet size to exceed the local home ISP's MTU (typically 1500 or 1492 for PPPoE), resulting in packet drops without ICMP "Fragmentation Needed" notifications.
- **Resolution:** Reduce VPN virtual adapter MTU to `1350` or `1300`:
  ```powershell
  netsh interface ipv4 set subinterface "Palo Alto GlobalProtect" mtu=1350 store=persistent
  ```
