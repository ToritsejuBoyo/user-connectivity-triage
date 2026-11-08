# Captive Portal Detection Rubric

This reference explains how `user-connectivity-triage` detects and handles Wi-Fi captive portals (hotel, airport, cafe splash screens) that prevent corporate application and VPN connectivity.

---

## 1. How Captive Portals Interfere with Enterprise IT

When mobile employees connect to hotel, airport, or conference Wi-Fi:
1. The endpoint successfully receives a valid local DHCP IP (e.g., `10.100.5.42`) and gateway.
2. Standard ICMP pings to the gateway succeed.
3. However, any outbound HTTP or HTTPS packet is intercepted by a firewall/gateway and redirected to a login page.
4. Corporate VPN clients (Cisco AnyConnect, GlobalProtect, Zscaler) fail to connect because their handshake packets are blocked before user authentication on the portal.
5. Users assume "The corporate VPN is broken" and submit high-priority Help Desk tickets.

---

## 2. Detection Mechanism

The collector executes a lightweight probe to Microsoft's standard Network Connectivity Status Indicator (NCSI) endpoint:

```http
GET http://www.msftconnecttest.com/connecttest.txt HTTP/1.1
Host: www.msftconnecttest.com
```

### Expected Behavior on Open Internet
- **HTTP Status Code:** `200 OK`
- **Response Body:** `Microsoft Connect Test`

### Captive Portal Indicators
1. **HTTP 302 / 301 / 307 Redirect:** The router responds with a redirect header pointing to a landing page (e.g., `Location: https://wifi.hotelportal.example/login`).
2. **HTML Body on Port 80:** The router returns `200 OK`, but the body contains an HTML splash screen rather than the expected text `Microsoft Connect Test`.

---

## 3. Help Desk Resolution Script

When Layer 6 is flagged:
1. **Direct User:** "Your internet connection is paused by the hotel/guest Wi-Fi login portal. Before corporate VPN can connect, you must accept their terms."
2. **Force Splash Screen:** Instruct the user to open Edge or Chrome and navigate to `http://neverssl.com` (an unencrypted HTTP domain that prevents HTTPS certificate warnings when the portal redirects).
3. **Reconnect VPN:** Once authenticated on the portal, launch the corporate VPN client.
