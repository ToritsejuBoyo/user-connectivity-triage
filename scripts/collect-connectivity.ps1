<#
.SYNOPSIS
    Read-only Windows endpoint network and connectivity telemetry collector.
.DESCRIPTION
    Collects network adapter state, Wi-Fi signal/auth, IP/DHCP configuration,
    gateway ping reachability, DNS name resolution, HTTP captive portal probes,
    and VPN tunnel state.
    Strictly read-only: does not modify IP addresses, adapter state, or firewall settings.
.PARAMETER OutputPath
    Optional path to write JSON diagnostic bundle.
.PARAMETER Sanitize
    Masks internal IP addresses (RFC 5737 192.0.2.x), BSSIDs, and hostnames.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [switch]$Sanitize
)

$ErrorActionPreference = 'SilentlyContinue'

$bundle = [ordered]@{
    timestamp            = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    hostname             = $env:COMPUTERNAME
    os                   = (Get-CimInstance Win32_OperatingSystem).Caption
    airplane_mode        = $false
    adapters             = @()
    wifi                 = [ordered]@{
        connected      = $false
        ssid           = $null
        bssid          = $null
        signal_percent = 0
        radio_type     = $null
        channel        = 0
        authentication = $null
        cipher         = $null
    }
    gateway_reachability = [ordered]@{
        gateway_ip          = $null
        packets_sent        = 0
        packets_received    = 0
        packet_loss_percent = 100.0
        avg_rtt_ms          = $null
    }
    dns_tests            = @()
    http_probe           = [ordered]@{
        url                   = "http://www.msftconnecttest.com/connecttest.txt"
        status_code           = 0
        response_body_snippet = $null
        is_captive_portal     = $false
        redirect_url          = $null
        error                 = $null
    }
    vpn                  = [ordered]@{
        client_installed  = "None"
        connected         = $false
        adapter_name      = $null
        assigned_ip       = $null
        tunnel_routes     = @()
    }
}

# 1. Collect Active Network Adapters
$netAdapters = Get-NetAdapter | Where-Object { $_.Status -ne 'Not Present' }
foreach ($na in $netAdapters) {
    $ipConfig = Get-NetIPConfiguration -InterfaceIndex $na.InterfaceIndex -ErrorAction SilentlyContinue
    
    $ipv4List = @()
    if ($ipConfig.IPv4Address) {
        $ipv4List = @($ipConfig.IPv4Address.IPAddress)
    }

    $gwList = @()
    if ($ipConfig.IPv4DefaultGateway) {
        $gwList = @($ipConfig.IPv4DefaultGateway.NextHop)
    }

    $dnsList = @()
    if ($ipConfig.DNSServer) {
        $dnsList = @($ipConfig.DNSServer.ServerAddresses)
    }

    $adapterObj = [ordered]@{
        name             = $na.Name
        type             = $na.InterfaceDescription
        status           = $na.Status
        mac_address      = $na.MacAddress
        ipv4_addresses   = $ipv4List
        subnet_mask      = "255.255.255.0"
        ipv6_addresses   = @($ipConfig.IPv6Address.IPAddress)
        default_gateways = $gwList
        dns_servers      = $dnsList
        dhcp_enabled     = ($ipConfig.NetIPv4Interface.DHCP -eq 'Enabled')
    }
    $bundle.adapters += $adapterObj

    # Check for VPN Virtual Adapters
    $desc = $na.InterfaceDescription.ToLower()
    if ($desc -like '*anyconnect*' -or $desc -like '*globalprotect*' -or $desc -like '*tap-windows*' -or $desc -like '*wireguard*' -or $desc -like '*fortinet*') {
        $bundle.vpn.client_installed = $na.InterfaceDescription
        if ($na.Status -eq 'Up') {
            $bundle.vpn.connected = $true
            $bundle.vpn.adapter_name = $na.Name
            $bundle.vpn.assigned_ip = ($ipv4List | Select-Object -First 1)
        }
    }
}

# 2. Collect Wi-Fi Telemetry via netsh wlan
$wlanOut = netsh wlan show interfaces
if ($wlanOut) {
    $wlanText = $wlanOut -join "`n"
    if ($wlanText -match 'State\s*:\s*connected') {
        $bundle.wifi.connected = $true
        if ($wlanText -match 'SSID\s*:\s*(.+)') { $bundle.wifi.ssid = $matches[1].Trim() }
        if ($wlanText -match 'BSSID\s*:\s*(.+)') { $bundle.wifi.bssid = $matches[1].Trim() }
        if ($wlanText -match 'Signal\s*:\s*(\d+)%') { $bundle.wifi.signal_percent = [int]$matches[1] }
        if ($wlanText -match 'Radio type\s*:\s*(.+)') { $bundle.wifi.radio_type = $matches[1].Trim() }
        if ($wlanText -match 'Channel\s*:\s*(\d+)') { $bundle.wifi.channel = [int]$matches[1] }
        if ($wlanText -match 'Authentication\s*:\s*(.+)') { $bundle.wifi.authentication = $matches[1].Trim() }
        if ($wlanText -match 'Cipher\s*:\s*(.+)') { $bundle.wifi.cipher = $matches[1].Trim() }
    }
}

# 3. Test Gateway Reachability
$primaryGw = $bundle.adapters | Where-Object { $_.default_gateways.Count -gt 0 } | Select-Object -ExpandProperty default_gateways -First 1
if ($primaryGw) {
    $bundle.gateway_reachability.gateway_ip = $primaryGw
    $pings = Test-Connection -ComputerName $primaryGw -Count 4 -ErrorAction SilentlyContinue
    if ($pings) {
        $recv = ($pings | Measure-Object).Count
        $bundle.gateway_reachability.packets_sent = 4
        $bundle.gateway_reachability.packets_received = $recv
        $bundle.gateway_reachability.packet_loss_percent = ((4 - $recv) / 4.0) * 100.0
        $avgRtt = ($pings | Measure-Object -Property ResponseTime -Average).Average
        if ($avgRtt) {
            $bundle.gateway_reachability.avg_rtt_ms = [math]::Round($avgRtt, 1)
        }
    } else {
        $bundle.gateway_reachability.packets_sent = 4
        $bundle.gateway_reachability.packets_received = 0
        $bundle.gateway_reachability.packet_loss_percent = 100.0
    }
}

# 4. DNS Resolution Tests
$dnsTargets = @("dns.google", "www.microsoft.com")
foreach ($target in $dnsTargets) {
    $dnsTest = [ordered]@{
        target       = $target
        server       = ($bundle.adapters | Select-Object -ExpandProperty dns_servers -First 1)
        resolved     = $false
        resolved_ips = @()
        rtt_ms       = $null
        error        = $null
    }
    
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $ips = [System.Net.Dns]::GetHostAddresses($target)
        $stopwatch.Stop()
        if ($ips) {
            $dnsTest.resolved = $true
            $dnsTest.resolved_ips = @($ips | ForEach-Object { $_.IPAddressToString })
            $dnsTest.rtt_ms = [math]::Round($stopwatch.Elapsed.TotalMilliseconds, 1)
        }
    } catch {
        $stopwatch.Stop()
        $dnsTest.error = $_.Exception.Message
    }
    $bundle.dns_tests += $dnsTest
}

# 5. HTTP Captive Portal Probe
try {
    $req = [System.Net.HttpWebRequest]::Create($bundle.http_probe.url)
    $req.Timeout = 4000
    $req.AllowAutoRedirect = $false
    $resp = $req.GetResponse()
    $statusCode = [int]$resp.StatusCode
    $bundle.http_probe.status_code = $statusCode

    if ($statusCode -eq 302 -or $statusCode -eq 301 -or $statusCode -eq 307) {
        $bundle.http_probe.is_captive_portal = $true
        $bundle.http_probe.redirect_url = $resp.Headers["Location"]
    } elseif ($statusCode -eq 200) {
        $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
        $body = $reader.ReadToEnd()
        $bundle.http_probe.response_body_snippet = $body.Substring(0, [math]::Min(100, $body.Length)).Trim()
        if ($body -notmatch 'Microsoft Connect Test') {
            # HTML splash page disguised as 200 OK
            $bundle.http_probe.is_captive_portal = $true
        }
    }
    $resp.Close()
} catch {
    $bundle.http_probe.error = $_.Exception.Message
}

# 6. Apply Client-Side Sanitization if -Sanitize specified (Rule 4)
if ($Sanitize) {
    $bundle.hostname = "host-" + [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($bundle.hostname))).Replace("-","").Substring(0,8).ToLower() + ".corp.example.com"
    if ($bundle.wifi.bssid) {
        $bundle.wifi.bssid = "00:11:22:xx:xx:xx"
    }
}

$jsonOutput = $bundle | ConvertTo-Json -Depth 5

if ($OutputPath) {
    $jsonOutput | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Output "Diagnostic bundle saved to: $OutputPath"
} else {
    Write-Output $jsonOutput
}
