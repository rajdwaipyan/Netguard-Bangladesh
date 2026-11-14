# NetGuard Bangladesh User Guide

## Gateway identification (Phase 3A)

Select an interface and choose **Identify Gateway** to record the default
gateway reported by Windows. If the gateway is present in the current ARP
cache, its MAC address is shown as an ARP-cache observation. The application
does not claim that this proves the router is online or identifies its model.
Management services, UPnP, DNS, firmware, credentials, internet exposure, and
Wi-Fi settings are not assessed.

## Router management assessment (Phase 3B)

After identifying the gateway, choose **Assess Gateway Services**. The
application revalidates the selected interface and current gateway, displays
the target, and requests explicit authorization. Only that local gateway is
assessed; no subnet or public address scan is performed.

The assessment makes bounded TCP connection checks for FTP (21), SSH (22),
Telnet (23), DNS/TCP (53), HTTP (80/8080), and HTTPS (443/8443). `OPEN` means
the gateway accepted a TCP connection from this computer. `REFUSED`, `TIMEOUT`,
and `ERROR` have different meanings; a timeout does not prove that a port is
closed. An open service is not automatically a vulnerability and does not prove
internet exposure.

HTTP assessment sends one minimal request and does not submit credentials,
forms, scripts, or follow redirects. HTTPS uses certificate validation.
self-signed certificates and hostname mismatches require investigation but do
not prove compromise. Use **Cancel Assessment** to request cancellation.

## UPnP security

After selecting an IPv4 private interface, choose **Discover UPnP Devices** and
explicitly authorize the local SSDP discovery. Results are local observations
of device responses and advertised services. An Internet Gateway Device or
service advertisement does not prove a vulnerability, port mapping, or
internet exposure. Device descriptions are retrieved only from validated local
literal IP addresses; redirects and unsafe XML are rejected.

## DNS security

Choose **Inspect DNS Configuration** to read resolver addresses associated with
the selected Windows interface without sending DNS queries. To perform a
resolver test, enter a domain and explicitly authorize the query. Only A and
AAAA queries are supported. Timeouts, SERVFAIL, NXDOMAIN, and response
differences are recorded as evidence; they do not prove DNS hijacking.
DNSSEC, DNS-over-HTTPS, DNS-over-TLS, and DNS-over-QUIC are not assessed.

## Selecting an interface

Open the application and use **Refresh** beside **Interface**. Select the
Ethernet, Wi-Fi, VPN, or virtual adapter you want to inspect. NetGuard shows
the adapter category, operational state, IPv4 address, directly connected
network, and gateway. It never silently selects the first adapter.

Interface information is collected from Windows `ipconfig /all`. If Windows
does not expose a valid IPv4 address and subnet mask, active IPv4 discovery is
unavailable for that adapter.

## ARP-cache observation

**Scan Network Devices** reads the local Windows ARP cache. This is a
read-only observation of IP-to-MAC mappings. It does not prove that a device is
online, safe, currently connected, or the complete set of network devices.
Records are labeled `OBSERVED_IN_ARP_CACHE`, and older records become
`PREVIOUSLY_OBSERVED` when absent from a later observation.

## Authorized active discovery

Select an interface, then choose **Active Discovery**. NetGuard displays the
exact directly connected subnet and asks for explicit authorization before
probing it. Only private or link-local IPv4 subnets are accepted. Public,
loopback, multicast, invalid, and missing scopes are rejected. Large networks
require an additional approval.

The active method uses bounded ICMP reachability probes. A response is labeled
`ACTIVELY_DISCOVERED`; an ARP cache record merged with that response is still
shown with both evidence sources. A failed ping does not prove that a device is
offline. Use **Stop Discovery** to request cancellation.

## Device inventory and trust

The inventory shows IP, MAC, vendor/type evidence, observation status, source,
last observation time, and trust state. Vendor lookup and device category
inference are intentionally conservative; unknown evidence remains Unknown.
**Toggle Trusted** records an administrative trust preference but does not hide
or suppress future observations and anomalies.

Mapping changes retain old and new addresses and are reported as informational
anomalies. DHCP reassignment, device replacement, proxy ARP, virtual machines,
and topology changes are possible explanations; the application does not
confirm ARP spoofing from a mapping change alone.

## Permissions and limitations

No administrator privilege is required for the standard Windows command
adapters, but local policy, firewall rules, drivers, or endpoint security
software may limit results. Npcap, packet capture, IPv6 neighbor discovery,
DHCP inspection, OUI databases, and active router assessment are not enabled in
this phase. Never scan a network unless you are authorized to assess it.

## Wi-Fi Security Intelligence

Click **Inspect Wi-Fi** and explicitly authorize the read-only Windows WLAN
inspection. The application reports the current connection, nearby BSSID
observations, signal/channel data, and conservative findings. Use **Set
Wireless Baseline** only after reviewing the expected access points.

Wireless findings are informational. A new BSSID, open network, or weaker
security report may be legitimate because of mesh roaming, guest networks,
router replacement, randomized addresses, or driver limitations. NetGuard does
not confirm rogue access points, capture traffic, read credentials, or connect
to networks. Missing fields are shown as unavailable.

## Firmware & Vulnerability Intelligence

Enter the exact router manufacturer and model, and optionally the hardware
revision, region, firmware version, and build. Click **Register**. Registration
is marked `USER_PROVIDED_UNVERIFIED`; it does not infer identity from MAC
addresses, ISP, or management banners.

After confirming you are authorized to retrieve public intelligence, click
**Sync NVD/KEV**. The application sends only the public manufacturer/model
search term to the official NVD service and retrieves the public CISA KEV feed.
It does not send private IP addresses, MAC addresses, credentials, or router
configuration. Use **Cancel Sync** to stop the worker.

Results distinguish exact verified, strong, possible, product-with-unknown-
firmware, no-match, and insufficient-data outcomes. A no-match result does not
mean the router is secure. A CISA KEV entry is shown as a prioritization signal
only after product applicability is established. Cached results are labeled
outdated or incomplete when synchronization fails.

Firmware recommendations link only to recorded official advisory information.
NetGuard never downloads firmware, uploads it to a router, changes router
configuration, or installs an update. Back up configuration and follow the
manufacturer's official installation and post-update verification instructions.
