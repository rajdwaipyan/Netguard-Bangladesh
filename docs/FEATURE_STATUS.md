# Feature Status

Status definitions: **fully implemented and tested**, **partially implemented**,
**simulated**, **not implemented**, **hardware-dependent**, and
**platform-dependent**.

| Feature | Status | Notes |
|---|---|---|
| Tkinter dashboard | Partially implemented | Main window exists; multiple actions are placeholders |
| JSON history persistence | Partially implemented | No schema versioning or atomic writes |
| Ping monitoring | Partially implemented | Uses a real Windows ping probe; packet loss remains single-probe scoped |
| Device observation | Partially implemented | Reads ARP cache and merges opt-in IPv4 ICMP evidence |
| Interface discovery | Partially implemented | Parses Windows `ipconfig /all`; user selection is required |
| Authorized active discovery | Partially implemented | Bounded ICMP probing on approved private/link-local IPv4 subnets |
| Device history | Partially implemented | Tracks observed, previously observed, unknown, and mapping changes |
| Attack detection | Partially implemented | Legacy heuristics consume probe data but are not validated compromise detection |
| Attack history export | Partially implemented | Exports local JSON-derived records |
| Router identification (Phase 3A) | Partially implemented | Identifies the selected interface gateway from `ipconfig /all` and matching ARP-cache evidence; model/firmware remain unknown unless explicitly entered and marked unverified |
| Router management assessment (Phase 3B) | Partially implemented | Authorized, read-only TCP checks and minimal HTTP/TLS evidence against the revalidated local gateway; no credentials, exploitation, internet exposure, or vulnerability confirmation |
| UPnP security intelligence (Phase 3C) | Partially implemented | Authorized IPv4 SSDP discovery, bounded local device-description retrieval, conservative device/service observations, and JSON history |
| DNS security intelligence (Phase 3C) | Partially implemented | Windows DNS configuration parsing and consent-gated actual UDP A/AAAA resolver queries; DNSSEC and encrypted DNS are not assessed |
| Router vulnerability scan | Not implemented | Legacy random assessment is disabled; no findings are shown |
| Speed test | Not implemented | Placeholder methods |
| ISP selection | Partially implemented | Manual selection only; default is not configured |
| Wi-Fi security intelligence | Partially implemented / platform-dependent | Windows `netsh wlan` adapter, driver, current-connection, nearby-BSSID, signal/channel, and authentication/cipher observations; baseline findings are informational only |
| Packet capture | Not implemented | No Scapy/Npcap integration |
| Windows endpoint security | Not implemented | No Defender, firewall, event-log, or process adapters |
| Threat intelligence | Not implemented | No NVD/CISA/URLhaus/etc. clients |
| SQLite database | Not implemented | JSON is the only persistence mechanism |
| Bengali localization | Not implemented | No localization layer |
| Automated tests | Partially implemented | Deterministic unittest coverage for discovery, router/Wi-Fi intelligence, CPE/version matching, NVD/KEV parsing, persistence, and worker behavior |

IPv6 neighbor discovery, DHCP evidence, OUI/vendor lookup, reliable hostname
resolution, firmware intelligence, SQLite migrations, and complete active
network inventory remain unimplemented. Gateway identification does not test management
interfaces, credentials, firmware, internet exposure, or vulnerabilities. The
application must not describe ARP or ICMP results as a complete list of
connected devices.

UPnP discovery is currently IPv4-only and does not verify control actions,
port mappings, or internet exposure. DNS comparisons remain optional and
conservative; differing answers are not treated as poisoning or hijacking.

Wireless observations require Windows WLAN support and a client-mode adapter.
They are limited to what `netsh wlan` exposes; hidden networks, unsupported
drivers, and unavailable fields remain unknown. Nearby BSSID observations are
not packet capture, cannot prove ownership, and do not confirm an evil twin or
rogue access point. Baseline changes are informational and require manual
investigation.

Firmware vulnerability intelligence is partially implemented and evidence
limited. Router products can be registered with explicit verification status;
manual official advisories, product-specific NVD records, CPE configuration
logic, version ranges, CISA KEV status, freshness, offline cache fallback, and
read-only update recommendations are supported. Live synchronization requires
explicit user consent and HTTPS. A KEV entry alone does not establish product
applicability, and no-match or unavailable intelligence is not proof of
security. Automatic firmware downloads or installation are not implemented.
