# NetGuard Bangladesh Security Audit

## Scope

This audit covers the files present in the workspace at the start of Phase 1:
`netguard_bangladesh.py` and `index.html`. No tests, dependency manifest,
workflow, or documentation set was present.

## Original findings

### Fabricated telemetry and findings

- `ping_router()` returns random latency, loss, and timeout values instead of
  probing the configured address.
- `scan_devices()` creates random IP and MAC addresses.
- The default ISP is selected randomly and its vulnerability list is treated as
  if it were evidence about the user's router.
- `simulate_random_attack()` creates arbitrary attack records.
- `simulate_vulnerability_scan()` creates random router vulnerabilities and
  includes unsupported Bangladesh-specific claims.

These behaviors can mislead a user into believing an attack or vulnerability
was observed. They are not acceptable for a security product.

### Unsafe concurrency

Monitoring and router-scan worker threads update Tkinter variables and widgets
directly. Tkinter is not thread-safe; this can freeze or crash the application.
The monitoring thread also calls synchronous scans from its worker.

### Incomplete functionality

Several user-facing actions are `pass` placeholders, including device details,
preferences, speed tests, alert settings, tutorials, and the about dialog.

### Weak persistence and error handling

- State is stored in one unversioned JSON file.
- Writes are not atomic and can lose history on interruption.
- Broad exception handlers log a message but do not expose enough structured
  context for callers to recover.
- The Windows DPI block uses a bare `except`.

### Privacy concerns

The application stores network observations and exports router/ISP details
without a documented retention policy or redaction model. The static page also
contains personal identifiers; it is unrelated to the security application and
should not be treated as its UI.

These findings described the pre-remediation implementation. They are retained
for traceability and are not the current runtime status.

## Fixes implemented and verified

- `ping_router()` now validates the target and invokes the Windows `ping`
  executable with an argument list, timeout, and explicit failure handling.
- Device observation reads `arp -a`, records the collection time and interface,
  and labels records `OBSERVED_IN_ARP_CACHE`. It does not claim liveness or
  complete network discovery.
- Monitoring and device-scan workers publish results through `queue.Queue`.
  Tkinter updates occur in `process_ui_queue`, scheduled by `root.after()` on
  the main thread. Stop events and bounded joins are used during shutdown.
- Router assessment is disabled until evidence-based checks exist; it produces
  no vulnerability findings.
- Mapping changes are recorded as informational `ARP_MAPPING_CHANGED` events,
  or `CONFLICTING_ARP_RESPONSES` when one collection contains multiple MACs
  for an IP. They are not confirmed spoofing alerts.
- Deterministic unit tests mock Windows subprocesses and cover probes,
  parsing, observations, worker communication, and the disabled scanner.

## Partially addressed and unresolved

- ARP cache observations are not active subnet discovery and cannot establish
  that a device is online, safe, or the complete set of connected devices.
- IPv6 neighbor discovery, DHCP evidence, OUI/vendor lookup, and SQLite
  migrations remain future work. Interface selection and bounded IPv4 active
  discovery are implemented in the Phase 2 candidate.
- The legacy monolithic Tkinter module still contains placeholder UI actions
  and unversioned JSON persistence.
- The existing heuristic ping analyzer is not a validated attack detector and
  should not be interpreted as confirmation of compromise.

## Current risk classification

| Area | Classification | Evidence |
|---|---|---|
| Ping monitoring | Partially implemented | Real Windows probe; one-probe loss measurement |
| Device observation | Partially implemented | Windows ARP cache plus opt-in IPv4 ICMP discovery |
| Router assessment | Not implemented | Disabled; no findings are generated |
| Attack history | Partially implemented | Legacy heuristic records require cautious interpretation |
| Persistence | Partially implemented | JSON load/save |
| GUI | Partially implemented | Tkinter UI with placeholder callbacks |
| Optional charts/ML | Partially implemented | Optional imports; no reproducible test coverage |
| Endpoint security | Not implemented | No endpoint adapters |
| Threat intelligence | Not implemented | No integrations |
| Wi-Fi assessment | Partially implemented / platform-dependent | Read-only Windows WLAN metadata and conservative baseline observations; no packet capture or confirmed rogue-AP detection |

## Phase 1 verification boundary

The Phase 1 candidate is acceptable only for the documented probe and
observation behavior. It is not a complete network security platform and must
not be marketed as one.

## Phase 2 verification

The current candidate adds real Windows interface parsing and opt-in active
IPv4 discovery. Scope is limited to the selected interface's private or
link-local subnet. Public, loopback, multicast, missing, and invalid scopes are
rejected. Large scopes require an additional approval, and probes use bounded
concurrency, rate limiting, timeouts, and cancellation.

Active ICMP responses are evidence of reachability only. ARP-cache records are
still cache observations. A failed ping does not establish that a device is
offline, and no device is labeled malicious from identity or vendor
information. No packet capture, IPv6 neighbor discovery, DHCP inspection,
vendor database, or credentialed network access is performed.

## Phase 3A verification boundary

Phase 3A adds read-only gateway identification. The selected interface's
default gateway is evidence from `ipconfig /all`; a gateway MAC is included only
when the current ARP-cache observation contains the gateway IP. This evidence
does not establish router liveness, model, manufacturer, firmware, exposed
services, internet exposure, or vulnerability status.

The router assessment remains disabled for management interfaces, UPnP, DNS,
firmware, credentials, and Wi-Fi. No security findings are generated from
gateway identity alone. User-entered model or firmware data is labeled
unverified and is not used to infer advisories or vulnerabilities.

## Phase 3C verification boundary

UPnP discovery is restricted to an explicitly authorized selected private IPv4
interface and uses controlled SSDP multicast. Device-description URLs must be
literal local IPv4 addresses; public addresses, hostnames, user information,
redirects, oversized responses, and unsafe XML declarations are rejected.
Descriptions are informational evidence only. No UPnP control action, port
mapping change, or internet exposure check is performed.

DNS configuration is read from Windows interface output. Actual resolver tests
require explicit user consent, support only A and AAAA queries, use short
timeouts, and preserve response codes and answer evidence. DNS configuration
changes, ISP resolvers, and differing resolver answers remain informational and
are not treated as hijacking or poisoning. DNSSEC, DoH, DoT, and DoQ are not
claimed.

## Phase 3B verification boundary

Phase 3B adds a read-only assessment of the currently identified local gateway.
The selected interface is re-read before assessment, the gateway must belong to
that interface's validated local scope, and explicit authorization is required.
Only the gateway is checked; the subnet and public addresses are never scanned.

TCP states distinguish `OPEN`, `REFUSED`, `TIMEOUT`, `ERROR`, and
`NOT_TESTED`. A timeout is not treated as a closed port, and an open port is
not automatically a vulnerability or evidence of internet exposure. HTTP uses
a minimal request without credentials or redirect following. HTTPS uses
certificate validation and records trust, expiry, or hostname limitations
without silently treating an unverified connection as secure.

## Phase 3D verification boundary

Wireless inspection is explicitly authorized by the user and uses bounded,
read-only Windows `netsh wlan` commands. It records only adapter, driver,
current-connection, and nearby BSSID metadata exposed by Windows. No wireless
credentials, saved profiles, packet payloads, authentication attempts, or
connections are collected.

Wireless baseline findings are informational. A new BSSID, an open network, or
a weaker security report can have legitimate explanations such as mesh
roaming, router replacement, guest networks, misconfiguration, or driver
reporting differences. The implementation does not confirm rogue access
points, evil twins, deauthentication, interception, or compromise. Missing
fields remain unknown, and client-mode `netsh` output is not equivalent to
monitor-mode packet capture.

## Phase 3E verification boundary

Router firmware intelligence requires an exact manufacturer and model.
Manually registered identity and firmware values remain
`USER_PROVIDED_UNVERIFIED` until the administrator independently confirms them.
No model or firmware version is inferred from a MAC address, HTTP banner,
ISP, or keyword-only description.

NVD 2.0 and CISA KEV synchronization uses bounded HTTPS requests, rate limits,
retry/backoff, pagination, response validation, and local cache state. An API
key, when supplied through `NVD_API_KEY`, is never persisted. Only public
product search terms are sent; private network identifiers and credentials are
not transmitted. Failed or stale sources produce an incomplete/outdated
assessment rather than a false no-vulnerability result.

CPE configuration logic and version boundaries are retained as evidence.
`EXACT_VERIFIED_MATCH`, `STRONG_PRODUCT_MATCH`, `POSSIBLE_MATCH`,
`PRODUCT_MATCH_VERSION_UNKNOWN`, `NO_MATCH_FOUND`, and `INSUFFICIENT_DATA`
remain distinct. CISA KEV inclusion does not prove that the registered router
is affected. No automatic firmware download, upload, installation, exploit,
credential attempt, or configuration change is performed.
