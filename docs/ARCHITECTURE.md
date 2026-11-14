# NetGuard Bangladesh Architecture Audit

## Current state

The repository currently contains one Python entry point, `netguard_bangladesh.py`,
and an unrelated static portfolio page, `index.html`. The Python application is a
Tkinter monolith: UI construction, persistence, probing, detection heuristics,
router assessment, and reporting all live in one module.

At the original audit there was no dependency manifest, test suite, migration
layer, package boundary, or CI workflow. The current Phase 1 candidate adds a
focused standard-library test suite, but the other boundaries remain future
work. The `netguard_data` directory is empty in the audited workspace.

## Existing runtime flow

1. `main()` creates a Tkinter root and instantiates `NetGuardBangladesh`.
2. `NetworkAnalyzer` loads JSON history from the user's home directory.
3. UI callbacks start monitoring, scanning, or reporting.
4. Background workers perform probes and publish immutable results to a
   `queue.Queue`.
5. `root.after()` drains the queue on the Tkinter main thread and applies all
   widget updates.
6. State is persisted as a single JSON document.

## Phase 1 target architecture

The application should be migrated incrementally:

```text
netguard/
  domain/       typed device, event, and assessment models
  discovery/    authorized interface, route, ARP, and device discovery
  monitoring/   cancellable workers and telemetry adapters
  assessment/   evidence-based router and endpoint checks
  persistence/  SQLite repositories and migrations
  ui/           Tk/PySide presentation and main-thread event dispatch
  reporting/    privacy-conscious exports
tests/
docs/
```

Adapters must report capability and permission failures explicitly. Detection
engines should consume evidence records rather than generate observations.
Later phases must not be started until the corresponding adapters have focused
tests and documented platform limitations.

## Phase 2 discovery flow

`DiscoveryEngine` parses the Windows `ipconfig /all` output into selectable
interface records. The selected interface exposes its IPv4 subnet, gateway,
MAC, IPv6 addresses, operational state, and a cautious VPN/virtual adapter
classification.

ARP-cache observation remains read-only. Active discovery requires an explicit
user approval for the selected private or link-local subnet, rejects public or
invalid scopes, limits host concurrency and submission rate, and can be
cancelled. ICMP responses are labeled `ACTIVELY_DISCOVERED`; ARP-only records
remain `OBSERVED_IN_ARP_CACHE`. A failed ICMP probe is not treated as proof
that a host is offline.

Workers publish discovery results to the existing queue and the Tkinter main
thread renders them through the existing `root.after()` poller.

## Phase 3A gateway identification

The Phase 3A router layer is deliberately read-only. It combines the selected
interface's default gateway from `ipconfig /all` with a matching
`windows_arp_cache` observation when one exists. The result records its sources,
timestamp, MAC evidence, and confidence limitations. It does not probe HTTP,
HTTPS, ports, UPnP, DNS, credentials, firmware, or Wi-Fi settings. Unknown
router models remain unknown; user-entered model or firmware values are stored
as explicitly unverified.

## Phase 3B router management assessment

The management assessment accepts only the currently selected interface and its
current default gateway. The worker re-reads interface configuration before
connecting, rejects public or unrelated targets, and requires explicit user
authorization. It performs one-at-a-time, rate-limited TCP connection checks on
the configured ports 21, 22, 23, 53, 80, 443, 8080, and 8443.

Open, refused, timeout, error, and cancelled results remain distinct. HTTP
checks issue one `GET /` request without credentials, forms, scripts, or
redirect following. HTTPS checks use the default certificate-validating TLS
context; failed validation is never presented as secure. Results are published
through the existing queue, rendered by the Tkinter main thread, and persisted
in the existing JSON history.

## Phase 3C UPnP and DNS intelligence

`UPnPDiscoveryEngine` sends an authorized, bounded IPv4 SSDP `M-SEARCH` only
through the selected private interface. Responses are size-limited, parsed as
untrusted headers, deduplicated, and optionally resolved to direct literal-IP
HTTP descriptions. Description retrieval rejects public/hostname destinations,
redirects, user information, oversized XML, and unsafe entity declarations.

`DNSConfigurationEngine` parses interface-associated Windows DNS server
configuration and performs consent-gated UDP A/AAAA queries with bounded
timeouts. It reports actual response codes and records, not simulated answers.
`SecurityFindingsEngine` produces informational, evidence-linked observations;
configuration changes and resolver differences are not labelled hijacking.

## Phase 3D Wi-Fi intelligence

`WirelessSecurityEngine` runs controlled, read-only `netsh wlan` commands on
Windows. It parses adapter state, driver metadata, current connection fields,
nearby BSSID observations, signal/channel data, and authentication/cipher
values. Missing Windows fields remain unavailable rather than being inferred.
The engine does not collect credentials, profiles, packet payloads, or connect
to access points.

`WirelessBaselineEngine` compares observed SSID/BSSID/security records with a
user-created local baseline. New BSSIDs, weaker security, open networks, and
incomplete evidence are informational findings with legitimate explanations.
They are not proof of a rogue access point or evil twin. Wireless work runs in
the existing cancellable worker and publishes results through the Tk queue;
only the main thread updates Tk variables and widgets. Wireless state is
persisted in the existing bounded JSON document.

## Phase 3E firmware vulnerability intelligence

`FirmwareIntelligenceEngine` keeps router identity, firmware verification
status, CPE applicability evidence, version comparison results, match
classifications, and findings separate. CPE configuration trees preserve
AND/OR logic and version boundaries; a CISA KEV match is only a prioritization
signal after product applicability has been established.

`VulnerabilitySourceClient` performs explicit-consent HTTPS retrieval from the
NVD 2.0 CVE API and CISA KEV JSON feed with bounded payloads, rate limiting,
retry/backoff, pagination, response validation, cancellation, and source
attribution. NVD API keys are read only from process configuration and are not
persisted. Manufacturer advisories use validated HTTPS records supplied by an
administrator or an independently verified official import; the application
does not scrape arbitrary pages.

Firmware synchronization runs in a queue worker. Cached records remain
available when a source fails, but the assessment is marked
`OUTDATED_OR_INCOMPLETE`. Persistence extends the existing atomic JSON
document; no router credentials, private addresses, MAC addresses, or
configuration data are sent to public intelligence providers. Firmware
recommendations are read-only and never download or install firmware.

## Phase 1 decisions

- Keep the existing Tkinter entry point until a tested application/service
  boundary exists.
- Remove or disable simulated security findings rather than presenting them as
  observations.
- Treat ARP output as cache observations only; it is not active discovery or
  proof of liveness.
- Record mapping changes as cautious anomalies and do not confirm spoofing
  without corroborating telemetry.
- Use standard-library Windows probes first; optional dependencies belong in a
  manifest and must be capability-checked.
- Preserve existing JSON data for read-only compatibility while a SQLite
  migration is designed.
