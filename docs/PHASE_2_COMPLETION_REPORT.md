# Phase 2 Completion Report

## Result

**CONDITIONAL COMPLETION — IPv4 interface selection, authorized discovery, and
evidence-based inventory are implemented; documented IPv6, DHCP, and vendor
intelligence limitations remain.**

Phase 3 has not started.

## Implemented features

- Windows interface parsing from `ipconfig /all`.
- Interface names, descriptions, IPv4/IPv6 addresses, subnet masks, CIDR,
  broadcast address, default gateway, MAC address, operational state, and
  cautious VPN/virtual classification.
- Explicit interface selection in the Tkinter UI; no adapter is selected
  automatically.
- Read-only Windows ARP-cache observations with interface and collection time.
- Explicit authorization before active discovery.
- Private/link-local IPv4 scope validation; public, loopback, multicast, invalid,
  and missing scopes are rejected.
- Large-scope warning and additional approval.
- Bounded ICMP probing with rate limiting, bounded concurrency, timeout
  behavior inherited from the real Windows ping adapter, and cancellation.
- Distinct `OBSERVED_IN_ARP_CACHE` and `ACTIVELY_DISCOVERED` evidence statuses.
- Conservative merge of ICMP and ARP evidence.
- Persistent history for observations, historical IP/MAC addresses, interface
  changes, mapping changes, trust preference, and identity-related IP changes.
- Duplicate and conflicting observation handling without confirmed spoofing.
- Queue-based GUI updates and worker shutdown integration.

## Architecture changes

`DiscoveryEngine` owns interface parsing, scope validation, and bounded active
host probing. `NetGuardBangladesh` owns user approval, worker lifecycle, ARP
evidence merging, persistence calls, and main-thread rendering. Workers never
touch Tkinter widgets.

## Files modified

- `netguard_bangladesh.py`
- `tests/test_runtime_probes.py`
- `tests/test_discovery_engine.py`
- `docs/ARCHITECTURE.md`
- `docs/FEATURE_STATUS.md`
- `docs/SECURITY_AUDIT.md`
- `docs/ROADMAP.md`

## Files added

- `docs/USER_GUIDE.md`
- `docs/PHASE_2_COMPLETION_REPORT.md`

No third-party dependencies were added.

## Hardware and permission requirements

- Windows is required for the implemented command adapters.
- Standard interface and ARP commands normally require no administrator
  privilege, but endpoint policy, firewall rules, and drivers can limit output.
- Active discovery requires explicit user authorization and is restricted to the
  selected private or link-local subnet.
- Npcap is not required for the current ICMP/ARP implementation and is not
  currently used.

## Test results

`python -m unittest discover -s tests -v`: **37 tests executed, 37 passed**.

Tests use mocked Windows command output and controlled probe callbacks. They do
not require internet access, perform real active scans, or execute attacks.

`python -m py_compile` completed successfully for the application and both test
modules.

## Known limitations

- Active discovery is IPv4 ICMP reachability probing, not packet-level ARP
  response capture.
- A failed ping does not establish that a device is offline.
- ARP-cache presence does not establish liveness or complete inventory.
- IPv6 neighbor discovery, DHCP inspection, offline OUI lookup, reliable
  hostname resolution, and SQLite migrations are not implemented.
- Device category inference remains Unknown unless separately sourced evidence
  is added; MAC vendor data is not invented.
- Existing JSON persistence remains unversioned.

## Remaining risks

- ICMP filtering can produce partial active-discovery results.
- Windows command output is locale-sensitive and may require additional parser
  fixtures for non-English installations.
- A bounded worker can take up to the probe timeout to stop when subprocesses
  are already running.
- No Git repository exists in the workspace, so no Git diff or history review
  is claimed.

The current candidate is suitable for the documented Phase 2 IPv4 discovery
scope only. It must not be marketed as complete network discovery.
