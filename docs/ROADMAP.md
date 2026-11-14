# Roadmap

## Phase 1 — Audit and foundations

**Phase 1 conditionally accepted; Phase 2 implementation candidate complete for
the documented IPv4 scope.**

- Audit the complete repository and document capability boundaries.
- Remove misleading security claims from normal workflows.
- Define package, persistence, worker, and reporting boundaries.
- Add focused tests and a dependency manifest before introducing optional
  integrations.
- Verify worker cancellation, ARP evidence boundaries, and conservative anomaly
  classification before approval.

## Phase 2 — Authorized network discovery

**Current implementation phase; completion report pending final verification.**

- Detect local interfaces, route, and subnet.
- Implement cancellable, permission-aware IPv4 discovery.
- Add interface selection and evidence-based device history.
- Add duplicate-IP and conflicting-MAC evidence without calling it compromise.
- Remaining scope: IPv6 neighbor discovery, DHCP evidence, OUI lookup, and
  SQLite migrations.

## Phase 3 — Router and Wi-Fi assessment

- Phase 3A gateway identification is implemented as a read-only, evidence-based
  sub-stage. It identifies the selected interface's default gateway and can
  associate a matching ARP-cache MAC observation.
- Router management-service assessment and UPnP/DNS checks are implemented for
  their documented local scope. Wi-Fi security intelligence is implemented as
  a Windows `netsh wlan` observation and baseline sub-stage; it does not
  provide packet capture or confirmed rogue-AP detection.
- Add non-invasive, user-authorized checks with evidence.

Phase 3B (router management interface and service assessment) is implemented
for the documented local-gateway scope. It does not include Wi-Fi, firmware
intelligence, credentialed checks, or vulnerability confirmation.

Phase 3C (UPnP exposure and DNS security intelligence) is implemented for the
documented IPv4 SSDP and consent-gated UDP resolver scope. UPnP control actions,
port mapping verification, IPv6 SSDP, DNSSEC, encrypted DNS, and firmware
intelligence remain pending.

Phase 3D (Wi-Fi security intelligence) is implemented for Windows WLAN
adapter/current-connection/nearby-BSSID observations and conservative local
baselines. Native WLAN APIs, packet capture, hidden-network attribution,
enterprise authentication validation, and confirmed evil-twin/rogue-AP
detection remain pending.

Phase 3E (firmware vulnerability intelligence) is implemented for registered
router products, manually verified advisory records, product-specific NVD
retrieval, CPE configuration/version evaluation, CISA KEV prioritization,
offline JSON caching, and conservative findings. Manufacturer coverage is
limited to the supported registration set and does not imply that every model
or firmware branch has intelligence. Advisory feeds beyond validated imports,
automatic firmware update workflows, and Phase 3F work remain pending.
- Report unsupported model, driver, and hardware capabilities explicitly.
- Remove all vendor/ISP assumptions and require sourced firmware/CVE data.

## Phase 4 — Monitoring and detection

- Add resource-bounded telemetry adapters.
- Implement typed events, correlation, confidence, and false-positive context.
- Keep payload collection off by default.

## Phase 5 — Windows endpoint security

- Add least-privilege process, Defender, firewall, event-log, and update
  adapters with Windows-specific integration tests.

## Phase 6 — Intelligence, risk, remediation, and UI

- Add independently testable intelligence clients with caching and rate limits.
- Add explainable risk scoring and approval-gated remediation.
- Introduce the planned PySide6 UI only after service boundaries are stable.

Every phase requires focused tests, updated feature status, documented
permissions and limitations, and a clean error path before the next phase.
