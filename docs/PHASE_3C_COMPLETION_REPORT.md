# Phase 3C Completion Report

## Result

**CONDITIONAL PASS — Phase 3C IPv4 UPnP and consent-gated DNS intelligence is
implemented and tested for its documented scope.**

Phase 3D was not started.

## Implemented UPnP capabilities

- Explicitly authorized IPv4 SSDP discovery on the selected private interface.
- Controlled multicast request, short response window, cancellation, response
  limits, and duplicate prevention.
- Safe SSDP header normalization and malformed-response handling.
- Local literal-IP `LOCATION` validation.
- Direct HTTP device-description retrieval without proxy use or redirects.
- Response-size limits and rejection of DTD/entity declarations.
- Conservative device, gateway-device, and advertised-service observations.

No UPnP control actions, port mapping changes, or internet exposure claims are
made.

## Implemented DNS capabilities

- Interface-associated Windows DNS configuration parsing.
- IPv4 and IPv6 server address collection where exposed by Windows output.
- Consent-gated actual UDP A/AAAA resolver queries.
- Response-code, answer, timeout, duration, and cancellation evidence.
- Optional resolver comparison with conservative discrepancy classification.
- Informational configuration-change and resolver findings.

DNSSEC, DoH, DoT, DoQ, and background query collection are not implemented.

## Architecture and persistence

New engines remain in the existing Python entry point and use standard-library
`socket`, `struct`, `http.client`, and safe `xml.etree.ElementTree` processing.
UPnP observations, DNS snapshots/results, and findings are retained in the
existing JSON document with bounded histories and atomic temporary-file replace.
GUI workers communicate through `Queue`; only the main-thread queue poller
updates Tkinter.

## Files modified

- `netguard_bangladesh.py`
- `tests/test_discovery_engine.py`
- `docs/ARCHITECTURE.md`
- `docs/SECURITY_AUDIT.md`
- `docs/FEATURE_STATUS.md`
- `docs/ROADMAP.md`
- `docs/USER_GUIDE.md`

## Files created

- `docs/UPNP_SECURITY_GUIDE.md`
- `docs/DNS_SECURITY_GUIDE.md`
- `docs/PHASE_3C_COMPLETION_REPORT.md`

## Tests and verification

Command: `python -m unittest discover -s tests -v`

Result: **59 tests executed, 59 passed, 0 failed**.

Coverage includes SSDP parsing, deduplication, cancellation, authorization,
safe URL validation, XML entity rejection, DNS configuration parsing, actual
DNS packet parsing, timeout handling, consent enforcement, comparison consent,
conservative findings, and all prior Phase 1–3B tests.

Command: `python -m py_compile netguard_bangladesh.py tests\test_runtime_probes.py tests\test_discovery_engine.py`

Result: **successful**.

No real network assessment was performed.

## Permissions and privacy

Standard interface/configuration inspection uses existing Windows command
access. SSDP and DNS queries require explicit user authorization. Domain names
are not queried in the background, credentials are never collected, and no
telemetry is transmitted.

## Known limitations and outstanding risks

- UPnP is IPv4-only; IPv6 scope-aware SSDP is not implemented.
- Real router/device behavior and firewall effects require authorized
  real-world validation.
- Device descriptions may omit fields or provide untrusted identity claims.
- DNS parser supports only A and AAAA queries and does not validate DNSSEC.
- DNS-over-HTTPS/TLS/QUIC are not assessed.
- Windows output parsing remains locale-sensitive.
- JSON persistence is atomic but remains unversioned.

## Final recommendation

**CONDITIONAL PASS for Phase 3C.** The documented IPv4 UPnP and consent-gated
DNS scope is implemented and verified by deterministic tests. Real-world
validation remains outstanding and Phase 3D must not begin automatically.
