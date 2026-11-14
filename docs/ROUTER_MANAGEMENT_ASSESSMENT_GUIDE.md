# Router Management Assessment Guide

## Scope and authorization

Phase 3B assesses only the currently selected interface's current default
gateway. Before any connection is attempted, NetGuard revalidates the
interface and gateway, rejects public or unrelated targets, and requires an
explicit authorization confirmation. It does not scan the subnet or public
addresses.

## Checks

The bounded internal port list is:

- FTP: 21
- SSH: 22
- Telnet: 23
- DNS over TCP: 53
- HTTP: 80 and 8080
- HTTPS: 443 and 8443

Checks are read-only, rate-limited, timeout-bounded, cancellable, and performed
without credentials or configuration changes.

## Interpreting results

- `OPEN`: the gateway accepted a TCP connection from this computer.
- `REFUSED`: the gateway actively refused the connection at that time.
- `TIMEOUT`: no response arrived before the timeout; this is not proof of closure.
- `ERROR`: the connection attempt failed before service state was established.
- `NOT_TESTED`: cancellation prevented the check.

An open port is a service observation, not a vulnerability finding. Local
availability does not establish exposure from the internet.

## HTTP and TLS limitations

HTTP uses one minimal `GET /` request. It does not follow redirects, submit
forms, execute scripts, enumerate administrative paths, or transmit credentials.
Redirect destinations are recorded without being contacted.

HTTPS uses the platform's default certificate validation. Certificate trust,
expiry, and hostname problems are recorded as investigation observations;
certificate problems do not prove compromise. Router certificates may be
self-signed, and certificate metadata can be incomplete on Windows.

## Requirements and privacy

No administrator privilege or third-party dependency is required by the current
implementation, but firewall policy and router behavior can limit evidence.
Assessment history is stored in the existing local JSON data file. No
credentials or packet payloads are collected.
