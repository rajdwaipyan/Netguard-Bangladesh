# DNS Security Guide

## Configuration inspection

NetGuard reads DNS server addresses associated with the selected Windows
interface. It distinguishes configured servers from tested availability.
Configuration changes are informational and may result from DHCP, VPN,
router, ISP, adapter, or manual changes.

## Resolver tests

Resolver tests require explicit consent because the selected domain is sent to
the resolver. A and AAAA queries are supported. Results include response code,
answers, timeout state, and duration. No background external queries or
telemetry uploads occur.

## Conservative interpretation

Different answers may result from CDN rotation, caching, split-horizon DNS,
geographic load balancing, or legitimate resolver policy. They are not proof of
poisoning or hijacking. DNSSEC, DNS-over-HTTPS, DNS-over-TLS, and DNS-over-QUIC
are outside this phase.
