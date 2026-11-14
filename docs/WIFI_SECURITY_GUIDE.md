# Wi-Fi Security Intelligence Guide

## Scope

The Wi-Fi action reads Windows WLAN metadata with `netsh wlan`. It can report
wireless adapters, driver metadata, the current connection, nearby BSSIDs,
signal strength, channel, authentication, and cipher values.

The action is read-only and requires explicit user approval. It does not read
credentials or saved profiles, connect to networks, capture packets, or send
authentication traffic. Windows and the wireless driver must expose the field
for it to be recorded.

## Baselines and findings

Use **Set Wireless Baseline** after reviewing an expected observation. Later
observations can produce informational findings for a new BSSID, weaker
reported security, open networks, legacy encryption, or incomplete evidence.
Mesh networks, roaming, router replacement, guest networks, randomized BSSIDs,
and driver differences are legitimate explanations that must be investigated.

These findings do not prove an evil twin, rogue access point, interception, or
compromise. Confirm identity through authorized administrative records and
access-point management systems.

## Limitations

Client-mode `netsh` output is not monitor-mode capture. Hidden SSIDs,
unsupported adapters, missing channel/security fields, enterprise
authentication details, and historical observations may be unavailable.
Channel counts are performance observations, not security findings.
