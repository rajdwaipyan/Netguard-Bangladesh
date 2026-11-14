# UPnP Security Guide

## What is assessed

NetGuard sends a controlled SSDP `M-SEARCH` on the explicitly selected,
authorized private IPv4 interface. It records source IP, SSDP headers, device
identity fields, and advertised services. A device description is retrieved
only when `LOCATION` contains a literal local IPv4 address in the selected
network.

## Safety controls

- Explicit authorization is required.
- Public addresses, hostnames, user-information URLs, redirects, and unsupported
  schemes are rejected.
- Response and XML sizes are bounded.
- External entity declarations are rejected.
- No control actions or port-mapping changes are sent.
- Cancellation and duplicate-worker protection are provided.

## Interpretation

UPnP discovery, an Internet Gateway Device type, and service advertisement are
separate observations. None proves a vulnerability or internet exposure.
IPv6 SSDP, control-service verification, port-mapping status, and external
reachability are not implemented.
