# Security Policy

## Supported versions

This project is currently experimental and has no published release or
supported-version guarantee. Security fixes should target the current working
tree until release maintenance policy is established.

## Reporting a vulnerability

Do not include credentials, private network data, router configurations, or
live exploit code in public issues. Because this workspace has no configured
GitHub repository or verified security contact, use the private security
reporting mechanism provided by the project owner after repository publication.
If no private channel is available, report only a sanitized description and
request a private contact; do not assume an email address.

Reports should include affected file or feature, reproducible steps, impact,
sanitized logs, and a suggested mitigation where safe.

## Security testing scope

NetGuard is defensive software. Testing must not brute-force credentials,
exploit routers, scan unauthorized networks, upload firmware, modify router
configuration, or transmit private data to public services. External
intelligence tests must use mocked responses.

## Privacy

Local observations and history may contain network metadata. Review retention
and redact exports before sharing. Firmware intelligence synchronization sends
only public product search terms; API keys are environment configuration and
are not persisted.
