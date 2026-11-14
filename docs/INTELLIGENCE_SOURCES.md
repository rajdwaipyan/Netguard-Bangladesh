# Intelligence Sources

## NVD

- CVE API: <https://services.nvd.nist.gov/rest/json/cves/2.0>
- CPE API reference: <https://services.nvd.nist.gov/rest/json/cpes/2.0>
- CPE match criteria reference: <https://services.nvd.nist.gov/rest/json/cpematch/2.0>
- Developer documentation: <https://nvd.nist.gov/developers>

The implementation currently retrieves product-specific CVE results through the
NVD CVE 2.0 interface. CPE and match-criteria endpoints are documented for
future targeted synchronization; returned CVE configuration trees are retained
and evaluated without flattening logical applicability.

## CISA KEV

- Catalog page: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- Official JSON feed: <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>
- Data mirror: <https://github.com/cisagov/kev-data>

KEV inclusion means CISA lists the CVE as known exploited. It does not prove
that a registered router product or installed firmware is affected.

## Manufacturer advisories

Manufacturer advisories are accepted as validated HTTPS records with an
advisory identifier, exact affected product, affected versions/revisions,
source URL, and remediation. The current subsystem does not indiscriminately
scrape manufacturer websites. Records without verified official provenance
remain `USER_PROVIDED_UNVERIFIED`.

## Freshness and failure

Each synchronized record includes source attribution and retrieval time.
Unavailable or stale sources remain visible and make assessment incomplete;
the application never converts a failed synchronization into “no
vulnerabilities.”
