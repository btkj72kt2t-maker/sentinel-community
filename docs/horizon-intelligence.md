# Horizon intelligence core

Horizon adds reproducible threat-intelligence and supply-chain data to Sentinel.

## Trusted feed synchronization

Only two built-in sources can be downloaded: CISA KEV and the FIRST-published EPSS
daily dataset. The downloader requires HTTPS, constrains redirects to approved
hosts, uses time and size limits, validates the expected document shape, hashes
the decompressed content, and archives the exact input before ingestion. Feed
history records URL, digest, size, path, and retrieval time.

Synchronization is explicit. A host scheduler may invoke `intel sync all` at the
desired interval. A failed update leaves previous intelligence intact.

## STIX 2.1

Sentinel imports JSON bundle objects into an engagement-bound graph. Supported
nodes include domains, IP addresses, software, vulnerabilities, indicators,
threat actors, intrusion sets, and malware. Relationships are imported only when
both endpoints resolve. Export emits the smaller set for which Sentinel can
provide structurally valid required properties.

## CSAF, CycloneDX, and VEX

CSAF advisories enrich global vulnerability records with product status and
vendor remediation. CycloneDX imports engagement-specific components using
`bom-ref`, purl, name, and version, then relates vulnerabilities through
`affects`. Embedded VEX analysis records status, justification, and response.

Feed or SBOM presence is never treated as proof of local exploitability. Sentinel
keeps known exploitation, predicted probability, component presence, VEX state,
and local scanner evidence as distinct facts.
