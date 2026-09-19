# Advanced assessment tooling: research and integration policy

Reviewed: 2026-09-19

## Outcome

Sentinel selects tools by evidence quality, maintenance, structured output,
bounded execution, and unique coverage—not by raw tool count. No scanner can
guarantee discovery of every known vulnerability or zero-day. Sentinel therefore
reports coverage gaps, preserves raw evidence, correlates independent sensors,
and labels single-source results as unverified.

## Selection gates

An executable adapter must have all of the following:

1. An identifiable upstream project and documented CLI.
2. A noninteractive, machine-readable output mode where one exists.
3. Explicit limits for rate, concurrency, depth, duration, or corpus size.
4. Fixed argument construction without a shell interpreter.
5. Scope and policy enforcement before the process starts.
6. A version probe, binary identity record, parser tests, and fixture tests.
7. A distinct detection role that materially closes a measured coverage gap.
8. Raw-output retention and normalized evidence with source attribution.

Catalogue-only tools remain non-executable until they pass these gates.

## Recommended capability stack

| Layer | Preferred projects | Sentinel treatment |
|---|---|---|
| Asset discovery | Amass, Subfinder, dnsx | Passive enumeration plus bounded DNS validation; correlate overlapping observations. |
| Network exposure | Nmap, Naabu | Bounded port/service collection; retain raw XML/JSONL and require explicit active approval. |
| HTTP and crawling | httpx, Katana, feroxbuster, ffuf | Start with light probing and bounded crawling. Add ffuf only with a reviewed wordlist contract, auto-calibration, and hard time/rate limits. |
| TLS | testssl.sh, tlsx, SSLyze | Use independent implementations to reduce parser/tool blind spots; normalize certificate and protocol evidence. |
| DAST | Nuclei, OWASP ZAP, Burp DAST | Nuclei uses signed/reviewed templates. ZAP passive automation is a priority. Commercial Burp integration is optional and API-based. Active audit requires a separately approved profile. |
| API | OpenAPI analysis, Schemathesis, ZAP API jobs | Prefer schema-derived coverage and negative property testing in staging/labs. Keep authentication material outside reports. |
| SAST and secrets | Semgrep, CodeQL, Gitleaks | Offline repository profiles; import SARIF and preserve rule identity. Never collect live credentials. |
| Dependencies and artifacts | OSV-Scanner, Trivy, Grype, Syft | Import JSON/SARIF/SBOM; correlate package identity, reachability evidence, KEV and EPSS. |
| Cloud and Kubernetes | Prowler, ScoutSuite, Steampipe, kube-bench, Kubescape | Read-only profiles with least-privilege identities; never create or modify resources. |
| Mobile and firmware | MobSF/mobsfscan, JADX, apktool, Ghidra, Binwalk, EMBA | Offline or owned-lab analysis; treat unpacked content as untrusted. |
| Novel vulnerability research | libFuzzer, AFL++, Jazzer, Atheris, Honggfuzz | Lab-only campaigns with sanitizers, coverage telemetry, crash deduplication and reproducibility gates. |
| Evidence exchange | SARIF, CycloneDX, CSAF, VEX, STIX | Preserve provenance and translate results without overstating validation. |

## Accuracy model

Sentinel uses five independent signals:

- **Tool evidence:** raw request/response, parser record, source version and binary hash.
- **Repetition:** the same observation appears on multiple runs.
- **Independent confirmation:** different tools or a controlled proof agree.
- **Context:** asset, technology, component and reachability evidence match.
- **Reproduction:** a bounded proof succeeds and rollback is verified.

Single-tool matches are triage leads, not automatically confirmed findings.
Severity is not confidence. KEV and EPSS prioritize work but do not establish
that a particular asset is vulnerable.

## Implemented from this review

- Added reviewed `dnsx` JSONL integration with a fixed rate limit and normalized
  domain, IPv4 and IPv6 evidence.
- Added reviewed `tlsx` JSONL integration with bounded concurrency, delay,
  timeout, certificate verification, and normalized TLS misconfiguration
  findings.
- Expanded the complete workflow so DNS validation precedes service discovery
  and an independent TLS collector runs before network service analysis.
- Upgraded the coverage matrix to distinguish installed catalogue tools,
  reviewed adapters, executable adapters and actual automation blind spots.
- Added adapter and parser fixtures for the new integrations.

## Next adapter priorities

1. OWASP ZAP passive Automation Framework import with plan validation.
2. Offline OSV-Scanner v2 and Trivy repository/SBOM profiles.
3. Semgrep SARIF profile for source-authorized engagements.
4. Schemathesis staging/lab profile for OpenAPI-derived negative tests.
5. AFL++/libFuzzer coverage import hardening and sanitizer-aware deduplication.

These should be added one at a time with real fixtures and compatibility tests.
Bulk-wrapping hundreds of binaries would reduce assurance and is intentionally
not treated as progress.

## Primary sources

- OWASP Web Security Testing Guide: https://wstg.owasp.org/
- OWASP ZAP Automation Framework: https://www.zaproxy.org/docs/desktop/addons/automation-framework/
- ProjectDiscovery open-source documentation: https://projectdiscovery.io/open-source
- dnsx: https://github.com/projectdiscovery/dnsx
- tlsx: https://github.com/projectdiscovery/tlsx
- Nuclei input formats: https://docs.projectdiscovery.io/tools/nuclei/input-formats
- Interactsh: https://github.com/projectdiscovery/interactsh
- ffuf: https://github.com/ffuf/ffuf
- OSV-Scanner: https://google.github.io/osv-scanner/
- Semgrep local scans: https://semgrep.dev/docs/category/local-and-cli-scans
- Google OSS-Fuzz: https://github.com/google/oss-fuzz
- PortSwigger DAST: https://portswigger.net/burp/documentation/dast

