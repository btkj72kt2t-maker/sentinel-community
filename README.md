# Sentinel Community

Sentinel Community is a local-first, Kali-compatible workspace for authorized
bug-bounty and defensive security investigations. It provides engagement scope
enforcement, passive reconnaissance, evidence hashing, relationship graphs,
audit logs, and portable reports.

## Safety model

Every target belongs to an engagement. Commands reject targets outside the
engagement's exact hosts or explicitly allowed subdomains. Active checks must
also be enabled on the engagement and requested with `--active`.

## Quick start

```bash
python3 sentinel.py init
python3 sentinel.py engagement create acme --domain example.com --allow-subdomains
python3 sentinel.py recon acme example.com
python3 sentinel.py tools list
python3 sentinel.py tools run acme nmap example.com --approve-active
python3 sentinel.py workflow create acme web-safe example.com
python3 sentinel.py workflow run 1 --dry-run
python3 sentinel.py jobs enqueue acme 1
python3 sentinel.py jobs run-next acme
python3 sentinel.py intel score acme
python3 sentinel.py intel paths acme
python3 sentinel.py health acme
python3 sentinel.py secure list acme
python3 sentinel.py proxy analyze-har acme traffic.har
python3 sentinel.py extensions install ./sentinel-extension.json
python3 sentinel.py lab validate-marker lab-engagement http://localhost:8000/ --approve-active
python3 sentinel.py credentials audit ./source-tree
python3 sentinel.py benchmark --iterations 250
python3 sentinel.py catalog
python3 sentinel.py coverage

# One-command, scope-bound assessment plan (no network execution)
python3 sentinel.py hunt acme example.com --mode full-safe --dry-run

# Execute reviewed active adapters and generate JSON/HTML reports
python3 sentinel.py hunt acme example.com --mode full-safe --approve-active

# Correlate independent observations and score confidence
python3 sentinel.py validate acme

# Analyze an in-scope OpenAPI JSON contract without sending traffic
python3 sentinel.py api analyze-openapi acme openapi.json

# Add a bounded recurring assessment (minimum interval: five minutes)
python3 sentinel.py schedule add acme example.com web-safe --interval 86400 --approve-active
python3 sentinel.py schedule list acme

# Build an operator dashboard and capture executable hashes
python3 sentinel.py dashboard acme
python3 sentinel.py provenance

# Inspect the ten-area implementation and outstanding production gates
python3 sentinel.py readiness

# Import standardized results from SAST, SCA, IaC, cloud, mobile, or firmware tools
python3 sentinel.py results import-sarif acme scan-results.sarif

# Certify local binaries and reviewed adapters; save the evidence report
python3 sentinel.py doctor --write

# Import authoritative exploitation intelligence and build the exposure graph
python3 sentinel.py intel import-kev known_exploited_vulnerabilities.json
python3 sentinel.py intel import-epss epss_scores.csv
python3 sentinel.py intel link acme
python3 sentinel.py intel prioritize acme
python3 sentinel.py intel validation-plan acme
python3 sentinel.py daemon run acme --poll-seconds 15 --max-runtime 86400
python3 sentinel.py daemon status acme
python3 sentinel.py daemon stop acme
python3 sentinel.py research create lab parser-fuzz afl++ ./parser ./corpus
python3 sentinel.py research plan 1
python3 sentinel.py research triage 1 ./asan-crash.log
python3 sentinel.py research ingest-corpus 1 ./corpus
python3 sentinel.py research corpus-stats 1
python3 sentinel.py research import-coverage 1 ./coverage.json
python3 sentinel.py research coverage-trend 1
python3 sentinel.py research sandbox-plan 1
python3 sentinel.py research record-reproduction 1 ./crash-input --sanitizer ASan reproduced
python3 sentinel.py research score-candidate 1
python3 sentinel.py report acme
```

State is stored under `.sentinel/` by default. Use `SENTINEL_DATA_DIR` to choose
another location.

## Current modules

- Engagement and target scope management
- Passive DNS and TLS reconnaissance
- Rate-limited, approval-gated Nmap adapter
- Controlled adapters for Nmap, Nuclei, Subfinder, httpx, WhatWeb, testssl,
  WHOIS, and dig
- Resumable passive, web-safe, and network-safe workflows
- Engagement kill switch and isolated-lab designation
- Finding deduplication and explainable risk scoring
- Entity correlation and bounded attack-path analysis
- Persistent workflow job queue
- Evidence classification, integrity verification, and safe health repair
- Passive in-scope HAR traffic analysis with credential redaction
- Manifest-verified extension registration without automatic code execution
- Loopback-only, non-destructive marker validation for isolated lab engagements
- Redacted credential-exposure auditing that never returns secret values
- Reproducible local benchmarks with environment and latency disclosure
- Persistent bounded worker with heartbeat, health repair, kill switch, and stop file
- Local fuzzing campaign registry and sanitizer crash deduplication
- 852-capability inventory: 130 curated entries plus an official Kali reference index; catalogue entries are not executable by default
- 16-family vulnerability coverage matrix derived from community methodology and modern application/infrastructure surfaces
- One-command `hunt` orchestration for passive, web-safe, network-safe, or combined scope-bound assessments
- Report remediation guidance mapped to finding families and CWE references
- Cross-tool correlation with explicit unverified, reproduced, and confirmed states
- Offline, scope-checked OpenAPI contract analysis for authentication, object authorization, and schema risks
- Persistent recurring schedules integrated with the bounded daemon and emergency stop controls
- Executable provenance manifests for deployment-time tool pinning
- Local HTML operator dashboard covering findings, validation state, risk, workflows, and jobs
- SARIF 2.1 result ingestion for interoperable SAST, SCA, IaC, cloud, mobile, and firmware analysis
- Machine-readable ten-area readiness report that refuses false production-complete claims
- Non-root container definition, continuous integration checks, security policy, and threat model
- Repeatable local certification with SHA-256 identities, permission checks, safe version probes, adapter argument audits, and explicit untested states
- CISA KEV and FIRST EPSS ingestion with asset/software/vulnerability/threat graph links
- Explainable exploitation-likelihood prioritization and least-intrusive validation plans
- Content-addressed corpus storage and duplicate elimination
- Coverage telemetry history and progress deltas
- Reproduction evidence and conservative zero-day-candidate scoring
- Sandbox readiness plans that refuse execution without a supported isolation backend

The included systemd unit is a hardened template. Replace `ENGAGEMENT_NAME`, review
paths and policy, then install it manually on the authorized Kali host.
- SHA-256 evidence ingestion with append-only audit events
- SQLite entity/relationship graph
- JSON and HTML reporting

The codebase intentionally does not include credential attacks, automated
exploitation, stealth/evasion, or indiscriminate internet scanning.
