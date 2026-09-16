# Sentinel Community

Sentinel Community is a local-first, Kali-compatible command-line workspace for
authorized bug-bounty, vulnerability-research, and defensive-security work. It
combines strict scope enforcement, reviewed tool adapters, normalized findings,
an asset and vulnerability knowledge graph, KEV/EPSS intelligence, evidence
integrity, research workflows, risk prioritization, and portable reports.

Sentinel is an orchestration and evidence platform. Its catalogue contains 852
security capabilities, but catalogue membership does not make a tool executable.
Only registered, reviewed adapters can run; unavailable tools are reported as
untested rather than presented as working.

## Safety and authorization

Use Sentinel only on systems you own or have written permission to assess.

- Every network target must belong to a named engagement scope.
- Active testing requires `--enable-active` on the engagement and
  `--approve-active` on the operation.
- The engagement kill switch overrides approvals and stops background work.
- Potentially disruptive proof-of-impact belongs in an isolated lab engagement.
- The marker validator accepts loopback targets only.
- Extensions are declarative and disabled by default.
- Sentinel does not provide credential harvesting, persistence, evasion,
  destructive actions, autonomous lateral movement, or indiscriminate scanning.
- KEV and EPSS improve prioritization but do not prove that an asset is vulnerable.

## Requirements and installation

Requirements are Python 3.10 or newer, SQLite support included with Python, and
Linux, Kali Linux, or macOS. External tools are needed only when their reviewed
adapters are used; Sentinel never installs them silently.

```bash
git clone https://github.com/btkj72kt2t-maker/sentinel-community.git
cd sentinel-community
python3 sentinel.py init
python3 sentinel.py doctor --write
```

Runtime state is stored in `.sentinel/` by default. Choose another protected
location with:

```bash
export SENTINEL_DATA_DIR=/secure/path/sentinel-data
python3 sentinel.py init
```

Do not commit that directory. It can contain confidential evidence, reports,
target metadata, and audit records.

## Tool certification

Run certification after installation and after upgrading an external tool:

```bash
python3 sentinel.py doctor --write
```

The report at `.sentinel/certification.json` records catalogue integrity,
executable permissions, SHA-256 identities, safe local version probes, and every
adapter's argument-construction checks.

- `passed`: the local check succeeded.
- `failed`: the local check found a real problem.
- `untested`: the tool is absent or cannot be inspected.
- `adapter_code_certified`: every registered profile constructs fixed arguments.
- `installed_integrity_passed`: no installed binary failed inspection.
- `environment_ready`: every reviewed adapter is installed and passed its probe.

Certification verifies local integration, not perfect third-party algorithms or
guaranteed vulnerability coverage.

## 1. Engagements and scope

Create a passive engagement for one exact domain:

```bash
python3 sentinel.py engagement create acme --domain example.com
```

Allow subdomains explicitly:

```bash
python3 sentinel.py engagement create acme-web \
  --domain example.com \
  --allow-subdomains
```

Create an engagement for approval-gated active checks:

```bash
python3 sentinel.py engagement create acme-active \
  --domain example.com \
  --allow-subdomains \
  --enable-active \
  --max-rate 25
```

Create an isolated research engagement:

```bash
python3 sentinel.py engagement create parser-lab \
  --domain localhost \
  --enable-active \
  --lab-mode \
  --max-rate 10
```

Repeated `--domain` and `--ip` arguments can define exact authorized domains,
IP addresses, or CIDRs. Review engagements with:

```bash
python3 sentinel.py engagement list
```

## 2. Emergency controls

Enable the kill switch immediately:

```bash
python3 sentinel.py engagement kill acme-active
```

Clear it only after reviewing the stop reason:

```bash
python3 sentinel.py engagement resume acme-active
```

## 3. Tools, catalogue, and coverage

```bash
python3 sentinel.py tools list
python3 sentinel.py catalog
python3 sentinel.py coverage
python3 sentinel.py readiness
```

`tools list` shows executable adapters. `catalog` shows the broader capability
inventory. `coverage` maps vulnerability families to available tools.
`readiness` shows the ten architectural foundations and outstanding production
gates.

Reviewed adapters currently cover `dig`, `whois`, `subfinder`, `httpx`,
`whatweb`, `testssl.sh`, `nmap`, and `nuclei`. A catalogue entry without an
adapter cannot execute through Sentinel.

## 4. Reconnaissance and individual adapters

Passive reconnaissance:

```bash
python3 sentinel.py recon acme example.com
python3 sentinel.py tools run acme whois example.com
```

An active adapter requires both approval gates:

```bash
python3 sentinel.py tools run acme-active nmap example.com \
  --profile safe \
  --approve-active \
  --timeout 600
```

Targets are scope-checked before execution. Adapters use argument arrays rather
than shell strings. Output is stored under `.sentinel/runs/` and supported output
is normalized into entities and findings.

## 5. One-command hunts

For the complete reviewed sequence, use `assess`. This runs one persistent
workflow in dependency order, then performs correlation, graph construction,
risk scoring, validation planning, reporting, dashboard generation, and a final
health check.

Review the complete sequence first:

```bash
python3 sentinel.py assess acme-active example.com --dry-run
```

Run the complete sequence with one up-front active approval:

```bash
python3 sentinel.py assess acme-active example.com --approve-active
```

The execution order is:

```text
preflight
  → DNS and registration
  → passive subdomain discovery
  → HTTP and technology discovery
  → TLS review
  → network service discovery
  → vulnerability checks
  → normalization and deduplication
  → finding correlation
  → knowledge graph and risk prediction
  → validation plan
  → JSON/HTML report and dashboard
  → evidence health check
```

Unavailable adapters are recorded as skipped; they are never replaced with
arbitrary shell commands. A blocked policy gate stops the chain. The command
does not run reference-only catalogue tools or automatically exploit live
targets.

Inspect a plan without network execution:

```bash
python3 sentinel.py hunt acme-active example.com \
  --mode full-safe \
  --dry-run
```

Modes are `passive`, `web`, `network`, and `full-safe`. Execute after reviewing
authorization and the plan:

```bash
python3 sentinel.py hunt acme-active example.com \
  --mode full-safe \
  --approve-active
```

A completed hunt correlates findings, scores risk, links vulnerability
intelligence, creates a least-intrusive validation plan, and generates JSON,
HTML, and dashboard output.

## 6. Workflows and jobs

```bash
python3 sentinel.py workflow profiles
python3 sentinel.py workflow create acme-active web-safe example.com
python3 sentinel.py workflow run WORKFLOW_ID --dry-run
python3 sentinel.py workflow run WORKFLOW_ID --approve-active
```

Queue a workflow for background processing:

```bash
python3 sentinel.py jobs enqueue acme-active WORKFLOW_ID --approve-active
python3 sentinel.py jobs list acme-active
python3 sentinel.py jobs run-next acme-active
```

Commands print record identifiers when they create them. Use those returned IDs
instead of assuming they start at `1`.

## 7. Scheduling and the worker

Create a daily schedule:

```bash
python3 sentinel.py schedule add acme-active example.com web-safe \
  --interval 86400 \
  --approve-active
python3 sentinel.py schedule list acme-active
python3 sentinel.py schedule enqueue-due acme-active
```

The minimum interval is five minutes. Run the bounded worker:

```bash
python3 sentinel.py daemon run acme-active \
  --poll-seconds 15 \
  --max-jobs 100 \
  --max-runtime 86400
```

From another terminal:

```bash
python3 sentinel.py daemon status acme-active
python3 sentinel.py daemon stop acme-active
```

The worker observes the kill switch, stop file, job limit, runtime limit, and
health checks. `deploy/sentinel-worker.service` is a hardened systemd template;
replace its placeholders and review its paths before installing it.

## 8. KEV, EPSS, and the knowledge graph

Import archived, reviewed snapshots of CISA KEV JSON and FIRST EPSS CSV:

```bash
python3 sentinel.py intel import-kev known_exploited_vulnerabilities.json
python3 sentinel.py intel import-epss epss_scores.csv
```

Link CVEs from findings to assets, products, and threat signals:

```bash
python3 sentinel.py intel link acme-active
python3 sentinel.py intel paths acme-active --source example.com --max-depth 5
```

Prioritize and plan validation:

```bash
python3 sentinel.py intel prioritize acme-active
python3 sentinel.py intel validation-plan acme-active
```

Scores expose severity, EPSS probability, KEV status, and evidence confidence.
Lower-priority findings use passive evidence; medium-priority findings may use
non-destructive scoped checks; KEV and high-priority findings are routed to an
isolated laboratory. Sentinel does not automatically exploit live targets.

## 9. Correlation, risk, and paths

```bash
python3 sentinel.py validate acme-active
python3 sentinel.py intel score acme-active
python3 sentinel.py intel paths acme-active
```

Validation states are `unverified`, `reproduced`, and `confirmed`. A single
scanner result is not automatically considered independently confirmed.

## 10. API, traffic, and standardized results

Analyze an OpenAPI 3 or Swagger JSON file without sending requests:

```bash
python3 sentinel.py api analyze-openapi acme-active openapi.json
```

Any server declared by the specification must match engagement scope. Analyze a
browser-proxy HAR file passively:

```bash
python3 sentinel.py proxy analyze-har acme-active traffic.har
```

Import SARIF 2.1 output from SAST, SCA, IaC, cloud, container, mobile, firmware,
or other compatible tools:

```bash
python3 sentinel.py results import-sarif acme-active scan-results.sarif
```

## 11. Source and credential-exposure review

```bash
python3 sentinel.py credentials audit ./source-tree --max-files 5000
```

This reports redacted indicators and never returns detected secret values. Use it
only for files and repositories you are authorized to inspect.

## 12. Evidence and health

Add classified evidence:

```bash
python3 sentinel.py evidence acme-active ./capture.json \
  --classification CONFIDENTIAL \
  --category tool-output
```

List evidence and verify workspace health:

```bash
python3 sentinel.py secure list acme-active
python3 sentinel.py secure verify acme-active
python3 sentinel.py health acme-active
python3 sentinel.py health acme-active --repair
```

Evidence is content-addressed with SHA-256. Store the data directory on encrypted
storage and apply retention appropriate to its classification.

## 13. Isolated vulnerability research

Research campaigns require a `--lab-mode` engagement. Sentinel stores plans and
evidence; review the sandbox plan before launching an external fuzzing engine.

```bash
python3 sentinel.py research create parser-lab parser-fuzz afl++ \
  ./parser ./corpus --max-seconds 3600
python3 sentinel.py research sandbox-plan CAMPAIGN_ID
python3 sentinel.py research plan CAMPAIGN_ID
python3 sentinel.py research ingest-corpus CAMPAIGN_ID ./corpus
python3 sentinel.py research corpus-stats CAMPAIGN_ID
python3 sentinel.py research import-coverage CAMPAIGN_ID ./coverage.json
python3 sentinel.py research coverage-trend CAMPAIGN_ID
python3 sentinel.py research triage CAMPAIGN_ID ./asan-crash.log
```

Record controlled reproduction and score the candidate:

```bash
python3 sentinel.py research record-reproduction CRASH_ID ./crash-input \
  reproduced --sanitizer ASan
python3 sentinel.py research score-candidate CRASH_ID
```

Prevent a known issue from being labeled novel:

```bash
python3 sentinel.py research add-known-signature \
  SHA256_FINGERPRINT CVE-2026-12345 --source vendor-advisory
```

“Zero-day candidate” is not proof of public novelty. Vendor coordination and
external-database review are still required.

## 14. Loopback laboratory validation

```bash
python3 sentinel.py lab validate-marker parser-lab \
  http://localhost:8000/ \
  --approve-active
```

The validator sends a unique harmless marker and records whether it was reflected.
Non-loopback targets are rejected.

## 15. Reports and dashboard

```bash
python3 sentinel.py report acme-active
python3 sentinel.py dashboard acme-active
```

Output under `.sentinel/reports/` includes scope, findings, remediation guidance,
coverage, graph information, runs, workflows, jobs, schedules, vulnerability
intelligence, research evidence, and evidence metadata. The dashboard is a local
HTML snapshot, not a network service.

## 16. Extensions

```bash
python3 sentinel.py extensions install ./sentinel-extension.json
python3 sentinel.py extensions list
```

Registration does not execute extension code. Executable entrypoints and
unexpected files are rejected.

## 17. Provenance and benchmarking

```bash
python3 sentinel.py provenance
python3 sentinel.py benchmark --iterations 250
```

Provenance records installed adapter hashes. Benchmarks disclose their local
environment and are not universal performance claims.

## Complete authorized workflow

```bash
# Initialize and certify
python3 sentinel.py init
python3 sentinel.py doctor --write

# Create precise scope with active testing enabled
python3 sentinel.py engagement create authorized-test \
  --domain example.com \
  --allow-subdomains \
  --enable-active \
  --max-rate 20

# Review before execution
python3 sentinel.py assess authorized-test example.com --dry-run

# Execute the full reviewed chain
python3 sentinel.py assess authorized-test example.com --approve-active

# Or select a narrower hunt profile
python3 sentinel.py hunt authorized-test example.com \
  --mode full-safe \
  --dry-run

# Execute the approved plan
python3 sentinel.py hunt authorized-test example.com \
  --mode full-safe \
  --approve-active

# Add reviewed vulnerability-intelligence snapshots
python3 sentinel.py intel import-kev known_exploited_vulnerabilities.json
python3 sentinel.py intel import-epss epss_scores.csv

# Link, prioritize, validate, and report
python3 sentinel.py intel link authorized-test
python3 sentinel.py intel prioritize authorized-test
python3 sentinel.py intel validation-plan authorized-test
python3 sentinel.py validate authorized-test
python3 sentinel.py report authorized-test
python3 sentinel.py dashboard authorized-test
```

## Data layout

```text
.sentinel/
├── sentinel.db             SQLite state and audit records
├── evidence/               Content-addressed evidence
├── runs/                   Tool stdout and stderr
├── reports/                JSON, HTML, and dashboard output
├── certification.json      Optional doctor report
├── heartbeat-*.json        Worker status
└── stop-*                  Worker stop requests
```

## Troubleshooting

### Target is outside engagement scope

Review `engagement list` and create an engagement containing the exact authorized
domain, IP, or CIDR. Never broaden scope merely to bypass the error.

### Active execution is disabled

The engagement was not created with `--enable-active`. Create an appropriately
authorized engagement; active mode is never inferred.

### Active execution requires explicit approval

Review the dry run, then add `--approve-active` only when the operation is
authorized.

### Tool is not installed

Run `doctor --write` and install the expected upstream package through a trusted,
pinned process. Catalogue presence is not installation.

### Workflow is blocked

Check scope, the kill switch, active enablement, per-run approval, installed
adapters, and workflow status. Policy decisions are included in the audit log.

### Environment is not ready

One or more reviewed adapters are missing or unverified. `doctor` identifies
exactly which adapters passed, failed, or remain untested.

## Development and verification

```bash
python3 -m py_compile sentinel.py sentinel/*.py
python3 -W error::ResourceWarning -m unittest discover -v
```

Continuous integration runs these checks and verifies the stated catalogue floor.

## Deployment and security documentation

- `deploy/Dockerfile` runs Sentinel as an unprivileged user with state at `/data`.
- `deploy/sentinel-worker.service` is the bounded-worker systemd template.
- Pin the container base and executable hashes in production.
- Back up and protect the data directory before upgrades.
- Read [SECURITY.md](SECURITY.md), [the threat model](docs/threat-model.md),
  [certification](docs/certification.md), and
  [vulnerability intelligence](docs/vulnerability-intelligence.md).

Do not place credentials, personal data, or third-party evidence in public
issues. Report Sentinel security defects through GitHub private vulnerability
reporting as described in [SECURITY.md](SECURITY.md).
