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

## Detailed installation guide

### Requirements

The Sentinel core requires:

- Python 3.10 or newer, including the standard-library SQLite module.
- Git for installation and upgrades.
- Linux, Kali Linux, or macOS.
- Access to the public GitHub repository.
- Written authorization for every target placed in an engagement.

The core has no third-party Python package dependency. External security tools
are optional and are required only for the corresponding reviewed adapter.
Sentinel never downloads, upgrades, or executes an unreviewed tool silently.

Check the base environment:

```bash
python3 --version
python3 -c "import sqlite3; print(sqlite3.sqlite_version)"
git --version
```

### 1. Clone the repository

GitHub CLI is one convenient option:

```bash
gh auth status
gh repo clone btkj72kt2t-maker/sentinel-community
cd sentinel-community
```

Alternatively, use an authenticated HTTPS or SSH setup already configured for
your GitHub account:

```bash
git clone https://github.com/btkj72kt2t-maker/sentinel-community.git
cd sentinel-community
```

Never place a GitHub token directly in a clone URL, shell history, README, or
Sentinel evidence directory.

### 2. Create an isolated Python environment

Sentinel can run with the system Python, but an isolated environment makes the
runtime explicit and reproducible:

```bash
python3 -m venv .venv
source .venv/bin/activate
python --version
python sentinel.py --help
```

There is currently no `pip install` step because the core uses only the Python
standard library. In the remaining examples, replace `python3` with `python` if
the virtual environment is active.

### 3. Choose and protect the data directory

By default, runtime state is written to `.sentinel/` inside the checkout. For a
long-lived installation, use a separate directory on encrypted storage:

```bash
mkdir -p "$PWD/../sentinel-data"
chmod 700 "$PWD/../sentinel-data"
export SENTINEL_DATA_DIR="$PWD/../sentinel-data"
python3 sentinel.py init
```

To keep this setting across terminal sessions, add the export to the operator's
shell profile or to a protected service environment file. Do not point multiple
simultaneous Sentinel processes at the same SQLite database unless the workflow
has been designed for that deployment.

The data directory may contain confidential scope, raw tool output, evidence,
reports, and audit records. Never commit or publicly share it.

### 4. Install optional reviewed adapters

Sentinel currently has reviewed adapters for the following binaries:

| Capability | Binary |
|---|---|
| DNS and registration | `dig`, `whois`, `subfinder`, `dnsx` |
| Port and service discovery | `naabu`, `nmap` |
| HTTP discovery and crawling | `httpx`, `katana`, `feroxbuster`, `whatweb` |
| TLS assessment | `testssl.sh`, `tlsx` |
| Template-based checks | `nuclei` |

Offline source and supply-chain analysis additionally supports `semgrep`,
`osv-scanner`, `trivy`, `gitleaks`, and `syft`.

Install tools only from their official project, a trusted operating-system
repository, or a verified release. Package names vary between operating-system
versions. On Kali/Debian, the usual base packages can be installed with:

```bash
sudo apt update
sudo apt install python3 python3-venv git golang-go \
  bind9-dnsutils whois nmap whatweb feroxbuster testssl.sh
```

ProjectDiscovery tools can be built with the supported Go version from their
official modules:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Ensure the Go binary directory is available to Sentinel:

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
```

On macOS, install Python, Git, Go, and available adapters with a trusted package
manager, then use the same official Go module commands for ProjectDiscovery
tools. Sentinel does not require Kali-specific filesystem paths.

The priority offline analyzers are available through Homebrew:

```bash
brew install semgrep osv-scanner trivy gitleaks syft
```

`latest` is convenient for a workstation evaluation. For production or
repeatable evidence, pin approved versions, record checksums, test upgrades in a
separate environment, and retain the generated certification report.

### 5. Initialize and certify the installation

```bash
python3 sentinel.py init
python3 sentinel.py doctor --write
python3 sentinel.py tools list
python3 sentinel.py coverage
```

Initialization creates the SQLite database and data directories. `doctor`
checks adapter argument construction, executable permissions, local binary
identity, and safe version probes. Its JSON report is written to
`$SENTINEL_DATA_DIR/certification.json` or `.sentinel/certification.json`.

A missing optional binary is reported as `untested`; it is not a successful
installation. A workflow records that adapter as skipped and continues where
policy permits. A `failed` certification result must be investigated before
using the affected adapter.

### 6. Run the tests

Verify the checkout before using it for engagement evidence:

```bash
python3 -m py_compile sentinel.py sentinel/*.py
python3 -W error::ResourceWarning -m unittest discover -v
```

All tests should pass. These tests validate Sentinel's policy and integration
logic; they do not certify an external target or guarantee vulnerability
coverage.

### 7. Optional container installation

The included image runs the Sentinel core as an unprivileged user:

```bash
docker build -f deploy/Dockerfile -t sentinel-community:local .
docker volume create sentinel-data
docker run --rm -v sentinel-data:/data sentinel-community:local init
docker run --rm -v sentinel-data:/data sentinel-community:local doctor
```

The base image intentionally does not bundle every external scanner. Add only
approved, pinned adapter binaries in a controlled derived image, then rerun
`doctor --write`. Network access, target scope, and container privileges remain
the operator's responsibility.

### 8. Upgrade safely

Stop workers, back up the protected data directory, then update and verify:

```bash
python3 sentinel.py daemon stop ENGAGEMENT_NAME
git status --short
git pull --ff-only
python3 sentinel.py init
python3 -m unittest discover
python3 sentinel.py doctor --write
```

`init` is safe to rerun and applies additive database migrations. Review release
changes before resuming scheduled work. Never overwrite a checkout containing
uncommitted operator changes.

## First authorized assessment

This walkthrough demonstrates the normal installation-to-report flow. Replace
`example.com` only with a target explicitly listed in your authorization.

1. Create a precisely scoped, active-enabled engagement:

   ```bash
   python3 sentinel.py engagement create authorized-web \
     --domain example.com \
     --allow-subdomains \
     --enable-active \
     --max-rate 20
   ```

2. Review the stored scope and the complete execution plan:

   ```bash
   python3 sentinel.py engagement list
   python3 sentinel.py assess authorized-web example.com --dry-run
   ```

3. Check local readiness and resolve missing tools you intend to use:

   ```bash
   python3 sentinel.py doctor --write
   python3 sentinel.py tools list
   ```

4. Run the reviewed pipeline after confirming authorization and timing:

   ```bash
   python3 sentinel.py assess authorized-web example.com --approve-active
   ```

5. Correlate, prioritize, and generate fresh output when needed:

   ```bash
   python3 sentinel.py validate authorized-web
   python3 sentinel.py intel prioritize authorized-web
   python3 sentinel.py intel validation-plan authorized-web
   python3 sentinel.py report authorized-web
   python3 sentinel.py dashboard authorized-web
   ```

6. Verify evidence integrity and inspect the generated paths printed by the
   report commands:

   ```bash
   python3 sentinel.py secure verify authorized-web
   python3 sentinel.py health authorized-web
   ```

The complete assessment skips unavailable adapters, retains their status, and
does not substitute arbitrary commands. It does not automatically exploit live
targets. Controlled proof workflows are separately gated and documented below.

## Usage guide map

| Goal | Primary command | Detailed section |
|---|---|---|
| Define authorization boundaries | `engagement create` | Engagements and scope |
| Stop or resume activity | `engagement kill`, `engagement resume` | Emergency controls |
| Inspect installed capabilities | `doctor`, `tools list`, `coverage` | Tools, catalogue, and coverage |
| Run the full reviewed chain | `assess` | One-command hunts |
| Run a narrower plan | `hunt`, `workflow` | Hunts, workflows, and jobs |
| Schedule bounded recurring work | `schedule`, `daemon` | Scheduling and the worker |
| Prioritize known vulnerabilities | `intel` | KEV, EPSS, and knowledge graph |
| Import offline results | `results import-sarif` | API, traffic, and standardized results |
| Conduct isolated fuzzing research | `research` | Isolated vulnerability research |
| Record controlled proof | `proof`, `lab` | Proof Engine and laboratory validation |
| Generate deliverables | `report`, `dashboard` | Reports and dashboard |
| Verify evidence integrity | `secure verify`, `health` | Evidence and health |

Use `python3 sentinel.py COMMAND --help` for the accepted arguments of any
top-level command. Subcommands support the same pattern, for example:

```bash
python3 sentinel.py engagement create --help
python3 sentinel.py tools run --help
python3 sentinel.py workflow create --help
python3 sentinel.py intel sync --help
python3 sentinel.py proof start --help
```

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

Reviewed adapters currently cover `dig`, `whois`, `subfinder`, `dnsx`, `naabu`,
`httpx`, `katana`, `feroxbuster`, `whatweb`, `testssl.sh`, `tlsx`, `nmap`, and `nuclei`. A
catalogue entry without an adapter cannot execute through Sentinel.

The maintained-tool research, selection gates, accuracy model, recommended
stack, and next integration priorities are documented in
[`docs/advanced-tool-research.md`](docs/advanced-tool-research.md).

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

Run focused, bounded SQL-injection or XSS detection profiles when a narrower
assessment is appropriate:

```bash
python3 sentinel.py tools run acme-active nuclei example.com \
  --profile sqli-detect --approve-active
python3 sentinel.py tools run acme-active nuclei example.com \
  --profile xss-detect --approve-active
```

These profiles use the corresponding Nuclei template tags, a lower rate limit,
and single-target concurrency. They detect and collect evidence; they do not
extract database contents, modify records, execute a browser payload, or turn a
scanner match into an automatically confirmed finding.

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
  → bounded DNS validation
  → bounded port enumeration
  → HTTP and technology discovery
  → bounded endpoint and content enumeration
  → TLS review
  → independent TLS certificate and configuration collection
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

Synchronize both authoritative feeds through the trusted-source updater:

```bash
python3 sentinel.py intel sync all
python3 sentinel.py intel feed-history
```

Downloads use a built-in HTTPS host allowlist, constrained redirects, compressed
and decompressed size limits, format validation, and SHA-256 archival under
`.sentinel/intelligence/` before import. `sync` accepts `kev`, `epss`, or `all`.

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

### STIX 2.1 exchange

```bash
python3 sentinel.py intel import-stix acme-active intelligence-bundle.json
python3 sentinel.py intel export-stix acme-active sentinel-bundle.json
```

Imported relationships are retained where both endpoints map to supported graph
entities. Export covers domains, IP addresses, software, and vulnerabilities;
unsupported internal objects are not silently converted.

### CSAF, VEX, and CycloneDX SBOMs

```bash
python3 sentinel.py intel import-csaf vendor-advisory.json
python3 sentinel.py intel import-sbom acme-active bom.cdx.json
python3 sentinel.py intel component-risk acme-active
```

Component risk combines inventory relationships, VEX state, KEV, EPSS, and
vendor remediation. `not_affected` and `false_positive` VEX states are separated
from affected components, but product identity and reachability still require
verification.

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

Saved AsyncAPI and GraphQL introspection documents can be reviewed without
opening broker connections or issuing GraphQL queries:

```bash
python3 sentinel.py api analyze-asyncapi acme-active asyncapi.json
python3 sentinel.py api analyze-graphql acme-active introspection.json
```

Any server declared by the specification must match engagement scope. Analyze a
browser-proxy HAR file passively:

```bash
python3 sentinel.py proxy analyze-har acme-active traffic.har
```

Run the credential-redacting authentication/session review for scoped HAR
traffic:

```bash
python3 sentinel.py proxy analyze-auth-har acme-active authenticated.har
```

This records URL parameter names, cookie-policy gaps, credentialed CORS
misconfiguration, authenticated caching risks, and CSRF review signals. It does
not retain authorization values, cookies, query values, request bodies, or
response bodies.

Review a JWT from a protected file without storing the token:

```bash
python3 sentinel.py auth analyze-jwt acme-active ./captured-token.txt
```

Sentinel reports the algorithm, claim names, token hash, lifetime/context
signals, and an explicit `signature_verified: false`. It does not guess signing
keys, accept a token as valid, or persist token contents. Delete the protected
input according to the engagement retention policy.

Review exported Terraform plan JSON or Kubernetes JSON locally, without cloud
credentials or provider API access:

```bash
terraform show -json saved.plan > terraform-plan.json
python3 sentinel.py cloud analyze-json acme-active terraform terraform-plan.json
python3 sentinel.py cloud analyze-json acme-active kubernetes workload.json
```

The built-in rules cover public sensitive service exposure, public object-store
ACLs, wildcard IAM grants, privileged containers, host namespace/path sharing,
privilege escalation, root-user policy, and added Linux capabilities. Exported
plans may contain sensitive values; protect and remove them according to the
engagement retention policy.

Inspect an authorized mobile, firmware, or binary artifact without extraction
or execution:

```bash
python3 sentinel.py artifact inspect acme-active firmware.bin
```

The result contains streaming SHA-256 integrity, bounded entropy analysis, and
embedded file-signature offsets. This is triage—not proof that embedded content
is safe or vulnerable.

Import SARIF 2.1 output from SAST, SCA, IaC, cloud, container, mobile, firmware,
or other compatible tools:

```bash
python3 sentinel.py results import-sarif acme-active scan-results.sarif
```

## 11. Source and credential-exposure review

Run fixed-profile local analysis against an authorized source tree:

```bash
python3 sentinel.py source scan acme-active semgrep ./source-tree
python3 sentinel.py source scan acme-active osv-scanner ./source-tree
python3 sentinel.py source scan acme-active trivy ./source-tree
python3 sentinel.py source scan acme-active gitleaks ./source-tree
python3 sentinel.py source scan acme-active syft ./source-tree
```

After intentionally populating the local advisory cache, Trivy can run without
refreshing it or performing dependency lookups:

```bash
python3 sentinel.py source scan acme-active trivy ./source-tree --offline
```

- Semgrep uses Sentinel's versioned local rules with metrics disabled.
- OSV-Scanner identifies vulnerable dependencies without enabling build-script
  or call-analysis execution.
- Trivy uses precise detection for vulnerabilities, configuration, and secrets.
- Gitleaks forces complete secret redaction and excludes archive traversal.
- Syft produces CycloneDX JSON that Sentinel imports into its component graph.

Raw outputs remain protected under the run directory. Normalized secret
findings exclude secret values, matching text, and source lines. Treat the
source tree itself as untrusted; scanners never invoke its build scripts through
these profiles.

Some analyzers download signed advisory databases on first use. Populate and
approve those caches in a controlled environment before an air-gapped scan.

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

For a disposable, loopback-only Juice Shop and WebGoat environment, follow
[`docs/lab-validation.md`](docs/lab-validation.md). Record resolved container
digests before testing and remove all lab volumes afterward.

```bash
python3 sentinel.py lab validate-marker parser-lab \
  http://localhost:8000/ \
  --approve-active
```

The validator sends a unique harmless marker and records whether it was reflected.
Non-loopback targets are rejected.

Record sanitized proof evidence after an approved isolated-lab reproduction:

```bash
python3 sentinel.py lab record-proof parser-lab FINDING_ID ./proof.txt confirmed \
  --rollback-verified \
  --notes "Reproduced in disposable lab; service restored"
python3 sentinel.py lab proofs parser-lab
```

Confirmed proof requires an explicit rollback/cleanup confirmation. The evidence
file is hashed and linked to the finding; this command records proof but does not
execute an exploit.

## 15. Proof Engine

List declarative proof modules and generate an evidence plan for a finding:

```bash
python3 sentinel.py proof modules
python3 sentinel.py proof plan ENGAGEMENT FINDING_ID
```

Move an eligible module to `ready` after its policy gates pass:

```bash
python3 sentinel.py proof start LAB_ENGAGEMENT FINDING_ID MODULE_ID \
  --approve-active
python3 sentinel.py proof runs LAB_ENGAGEMENT
```

`ready` does not mean exploited. It means the module contract, request budget,
side effects, evidence requirements, cleanup procedure, engagement mode, and
approval were checked.

Analyze two sanitized HTTP observations without sending traffic:

```bash
python3 sentinel.py proof differential ENGAGEMENT FINDING_ID differential.json
```

The JSON input contains `baseline` and `variant`, each with `status`, `headers`,
and `body`. Sensitive headers are redacted; Sentinel records hashes, lengths,
status changes, header-name changes, and body similarity.

Evaluate an authorization matrix:

```bash
python3 sentinel.py proof auth-matrix ENGAGEMENT FINDING_ID role-matrix.json
```

The input uses an `observations` array with `role`, `resource`, `action`,
`expected_allowed`, and `observed_allowed` fields.

Analyze captured SQL-injection differential evidence without sending additional
traffic:

```bash
python3 sentinel.py proof sqli-evidence ENGAGEMENT FINDING_ID sql-evidence.json
```

The input contains `baseline` and `variant` objects with `status`, `elapsed_ms`,
and `body`. Sentinel records hashes, lengths, response similarity, timing deltas,
status changes, and introduced database-error signatures. Response bodies are
not stored in the proof result. Even a strong signal remains a review finding,
not proof of database access or permission to extract data.

Analyze an inert XSS reflection marker:

```bash
python3 sentinel.py proof xss-evidence ENGAGEMENT FINDING_ID xss-evidence.json
```

The input contains an 8–128 character alphanumeric `marker` and a `response`
object with `content_type` and `body`. Sentinel reports exact reflection and
HTML script/attribute context signals, stores only response metadata and a hash,
and rejects executable marker text. Reflection alone is not proof that script
execution is possible; browser-context validation remains controlled and
lab/manual.

For loopback-only callback evidence in an isolated lab:

```bash
python3 sentinel.py lab callback-token LAB_ENGAGEMENT FINDING_ID --ttl 600
python3 sentinel.py lab callback-listen LAB_ENGAGEMENT \
  --seconds 300 --port 8765 --approve-active
python3 sentinel.py lab callback-events LAB_ENGAGEMENT
```

The listener binds only to `127.0.0.1`, accepts short-lived issued tokens, stores
header presence rather than secret values, and has a ten-minute maximum runtime.
It is not an internet callback or command-and-control service.

Generate a sanitized, hashed disclosure package:

```bash
python3 sentinel.py proof disclosure ENGAGEMENT FINDING_ID
```

The package includes the finding, linked vulnerability intelligence, proof runs,
lab evidence, callback observations, and remediation guidance. Review it manually
before sharing outside the authorized engagement.

## 16. Reports and dashboard

```bash
python3 sentinel.py report acme-active
python3 sentinel.py dashboard acme-active
```

Output under `.sentinel/reports/` includes scope, findings, remediation guidance,
coverage, graph information, runs, workflows, jobs, schedules, vulnerability
intelligence, research evidence, and evidence metadata. The dashboard is a local
HTML snapshot, not a network service.

## 17. Extensions

```bash
python3 sentinel.py extensions install ./sentinel-extension.json
python3 sentinel.py extensions list
```

Registration does not execute extension code. Executable entrypoints and
unexpected files are rejected.

## 18. Provenance and benchmarking

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
- Track the remaining external acceptance work in
  [production-readiness gates](docs/production-readiness.md).

Do not place credentials, personal data, or third-party evidence in public
issues. Report Sentinel security defects through GitHub private vulnerability
reporting as described in [SECURITY.md](SECURITY.md).
