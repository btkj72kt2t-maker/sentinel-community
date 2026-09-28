# Production-readiness gates

Sentinel reports implemented foundations separately from production completion.
No local command may mark an external validation gate complete merely because a
module exists.

| Area | Local foundation | External acceptance gate |
|---|---|---|
| Reviewed adapters | Fixed argument arrays, scope policy, certification and integrity hashes | Certify pinned versions on every supported operating system |
| Web, API and authentication | OpenAPI, AsyncAPI, GraphQL, HAR, authorization-matrix and inert evidence analysis | Test representative multi-role accounts and traffic under written authorization |
| Cloud and containers | Offline Terraform-plan and Kubernetes-JSON review | Compare results with authorized read-only provider assessment data |
| Source and research | SAST/SCA/SBOM integration, corpus, coverage, triage and novelty evidence | Run sanitizer-backed fuzzing in an isolated worker and independently review candidates |
| Mobile, firmware and devices | Bounded, non-executing artifact inventory | Validate owned devices and firmware in an isolated hardware lab |
| Validation lab | Loopback-only Juice Shop/WebGoat stack and proof recording | Maintain expected-result benchmark cases and repeatable cleanup evidence |
| Operator experience | CLI, reports and local dashboard | Complete usability and accessibility testing with intended operators |
| Deployment | Unprivileged container, health check, daemon bounds and circuit breaker | Complete upgrade, recovery, backup, capacity and long-duration tests |
| Reporting | Sanitized evidence, hashes, remediation and disclosure packages | Review output with program owners and applicable disclosure/legal policy |
| Assurance | Unit tests, certification, provenance and local benchmarks | Obtain an independent security assessment and remediate its findings |

Run:

```bash
python3 sentinel.py readiness
python3 sentinel.py doctor --write
python3 -m unittest discover -s tests
```

The first command lists the remaining gate for every area. The second certifies
the current host; the third verifies deterministic local behavior. None of them
authorizes a target or guarantees that every vulnerability will be discovered.
