# Threat model

## Assets

Engagement scope, evidence, reports, tool output, schedules, audit records, and
operator authorization decisions are protected assets.

## Trust boundaries

- CLI input and imported files are untrusted.
- External tool output is untrusted and normalized before persistence.
- Catalogue entries are reference metadata, not executable code.
- External targets are denied unless they match stored engagement scope.
- Active adapters require both engagement enablement and per-run approval.
- Research execution requires an isolated lab engagement.

## Primary threats and controls

| Threat | Control |
|---|---|
| Scope escape | Canonical target matching before workflow, tool, API, and schedule operations |
| Command injection | Argument arrays from registered adapters; no shell execution |
| Malicious extension | Declarative manifests only; executable entrypoints rejected |
| Runaway automation | Rate limits, timeouts, job/runtime bounds, stop file, kill switch |
| False confirmation | Independent-source correlation and explicit confidence state |
| Evidence tampering | SHA-256 evidence inventory and health verification |
| Tool substitution | Executable provenance hashes and deployment pinning |
| Secret leakage | Redacted credential auditing and classified evidence handling |
| Unsafe research | Loopback/lab gates, sandbox planning, crash reproduction requirements |

## Explicit non-goals

Sentinel does not provide credential harvesting, persistence, evasion, destructive
actions, unrestricted payload execution, autonomous lateral movement, or a claim
that every known or unknown vulnerability can be found.
