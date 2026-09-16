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
python3 sentinel.py daemon run acme --poll-seconds 15 --max-runtime 86400
python3 sentinel.py daemon status acme
python3 sentinel.py daemon stop acme
python3 sentinel.py research create lab parser-fuzz afl++ ./parser ./corpus
python3 sentinel.py research plan 1
python3 sentinel.py research triage 1 ./asan-crash.log
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
- Broad bug-bounty capability catalogue with installation detection

The included systemd unit is a hardened template. Replace `ENGAGEMENT_NAME`, review
paths and policy, then install it manually on the authorized Kali host.
- SHA-256 evidence ingestion with append-only audit events
- SQLite entity/relationship graph
- JSON and HTML reporting

The codebase intentionally does not include credential attacks, automated
exploitation, stealth/evasion, or indiscriminate internet scanning.
