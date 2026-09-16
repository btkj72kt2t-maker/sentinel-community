# Tool certification

Run `python3 sentinel.py doctor --write` after installation and after every tool
upgrade. The resulting `.sentinel/certification.json` records:

- catalogue integrity and duplicate counts;
- SHA-256 identity and executable permissions for installed catalogue binaries;
- safe, local-only version probes for reviewed adapters;
- construction checks for every fixed adapter profile; and
- separate pass, failure, and untested states.

`adapter_code_certified` means every registered profile produced a fixed argument
array containing the target as a separate value. `installed_integrity_passed`
means no installed binary failed identity or permission checks.
`environment_ready` requires every reviewed adapter binary to be installed and
pass its probe. It is expected to remain false on partial installations.

Certification does not execute scans, contact targets, validate third-party tool
algorithms, or guarantee vulnerability coverage. Reference-only tools are never
launched. A production release still requires representative isolated-lab tests,
pinned expected hashes, parser fixtures, performance limits, and independent
review for each enabled adapter version.
