# Security policy

Please do not publish suspected Sentinel vulnerabilities in a public issue.
Use GitHub private vulnerability reporting for this repository and include the
affected commit, reproduction conditions, impact, and a minimal non-destructive
proof. Do not include live credentials, personal data, or third-party targets.

Sentinel treats catalogue data as untrusted metadata. A catalogue entry cannot
execute. Executable adapters require fixed argument construction, scope checks,
policy approval, rate limits, output normalization, evidence capture, and tests.

Supported security fixes target the current `main` branch. Deployment operators
must pin container images and external tool hashes, restrict the data directory,
and run active assessments only under written authorization.
