from __future__ import annotations

import shutil

from .tools import REGISTRY
from .source_scan import TOOLS as SOURCE_TOOLS


# A control-oriented taxonomy.  It records what Sentinel can assess without
# turning public payload collections into an automatic exploitation feed.
FAMILIES = (
    {"id": "access-control", "name": "Access control", "tests": ["IDOR/BOLA", "403 bypass", "mass assignment", "privilege boundaries"], "cwe": ["CWE-284", "CWE-639", "CWE-915"], "mode": "safe-active+manual", "tools": ["httpx", "nuclei", "burpsuite", "zaproxy"], "remediation": "Enforce object and function authorization server-side on every request; deny by default."},
    {"id": "authentication", "name": "Authentication and account recovery", "tests": ["2FA flows", "forgot-password flows", "default credentials", "account takeover preconditions"], "cwe": ["CWE-287", "CWE-798", "CWE-640"], "mode": "manual", "tools": ["burpsuite", "zaproxy"], "remediation": "Use phishing-resistant MFA, generic recovery responses, rate limits, and secure credential provisioning."},
    {"id": "session-token", "name": "Sessions, OAuth and tokens", "tests": ["OAuth misconfiguration", "JWT validation", "session lifecycle"], "cwe": ["CWE-384", "CWE-613", "CWE-347"], "mode": "safe-active+manual", "tools": ["jwt-tool", "oauth2c", "burpsuite"], "remediation": "Validate issuer, audience and signatures; rotate sessions; bind redirects to an exact allowlist."},
    {"id": "injection", "name": "Injection", "tests": ["SQL injection", "NoSQL injection", "command injection", "SSI injection", "template injection"], "cwe": ["CWE-89", "CWE-943", "CWE-78", "CWE-1336"], "mode": "safe-active+lab-only", "tools": ["nuclei", "semgrep", "sqlmap", "commix"], "remediation": "Use parameterized APIs, strict schemas, contextual escaping, and least-privileged service identities."},
    {"id": "browser", "name": "Browser and request integrity", "tests": ["XSS", "CSRF", "clickjacking", "tabnabbing", "open redirect", "CORS"], "cwe": ["CWE-79", "CWE-352", "CWE-601", "CWE-942"], "mode": "safe-active+manual", "tools": ["dalfox", "kxss", "burpsuite", "zaproxy"], "remediation": "Apply contextual output encoding, CSP, CSRF defenses, safe link attributes, and explicit origin policy."},
    {"id": "server-request", "name": "Server-side request handling", "tests": ["SSRF", "XXE", "request smuggling", "host-header injection", "CRLF injection"], "cwe": ["CWE-918", "CWE-611", "CWE-444", "CWE-113"], "mode": "safe-active+manual", "tools": ["nuclei", "httpx", "smuggler"], "remediation": "Normalize requests consistently; constrain outbound destinations; reject ambiguous framing and untrusted host metadata."},
    {"id": "file-path", "name": "Files and paths", "tests": ["file upload", "LFI", "RFI", "path traversal", "source exposure", "RFD"], "cwe": ["CWE-22", "CWE-98", "CWE-434", "CWE-540"], "mode": "safe-active+manual", "tools": ["nuclei", "feroxbuster", "ffuf"], "remediation": "Store uploads outside execution paths, generate names, validate content, canonicalize paths, and remove source artifacts."},
    {"id": "availability", "name": "Availability and resource controls", "tests": ["DoS preconditions", "rate limiting", "unbounded work"], "cwe": ["CWE-400", "CWE-770"], "mode": "passive+manual", "tools": ["semgrep", "k6"], "remediation": "Bound resource use, enforce quotas and timeouts, and validate safely in a representative lab."},
    {"id": "cache-proxy", "name": "Cache and proxy behavior", "tests": ["web cache poisoning", "web cache deception", "proxy inconsistencies"], "cwe": ["CWE-444", "CWE-525"], "mode": "safe-active+manual", "tools": ["httpx", "nuclei", "burpsuite"], "remediation": "Define cache keys explicitly, never cache personalized responses, and normalize requests consistently."},
    {"id": "api", "name": "API, GraphQL and realtime", "tests": ["BOLA", "property authorization", "resource consumption", "GraphQL introspection", "WebSocket authorization"], "cwe": ["CWE-639", "CWE-770", "CWE-285"], "mode": "safe-active+manual", "tools": ["kiterunner", "graphql-cop", "mitmproxy"], "remediation": "Authorize every object and property, cap query cost, validate schemas, and authenticate upgraded connections."},
    {"id": "business-logic", "name": "Business logic", "tests": ["workflow abuse", "race conditions", "price/quantity integrity"], "cwe": ["CWE-362", "CWE-840"], "mode": "manual", "tools": ["burpsuite", "zaproxy"], "remediation": "Model state transitions, enforce invariants atomically, and add abuse-case tests."},
    {"id": "secrets-supply-chain", "name": "Secrets and supply chain", "tests": ["exposed API keys", "dependency risk", "CI/CD trust", "artifact integrity"], "cwe": ["CWE-798", "CWE-1395"], "mode": "offline+passive", "tools": ["gitleaks", "trivy", "grype", "osv-scanner", "syft"], "remediation": "Revoke exposed secrets, use short-lived identities, pin and verify artifacts, and continuously inventory dependencies."},
    {"id": "cloud-container", "name": "Cloud, containers and orchestration", "tests": ["IAM exposure", "public storage", "container configuration", "Kubernetes policy"], "cwe": ["CWE-732", "CWE-250"], "mode": "read-only", "tools": ["prowler", "scoutsuite", "trivy", "kube-bench", "kubescape"], "remediation": "Apply least privilege, private defaults, policy-as-code, image provenance, and continuous configuration review."},
    {"id": "network-tls", "name": "Network, DNS and TLS", "tests": ["service exposure", "DNS configuration", "TLS posture", "segmentation evidence"], "cwe": ["CWE-200", "CWE-319", "CWE-326"], "mode": "safe-active", "tools": ["nmap", "naabu", "testssl.sh", "sslyze", "dnsx"], "remediation": "Minimize exposed services, segment trust zones, patch services, and enforce modern TLS and DNS controls."},
    {"id": "wireless-device", "name": "Wireless, mobile, device and firmware", "tests": ["Wi-Fi configuration", "mobile static analysis", "firmware analysis", "device attack surface"], "cwe": ["CWE-319", "CWE-693"], "mode": "owned-lab-only", "tools": ["mobsfscan", "mobsf", "jadx", "apktool", "binwalk", "firmwalker"], "remediation": "Use modern authenticated encryption, signed updates, hardware-backed keys, and minimize exposed device services."},
    {"id": "source-binary", "name": "Source, binary and offline research", "tests": ["SAST", "SCA", "fuzzing", "memory safety", "malformed input handling"], "cwe": ["CWE-119", "CWE-787", "CWE-20"], "mode": "offline+lab-only", "tools": ["semgrep", "codeql", "afl-fuzz", "libfuzzer", "jazzer", "honggfuzz"], "remediation": "Adopt memory-safe components, sanitizers, coverage-guided fuzzing, secure review, and reproducible builds."},
)


def coverage_matrix() -> dict:
    rows = []
    for family in FAMILIES:
        available = [tool for tool in family["tools"] if shutil.which(tool)]
        reviewed = [tool for tool in family["tools"] if tool in REGISTRY or tool in SOURCE_TOOLS]
        executable = [tool for tool in reviewed if shutil.which(tool)]
        blind_spot = not reviewed and "manual" not in family["mode"]
        rows.append({**family, "available_tools": available, "reviewed_adapters": reviewed, "executable_adapters": executable, "blind_spot": blind_spot, "automation": "reviewed-ready" if executable else ("reviewed-missing" if reviewed else ("manual" if "manual" in family["mode"] else "adapter-needed"))})
    reviewed_families = sum(bool(r["reviewed_adapters"]) for r in rows)
    return {
        "families": rows,
        "summary": {
            "families": len(rows),
            "with_installed_tools": sum(bool(r["available_tools"]) for r in rows),
            "with_reviewed_adapters": reviewed_families,
            "with_executable_adapters": sum(bool(r["executable_adapters"]) for r in rows),
            "automation_coverage_percent": round(100 * reviewed_families / len(rows), 1),
            "blind_spots": [r["id"] for r in rows if r["blind_spot"]],
        },
        "assurance": "Coverage measures reviewed capability, not a guarantee that every vulnerability or zero-day will be found.",
    }


def recommendations(findings: list[dict]) -> list[dict]:
    output = []
    for finding in findings:
        text = f"{finding.get('title', '')} {finding.get('details', '')}".lower()
        matches = [f for f in FAMILIES if any(test.lower().split()[0] in text for test in f["tests"])]
        if matches:
            output.append({"finding_id": finding.get("id"), "families": [m["id"] for m in matches], "remediation": matches[0]["remediation"]})
    return output
