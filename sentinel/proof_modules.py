from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class ProofModule:
    module_id: str
    family: str
    mode: str
    max_requests: int
    side_effects: str
    evidence: tuple[str, ...]
    cleanup: str
    keywords: tuple[str, ...]


MODULES = (
    ProofModule("authorization-differential", "access-control", "offline-or-safe-active", 6, "Reads only", ("baseline response", "variant response", "identity labels"), "No target changes", ("idor", "bola", "authorization", "access control")),
    ProofModule("session-policy-review", "authentication", "offline", 0, "None", ("sanitized session observations",), "No target changes", ("session", "authentication", "oauth", "jwt", "2fa")),
    ProofModule("inert-reflection-marker", "browser", "lab-only", 1, "Adds an inert marker to one request", ("marker hash", "sanitized response"), "Marker expires; no stored target state", ("xss", "reflection", "html injection")),
    ProofModule("injection-differential", "injection", "offline-or-lab", 4, "No data extraction; laboratory requests only", ("response deltas", "timing summary"), "Disposable lab restored", ("sql injection", "nosql", "command injection", "template injection")),
    ProofModule("callback-observation", "server-request", "lab-only", 2, "Operator-owned loopback callback only", ("unique token", "callback event"), "Token expires automatically", ("ssrf", "xxe", "blind")),
    ProofModule("file-policy-review", "file-path", "offline-or-lab", 3, "Inert file only; no executable upload", ("upload policy", "storage behavior"), "Remove inert lab artifact", ("upload", "path traversal", "lfi", "rfi")),
    ProofModule("cache-behavior-differential", "cache-proxy", "offline-or-lab", 4, "No poisoning of shared production caches", ("cache headers", "response deltas"), "Disposable cache cleared", ("cache poisoning", "cache deception")),
    ProofModule("api-schema-and-role-matrix", "api", "offline", 0, "None", ("schema observation", "role matrix"), "No target changes", ("api", "graphql", "mass assignment", "websocket")),
    ProofModule("workflow-invariant-review", "business-logic", "offline-or-lab", 4, "No purchases, transfers, or irreversible actions", ("state model", "invariant delta"), "Disposable records removed", ("business logic", "race condition", "price", "quantity")),
)


def list_modules() -> list[dict]:
    return [asdict(module) for module in MODULES]


def select_modules(title: str, details: str = "") -> list[ProofModule]:
    text = f"{title} {details}".lower()
    selected = [module for module in MODULES if any(keyword in text for keyword in module.keywords)]
    return selected or [ProofModule("manual-specialist-review", "unclassified", "manual", 0, "Unknown until reviewed", ("analyst notes",), "Defined during review", ())]
