from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .db import audit, connect, engagement, now


SENSITIVE_PORTS = {22, 23, 2375, 2376, 3389, 5432, 6379, 9200, 27017}


def _finding(severity: str, title: str, resource: str, details: dict) -> dict:
    return {"severity": severity, "title": title, "resource": resource, "details": details}


def _port(value: object, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _terraform(document: dict) -> tuple[int, list[dict]]:
    changes = document.get("resource_changes") or []
    findings: list[dict] = []
    for item in changes:
        if not isinstance(item, dict):
            continue
        resource = str(item.get("address") or "terraform-resource")
        kind = str(item.get("type") or "")
        after = (((item.get("change") or {}).get("after")) or {})
        if not isinstance(after, dict):
            continue
        if kind == "aws_s3_bucket_acl" and str(after.get("acl", "")).lower() in {"public-read", "public-read-write", "authenticated-read"}:
            findings.append(_finding("high", "Object storage ACL is not private", resource, {"acl": after.get("acl")}))
        if kind == "aws_s3_bucket_public_access_block" and any(after.get(key) is False for key in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")):
            findings.append(_finding("medium", "Object storage public-access protections are incomplete", resource, {"disabled_controls": sorted(key for key in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets") if after.get(key) is False)}))
        if kind in {"aws_security_group", "aws_security_group_rule"}:
            rules = after.get("ingress") if kind == "aws_security_group" else [after]
            for rule in rules or []:
                if not isinstance(rule, dict):
                    continue
                cidrs = set(rule.get("cidr_blocks") or []) | {str(rule.get("cidr_ipv4") or "")}
                start, end = _port(rule.get("from_port"), 0), _port(rule.get("to_port"), 65535)
                exposed = sorted(port for port in SENSITIVE_PORTS if start <= port <= end)
                if ({"0.0.0.0/0", "::/0"} & cidrs) and (exposed or (start == 0 and end >= 65535)):
                    findings.append(_finding("high", "Sensitive service range is publicly reachable", resource, {"ports": exposed or ["all"], "cidrs": sorted(cidrs & {"0.0.0.0/0", "::/0"})}))
        if kind in {"aws_iam_policy", "aws_iam_role_policy"}:
            policy = after.get("policy")
            if isinstance(policy, str):
                try:
                    policy = json.loads(policy)
                except json.JSONDecodeError:
                    policy = {}
            statements = (policy or {}).get("Statement", [])
            statements = [statements] if isinstance(statements, dict) else statements
            for statement in statements:
                if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
                    continue
                actions = statement.get("Action") if isinstance(statement.get("Action"), list) else [statement.get("Action")]
                resources = statement.get("Resource") if isinstance(statement.get("Resource"), list) else [statement.get("Resource")]
                if "*" in actions or "*" in resources:
                    findings.append(_finding("high", "IAM policy grants wildcard access", resource, {"action_wildcard": "*" in actions, "resource_wildcard": "*" in resources}))
        if kind.startswith("google_storage_bucket_iam_"):
            members = set(after.get("members") or []) | {str(after.get("member") or "")}
            public = sorted(members & {"allUsers", "allAuthenticatedUsers"})
            if public:
                findings.append(_finding("high", "Cloud storage IAM binding grants public access", resource, {"members": public, "role": after.get("role")}))
        if kind == "google_compute_firewall" and {"0.0.0.0/0", "::/0"} & set(after.get("source_ranges") or []):
            exposed = []
            for allow in after.get("allow") or []:
                for port in allow.get("ports") or [] if isinstance(allow, dict) else []:
                    if str(port).isdigit() and int(port) in SENSITIVE_PORTS:
                        exposed.append(int(port))
            if exposed:
                findings.append(_finding("high", "Sensitive service is exposed by a public cloud firewall rule", resource, {"ports": sorted(set(exposed))}))
        if kind == "azurerm_network_security_rule" and str(after.get("access", "")).lower() == "allow":
            sources = {str(after.get("source_address_prefix") or "")} | set(after.get("source_address_prefixes") or [])
            port_values = {str(after.get("destination_port_range") or "")} | set(after.get("destination_port_ranges") or [])
            exposed = sorted(port for port in SENSITIVE_PORTS if str(port) in port_values or "*" in port_values)
            if sources & {"*", "0.0.0.0/0", "Internet"} and exposed:
                findings.append(_finding("high", "Sensitive service is exposed by an Azure network security rule", resource, {"ports": exposed, "sources": sorted(sources & {"*", "0.0.0.0/0", "Internet"})}))
    return len(changes), findings


def _pod_specs(document: object) -> list[tuple[str, dict]]:
    documents = document.get("items", []) if isinstance(document, dict) and document.get("kind") == "List" else [document]
    result = []
    for item in documents:
        if not isinstance(item, dict):
            continue
        metadata, spec = item.get("metadata") or {}, item.get("spec") or {}
        metadata = metadata if isinstance(metadata, dict) else {}
        spec = spec if isinstance(spec, dict) else {}
        if str(item.get("kind")) in {"Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job"}:
            spec = (((spec.get("template") or {}).get("spec")) or {})
        if str(item.get("kind")) == "CronJob":
            spec = (((((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec")) or {})
        if isinstance(spec, dict) and (spec.get("containers") or spec.get("initContainers")):
            result.append((str(metadata.get("name") or item.get("kind") or "workload"), spec))
    return result


def _kubernetes(document: object) -> tuple[int, list[dict]]:
    specs = _pod_specs(document)
    findings: list[dict] = []
    for resource, spec in specs:
        if spec.get("hostNetwork") or spec.get("hostPID") or spec.get("hostIPC"):
            findings.append(_finding("high", "Workload shares a host namespace", resource, {"hostNetwork": bool(spec.get("hostNetwork")), "hostPID": bool(spec.get("hostPID")), "hostIPC": bool(spec.get("hostIPC"))}))
        for volume in spec.get("volumes") or []:
            if isinstance(volume, dict) and "hostPath" in volume:
                findings.append(_finding("high", "Workload mounts a host path", resource, {"volume": volume.get("name"), "path": (volume.get("hostPath") or {}).get("path")}))
        for container in list(spec.get("initContainers") or []) + list(spec.get("containers") or []):
            if not isinstance(container, dict):
                continue
            name, security = str(container.get("name") or "container"), container.get("securityContext") or {}
            security = security if isinstance(security, dict) else {}
            if security.get("privileged") is True:
                findings.append(_finding("critical", "Container is privileged", resource, {"container": name}))
            if security.get("allowPrivilegeEscalation") is not False:
                findings.append(_finding("medium", "Container does not explicitly prevent privilege escalation", resource, {"container": name}))
            if security.get("runAsNonRoot") is not True:
                findings.append(_finding("medium", "Container does not explicitly require a non-root user", resource, {"container": name}))
            capabilities = ((security.get("capabilities") or {}).get("add") or [])
            if capabilities:
                findings.append(_finding("medium", "Container adds Linux capabilities", resource, {"container": name, "capabilities": capabilities}))
    return len(specs), findings


def analyze_cloud_json(engagement_name: str, kind: str, path: Path) -> dict:
    if kind not in {"terraform", "kubernetes"}:
        raise ValueError("kind must be terraform or kubernetes")
    document = json.loads(path.read_text(encoding="utf-8"))
    resources, findings = _terraform(document) if kind == "terraform" else _kubernetes(document)
    with connect() as conn:
        eng = engagement(conn, engagement_name)
        for item in findings:
            fingerprint = hashlib.sha256(f"{kind}\0{item['resource']}\0{item['title']}".encode()).hexdigest()
            details = json.dumps(item["details"], sort_keys=True)
            existing = conn.execute("SELECT id FROM findings WHERE engagement_id=? AND fingerprint=?", (eng["id"], fingerprint)).fetchone()
            if existing:
                conn.execute("UPDATE findings SET occurrences=occurrences+1,details=?,severity=? WHERE id=?", (details, item["severity"], existing["id"]))
            else:
                conn.execute("INSERT INTO findings(engagement_id,target,source,severity,title,details,created_at,fingerprint) VALUES(?,?,?,?,?,?,?,?)", (eng["id"], item["resource"], f"{kind}-offline", item["severity"], item["title"], details, now(), fingerprint))
        audit(conn, "cloud.configuration_analyzed", {"kind": kind, "file": path.name, "resources": resources, "findings": len(findings)}, eng["id"])
    return {"kind": kind, "resources": resources, "findings": findings, "mode": "offline", "credentials_required": False}
