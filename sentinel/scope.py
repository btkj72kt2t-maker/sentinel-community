from __future__ import annotations

import ipaddress
from urllib.parse import urlparse


def normalize_target(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if "://" in value:
        parsed = urlparse(value)
        if not parsed.hostname:
            raise ValueError("URL has no hostname")
        return parsed.hostname.lower().rstrip(".")
    return value.split(":", 1)[0] if value.count(":") == 1 else value


def target_allowed(target: str, scope_rows) -> bool:
    host = normalize_target(target)
    for row in scope_rows:
        value = row["value"].lower().rstrip(".")
        if row["kind"] == "domain":
            if host == value or (row["allow_subdomains"] and host.endswith("." + value)):
                return True
        elif row["kind"] == "ip":
            try:
                if ipaddress.ip_address(host) == ipaddress.ip_address(value):
                    return True
            except ValueError:
                pass
        elif row["kind"] == "cidr":
            try:
                if ipaddress.ip_address(host) in ipaddress.ip_network(value, strict=True):
                    return True
            except ValueError:
                pass
    return False


def classify_scope(value: str) -> tuple[str, str]:
    value = normalize_target(value)
    try:
        if "/" in value:
            return "cidr", str(ipaddress.ip_network(value, strict=True))
        return "ip", str(ipaddress.ip_address(value))
    except ValueError:
        if not value or any(c.isspace() for c in value):
            raise ValueError("Invalid scope target")
        return "domain", value

