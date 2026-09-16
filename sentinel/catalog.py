from __future__ import annotations

import shutil

CATEGORIES = {
    "asset-discovery": ["amass", "subfinder", "assetfinder", "findomain", "dnsx", "puredns"],
    "network": ["nmap", "naabu", "masscan", "rustscan"],
    "http": ["httpx", "whatweb", "wafw00f", "testssl.sh"],
    "content-discovery": ["ffuf", "feroxbuster", "gobuster", "dirsearch", "katana", "gau"],
    "vulnerability": ["nuclei", "nikto", "dalfox", "commix", "sqlmap"],
    "code-and-secrets": ["semgrep", "gitleaks", "trivy", "grype", "osv-scanner", "bandit", "gosec"],
    "fuzzing": ["afl-fuzz", "honggfuzz", "jazzer", "radamsa", "wfuzz"],
    "cloud": ["prowler", "scoutsuite", "cloud_enum", "trufflehog"],
    "mobile": ["mobsfscan", "apktool", "jadx"],
    "forensics": ["exiftool", "binwalk", "yara", "volatility3"],
}


def capability_catalog() -> dict:
    categories = {}
    for category, tools in CATEGORIES.items():
        categories[category] = [{"name": tool, "installed": bool(shutil.which(tool)), "path": shutil.which(tool)} for tool in tools]
    total = sum(len(v) for v in categories.values())
    installed = sum(1 for values in categories.values() for item in values if item["installed"])
    return {"categories": categories, "summary": {"catalogued": total, "installed": installed, "missing": total - installed}, "note": "Catalogue presence does not authorize execution; registered adapters and engagement policy still apply"}

