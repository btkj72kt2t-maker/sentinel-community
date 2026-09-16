from __future__ import annotations

import shutil
from pathlib import Path

from .tools import REGISTRY

CATEGORIES = {
    "asset-discovery": ["amass", "subfinder", "assetfinder", "findomain", "dnsx", "puredns", "shuffledns", "massdns", "alterx", "tlsx", "asnmap", "mapcidr", "uncover"],
    "network": ["nmap", "naabu", "masscan", "rustscan", "zmap", "netexec", "enum4linux-ng", "snmpwalk", "onesixtyone", "ike-scan"],
    "http": ["httpx", "whatweb", "wafw00f", "testssl.sh", "sslyze", "curl", "mitmproxy", "zaproxy", "burpsuite"],
    "content-discovery": ["ffuf", "feroxbuster", "gobuster", "dirsearch", "katana", "gau", "waybackurls", "hakrawler", "gospider", "arjun", "paramspider", "kiterunner"],
    "vulnerability": ["nuclei", "nikto", "dalfox", "kxss", "commix", "sqlmap", "graphql-cop", "smuggler", "jwt-tool", "wpscan", "joomscan", "droopescan"],
    "code-and-secrets": ["semgrep", "codeql", "gitleaks", "trivy", "grype", "osv-scanner", "bandit", "gosec", "brakeman", "spotbugs", "bearer", "syft", "trufflehog", "detect-secrets"],
    "fuzzing": ["afl-fuzz", "libfuzzer", "honggfuzz", "jazzer", "radamsa", "wfuzz", "boofuzz", "atheris", "cargo-fuzz", "zzuf"],
    "cloud": ["prowler", "scoutsuite", "cloud_enum", "pacu", "cloudfox", "steampipe", "checkov", "terrascan", "tfsec"],
    "containers-kubernetes": ["kube-bench", "kubescape", "kubeaudit", "kube-hunter", "dockle", "hadolint", "clair", "falco"],
    "mobile": ["mobsfscan", "mobsf", "apktool", "jadx", "objection", "frida", "apkleaks", "qark"],
    "firmware-iot": ["binwalk", "firmwalker", "emba", "ghidra", "radare2", "cutter"],
    "wireless": ["aircrack-ng", "kismet", "hcxdumptool", "hcxtools", "wireshark", "tshark"],
    "forensics": ["exiftool", "yara", "volatility3", "sleuthkit", "foremost", "bulk_extractor"],
    "reporting-collaboration": ["dradis", "faraday", "defectdojo", "serpico", "eyewitness", "gowitness", "aquatone"],
}


def _kali_reference() -> list[str]:
    source = Path(__file__).with_name("data") / "kali_tools.txt"
    lines = source.read_text(encoding="utf-8").splitlines()
    marker = lines.index("---")
    return [line.strip() for line in lines[marker + 1:] if line.strip()]


def capability_catalog() -> dict:
    categories = {}
    for category, tools in CATEGORIES.items():
        categories[category] = [{"name": tool, "installed": bool(shutil.which(tool)), "path": shutil.which(tool), "maturity": "adapter-reviewed" if tool in REGISTRY else "catalogued"} for tool in tools]
    curated_names = {item["name"] for values in categories.values() for item in values}
    kali_names = _kali_reference()
    reference = [{"name": tool, "installed": bool(shutil.which(tool)), "path": shutil.which(tool), "maturity": "reference-only"} for tool in kali_names if tool not in curated_names]
    unique_names = curated_names | set(kali_names)
    installed_names = {name for name in unique_names if shutil.which(name)}
    return {
        "categories": categories,
        "reference_inventory": {"source": "https://www.kali.org/tools/all-tools/", "retrieved": "2026-09-16", "tools": reference},
        "summary": {"catalogued": len(unique_names), "curated": len(curated_names), "reference_only": len(reference), "adapter_reviewed": len(REGISTRY), "installed": len(installed_names), "missing": len(unique_names - installed_names)},
        "maturity": {"reference-only": "Known package; not reviewed for Sentinel use", "catalogued": "Curated capability; adapter not yet enabled", "adapter-reviewed": "Fixed command profile, policy gates, parser/testing required for executable use"},
        "note": "Catalogue presence never authorizes execution. Only reviewed adapters may run under engagement policy.",
    }
