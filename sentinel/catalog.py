from __future__ import annotations

import shutil

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


def capability_catalog() -> dict:
    categories = {}
    for category, tools in CATEGORIES.items():
        categories[category] = [{"name": tool, "installed": bool(shutil.which(tool)), "path": shutil.which(tool)} for tool in tools]
    total = sum(len(v) for v in categories.values())
    installed = sum(1 for values in categories.values() for item in values if item["installed"])
    return {"categories": categories, "summary": {"catalogued": total, "installed": installed, "missing": total - installed}, "note": "Curated capability index, not an execution allowlist. Presence does not authorize execution; only reviewed adapters may run under engagement policy."}
