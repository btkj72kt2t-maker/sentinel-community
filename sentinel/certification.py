from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

from .catalog import CATEGORIES, capability_catalog
from .config import data_dir
from .db import now
from .tools import REGISTRY


VERSION_PROBES = {
    "dig": (["-v"], {0}),
    "whois": ([], {0, 64}),
    "subfinder": (["-version"], {0}),
    "httpx": (["-version"], {0}),
    "whatweb": (["--version"], {0}),
    "testssl.sh": (["--version"], {0}),
    "nmap": (["--version"], {0}),
    "nuclei": (["-version"], {0}),
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _binary_check(name: str, path_value: str | None, *, probe: bool) -> dict:
    if not path_value:
        return {"name": name, "status": "untested", "reason": "not installed"}
    path = Path(path_value).resolve()
    try:
        mode = path.stat().st_mode
        regular = path.is_file()
        executable = os.access(path, os.X_OK)
        world_writable = bool(mode & stat.S_IWOTH)
        result = {"name": name, "path": str(path), "sha256": _sha256(path) if regular else None, "regular_file": regular, "executable": executable, "world_writable": world_writable}
        if not regular or not executable or world_writable:
            result.update(status="failed", reason="unsafe or unusable executable permissions")
            return result
        if probe:
            arguments, allowed_codes = VERSION_PROBES[name]
            completed = subprocess.run([str(path), *arguments], capture_output=True, text=True, timeout=10, check=False)
            version_text = (completed.stdout or completed.stderr).strip().splitlines()
            result["probe"] = {"exit_code": completed.returncode, "output": (version_text[0] if version_text else "")[:300]}
            if completed.returncode not in allowed_codes or not version_text:
                result.update(status="failed", reason="safe version probe failed")
                return result
        result.update(status="passed", reason="identity and permissions verified" + ("; version probe succeeded" if probe else ""))
        return result
    except PermissionError as exc:
        return {"name": name, "path": str(path), "status": "untested", "reason": f"operating system blocked binary inspection: {exc}"[:500]}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"name": name, "path": str(path), "status": "failed", "reason": str(exc)[:500]}


def _adapter_check(name: str) -> dict:
    spec = REGISTRY[name]
    profiles = []
    for profile, builder in spec.profiles.items():
        target = "sentinel.invalid"
        try:
            argv = builder(target)
            valid = isinstance(argv, list) and all(isinstance(value, str) and value for value in argv) and argv[0] == name and target in argv
            profiles.append({"name": profile, "status": "passed" if valid else "failed", "argument_count": len(argv), "target_is_separate_argument": target in argv})
        except Exception as exc:
            profiles.append({"name": profile, "status": "failed", "reason": str(exc)[:500]})
    status = "passed" if profiles and all(p["status"] == "passed" for p in profiles) else "failed"
    return {"name": name, "active": spec.active, "status": status, "profiles": profiles}


def certify(*, probe_versions: bool = True, write: bool = False) -> dict:
    catalog = capability_catalog()
    category_names = [tool for tools in CATEGORIES.values() for tool in tools]
    installed = {}
    for values in catalog["categories"].values():
        for item in values:
            if item["installed"]:
                installed[item["name"]] = item["path"]
    for item in catalog["reference_inventory"]["tools"]:
        if item["installed"]:
            installed.setdefault(item["name"], item["path"])
    binaries = [_binary_check(name, path, probe=probe_versions and name in VERSION_PROBES) for name, path in sorted(installed.items())]
    adapters = [_adapter_check(name) for name in sorted(REGISTRY)]
    adapter_binaries = [_binary_check(name, shutil.which(name), probe=probe_versions) for name in sorted(REGISTRY)]
    report = {
        "generated_at": now(),
        "catalogue": {**catalog["summary"], "duplicate_curated_entries": len(category_names) - len(set(category_names))},
        "installed_binaries": binaries,
        "adapters": adapters,
        "adapter_binaries": adapter_binaries,
    }
    statuses = [item["status"] for item in binaries + adapters + adapter_binaries]
    report["summary"] = {
        "passed": statuses.count("passed"),
        "failed": statuses.count("failed"),
        "untested": statuses.count("untested"),
        "adapter_code_certified": all(item["status"] == "passed" for item in adapters),
        "installed_integrity_passed": all(item["status"] != "failed" for item in binaries),
        "environment_ready": all(item["status"] == "passed" for item in adapter_binaries),
    }
    report["assurance"] = "Passed means local identity/permission checks and safe probes succeeded. Missing tools remain untested; no report establishes perfection or vulnerability-detection completeness."
    if write:
        destination = data_dir() / "certification.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, indent=2), encoding="utf-8")
        report["report_path"] = str(destination)
    return report
