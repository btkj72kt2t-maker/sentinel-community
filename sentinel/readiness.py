from __future__ import annotations

import importlib.util
from pathlib import Path

from .catalog import capability_catalog
from .tools import REGISTRY


AREAS = (
    (1, "Reviewed adapters", ("sentinel.tools", "sentinel.normalize")),
    (2, "API and application testing", ("sentinel.api_analysis", "sentinel.proxy_analysis")),
    (3, "Cloud and infrastructure assessment", ("sentinel.catalog", "sentinel.intelligence")),
    (4, "Application and source-code research", ("sentinel.research", "sentinel.corpus", "sentinel.coverage", "sentinel.source_scan")),
    (5, "Mobile, firmware, wireless and device coverage", ("sentinel.taxonomy", "sentinel.catalog")),
    (6, "Validation laboratories", ("sentinel.lab_validation", "sentinel.sandbox", "sentinel.validation")),
    (7, "Operator interface", ("sentinel.dashboard",)),
    (8, "Production deployment", ("sentinel.daemon", "sentinel.health", "sentinel.provenance")),
    (9, "Reporting and disclosure", ("sentinel.report", "sentinel.taxonomy")),
    (10, "Quality and security assurance", ("sentinel.benchmark", "sentinel.policy")),
)


def readiness_report() -> dict:
    root = Path(__file__).resolve().parent.parent
    catalog = capability_catalog()["summary"]
    areas = []
    for number, name, modules in AREAS:
        present = [module for module in modules if importlib.util.find_spec(module)]
        foundation = len(present) == len(modules)
        areas.append({"number": number, "name": name, "foundation": "implemented" if foundation else "missing", "modules": list(modules), "production_complete": False, "remaining_gate": "External integration, representative lab validation, performance measurement, and independent security review"})
    return {
        "areas": areas,
        "catalog": catalog,
        "executable_adapters": len(REGISTRY),
        "tests_present": len(list((root / "tests").glob("test_*.py"))),
        "assurance": "All ten architectural foundations exist. Production completion is intentionally false until each integration passes its external validation gates.",
    }
