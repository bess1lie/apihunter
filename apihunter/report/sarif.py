from __future__ import annotations

import json

from apihunter.core.models import Finding


def generate_sarif(findings: list[Finding]) -> str:
    """
    Generates SARIF 2.1.0 with real locations.
    Includes driver rules, severity mapping, and per-finding artifactLocation
    (endpoint path or fallback).
    """
    try:
        from apihunter import __version__
    except Exception:
        __version__ = "1.1.0"

    # Build unique rules
    rule_ids: dict[str, dict] = {}
    for f in findings:
        rid = f"AP-{f.check_type.upper()}"
        if rid not in rule_ids:
            rule_ids[rid] = {
                "id": rid,
                "name": f.check_type,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.remediation or f.detail or ""},
                "help": {"text": f.remediation or ""},
            }

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "apihunter",
                        "version": __version__,
                        "informationUri": "https://github.com/bess1lie/apihunter",
                        "rules": list(rule_ids.values()),
                    }
                },
                "results": [],
            }
        ],
    }

    level_map = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }

    for f in findings:
        # Use endpoint_path if available, else generic
        uri = f.endpoint_path or f"api-scan://{f.check_type}"
        # Include method in message for clarity
        msg = f"{f.title}: {f.detail}" if f.detail else f.title
        if getattr(f, "endpoint_method", None):
            msg = f"[{f.endpoint_method} {f.endpoint_path}] {msg}"
        # Extract Evidence block from detail for SARIF properties
        evidence = None
        if f.detail and "Evidence:" in f.detail:
            evidence = f.detail.split("Evidence:", 1)[1].strip()[:2000]
        props: dict[str, str] = {
            "severity": str(f.severity),
            "confidence": str(f.confidence),
            "check_type": f.check_type,
        }
        if evidence:
            props["evidence"] = evidence
        sarif["runs"][0]["results"].append(
            {
                "ruleId": f"AP-{f.check_type.upper()}",
                "message": {"text": msg},
                "level": level_map.get(str(f.severity).lower(), "warning"),
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
                "properties": props,
            }
        )

    return json.dumps(sarif, indent=2)
