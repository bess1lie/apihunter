from __future__ import annotations

import json

from apihunter.core.models import Finding


def generate_sarif(findings: list[Finding]) -> str:
    """
    Generates a minimal SARIF 2.1.0 compliant report.
    """
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "apihunter", "version": "0.1.0", "rules": []}}, "results": []}],
    }

    for i, f in enumerate(findings):
        sarif["runs"][0]["results"].append(
            {
                "ruleId": f"AP-{f.check_type.upper()}-{i}",
                "message": {"text": f"{f.title}: {f.detail}"},
                "level": "error" if f.severity in ("high", "critical") else "warning",
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "api-scan"}}}],
            }
        )

    return json.dumps(sarif, indent=2)
