import json

from apihunter.core.models import Confidence, Finding, Severity
from apihunter.report.sarif import generate_sarif


def test_generate_sarif_empty():
    findings = []
    sarif_str = generate_sarif(findings)
    sarif = json.loads(sarif_str)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 0


def test_generate_sarif_with_findings():
    findings = [
        Finding(
            check_type="auth",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Test Finding",
            detail="Test detail",
            remediation="Test remediation",
        )
    ]
    sarif_str = generate_sarif(findings)
    sarif = json.loads(sarif_str)
    assert len(sarif["runs"][0]["results"]) == 1
    assert "AP-AUTH-0" in sarif["runs"][0]["results"][0]["ruleId"]
    assert "Test Finding" in sarif["runs"][0]["results"][0]["message"]["text"]
