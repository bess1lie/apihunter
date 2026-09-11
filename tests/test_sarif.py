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
    assert sarif["runs"][0]["results"][0]["ruleId"] == "AP-AUTH"
    assert "Test Finding" in sarif["runs"][0]["results"][0]["message"]["text"]
    # Check real location, not api-scan
    assert sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_sarif_evidence_propagation():
    findings = [
        Finding(
            check_type="cors",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="CORS wildcard with credentials",
            detail="Endpoint /api sends ACAO: * and ACAC: true.\nEvidence: ACAO='*' ACAC='true' Vary=''",
            remediation="fix",
            endpoint_path="/api",
            endpoint_method="GET",
        )
    ]
    sarif = json.loads(generate_sarif(findings))
    props = sarif["runs"][0]["results"][0]["properties"]
    assert props["severity"] == "high"
    assert props["confidence"] == "high"
    assert "evidence" in props
    assert "ACAO" in props["evidence"]


def test_sarif_confidence_rendered():
    findings = [
        Finding(
            check_type="idor",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            title="Potential BOLA/IDOR (heuristic)",
            detail="x\nEvidence: status1=200",
        )
    ]
    sarif = json.loads(generate_sarif(findings))
    assert sarif["runs"][0]["results"][0]["properties"]["confidence"] == "low"
