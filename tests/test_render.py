from __future__ import annotations

import pytest

from apihunter.core.models import Confidence, Finding, Severity
from apihunter.report.render import render_html, render_markdown


@pytest.mark.anyio
def test_render_markdown():
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
    md = render_markdown(findings)
    assert "# Security Findings Report" in md
    assert "### Test Finding" in md
    assert "High" in md
    assert "Test detail" in md
    assert "Test remediation" in md


@pytest.mark.anyio
def test_render_html():
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
    html = render_html(findings)
    assert "<h1>Security Findings Report</h1>" in html
    assert "Test Finding" in html
    assert "High" in html


def test_render_markdown_confidence_evidence():
    findings = [
        Finding(
            check_type="cors",
            severity=Severity.INFO,
            confidence=Confidence.MEDIUM,
            title="CORS wildcard origin (info)",
            detail="x\nEvidence: ACAO='*' ACAC=''",
            remediation="r",
            endpoint_path="/api",
            endpoint_method="GET",
        )
    ]
    md = render_markdown(findings)
    assert "Medium" in md
    assert "Evidence:" in md
    assert "CORS wildcard" in md


def test_render_html_evidence_escaped():
    findings = [
        Finding(
            check_type="injection",
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            title="Potential SQL error in response (heuristic)",
            detail="x\nEvidence: baseline_status=200 probe_status=500",
            remediation="r",
        )
    ]
    html = render_html(findings)
    assert "Evidence:" in html
    assert "Potential SQL error" in html
