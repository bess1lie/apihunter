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
