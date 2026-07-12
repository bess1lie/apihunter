from apihunter.core.models import Confidence, Finding, Severity
from apihunter.report.markdown import render_markdown


def test_render_markdown_empty():
    assert render_markdown([]) == "No findings discovered."


def test_render_markdown_with_findings():
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
    assert "## Security Findings Summary" in md
    assert "- **[HIGH]** Test Finding (auth): Test detail" in md
