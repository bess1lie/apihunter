from __future__ import annotations

import html as _html

from apihunter.core.models import Finding
from apihunter.report.sarif import generate_sarif


def render_markdown(findings: list[Finding]) -> str:
    """
    Renders findings as a Markdown report.
    """
    if not findings:
        return "# Security Findings Report\n\nNo findings discovered."

    lines = ["# Security Findings Report", ""]

    # Summary
    high = len([f for f in findings if f.severity == "high" or f.severity == "critical"])
    medium = len([f for f in findings if f.severity == "medium"])
    low = len([f for f in findings if f.severity == "low" or f.severity == "info"])

    lines.append("## Summary")
    lines.append(f"- **Critical/High**: {high}")
    lines.append(f"- **Medium**: {medium}")
    lines.append(f"- **Low/Info**: {low}")
    lines.append("")

    # Details
    lines.append("## Findings")
    for f in findings:
        lines.append(f"### {_html.escape(f.title)}")
        lines.append(f"- **Severity**: {_html.escape(f.severity.capitalize())}")
        lines.append(f"- **Confidence**: {_html.escape(f.confidence.capitalize())}")
        lines.append(f"- **Check Type**: {_html.escape(f.check_type)}")
        lines.append(f"- **Detail**: {_html.escape(f.detail)}")
        lines.append(f"- **Remediation**: {_html.escape(f.remediation)}")
        lines.append("")

    return "\n".join(lines)


def render_html(findings: list[Finding]) -> str:
    """
    Renders findings as a minimal HTML report.
    """
    if not findings:
        return "<html><body><h1>Security Findings Report</h1><p>No findings discovered.</p></body></html>"

    high = len([f for f in findings if f.severity == "high" or f.severity == "critical"])
    medium = len([f for f in findings if f.severity == "medium"])
    low = len([f for f in findings if f.severity == "low" or f.severity == "info"])

    parts = [
        "<html>",
        "<head><title>Security Findings Report</title>"  # noqa: E501
        '<meta charset="utf-8"><meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'none'; style-src 'unsafe-inline'\"></head>",
        "<body>",
        "<h1>Security Findings Report</h1>",
        "<h2>Summary</h2>",
        "<ul>",
        f"<li><strong>Critical/High</strong>: {high}</li>",
        f"<li><strong>Medium</strong>: {medium}</li>",
        f"<li><strong>Low/Info</strong>: {low}</li>",
        "</ul>",
        "<h2>Findings</h2>",
    ]

    for f in findings:
        parts.append("<div>")
        parts.append(f"<h3>{_html.escape(f.title)}</h3>")
        parts.append(f"<ul><li><strong>Severity</strong>: {_html.escape(f.severity.capitalize())}</li>")
        parts.append(f"<li><strong>Confidence</strong>: {_html.escape(f.confidence.capitalize())}</li>")
        parts.append(f"<li><strong>Check Type</strong>: {_html.escape(f.check_type)}</li>")
        parts.append(f"<li><strong>Detail</strong>: {_html.escape(f.detail)}</li>")
        parts.append(f"<li><strong>Remediation</strong>: {_html.escape(f.remediation)}</li>")
        parts.append("</ul>")
        parts.append("</div>")

    parts.append("</body></html>")
    return "\n".join(parts)


def render_sarif(findings: list[Finding]) -> str:
    """
    Renders findings as a SARIF report.
    """
    return generate_sarif(findings)
