from __future__ import annotations

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
        lines.append(f"### {f.title}")
        lines.append(f"- **Severity**: {f.severity.capitalize()}")
        lines.append(f"- **Confidence**: {f.confidence.capitalize()}")
        lines.append(f"- **Check Type**: {f.check_type}")
        lines.append(f"- **Detail**: {f.detail}")
        lines.append(f"- **Remediation**: {f.remediation}")
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

    html = [
        "<html>",
        "<head><title>Security Findings Report</title></head>",
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
        html.append("<div>")
        html.append(f"<h3>{f.title}</h3>")
        html.append(f"<ul><li><strong>Severity</strong>: {f.severity.capitalize()}</li>")
        html.append(f"<li><strong>Confidence</strong>: {f.confidence.capitalize()}</li>")
        html.append(f"<li><strong>Check Type</strong>: {f.check_type}</li>")
        html.append(f"<li><strong>Detail</strong>: {f.detail}</li>")
        html.append(f"<li><strong>Remediation</strong>: {f.remediation}</li>")
        html.append("</ul>")
        html.append("</div>")

    html.append("</body></html>")
    return "\n".join(html)


def render_sarif(findings: list[Finding]) -> str:
    """
    Renders findings as a SARIF report.
    """
    return generate_sarif(findings)
