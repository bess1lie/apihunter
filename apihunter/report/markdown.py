from __future__ import annotations

from apihunter.core.models import Finding


def render_markdown(findings: list[Finding]) -> str:
    """
    Renders findings as a brief Markdown summary.
    """
    if not findings:
        return "No findings discovered."

    lines = ["## Security Findings Summary", ""]

    for f in findings:
        lines.append(f"- **[{f.severity.upper()}]** {f.title} ({f.check_type}): {f.detail}")

    return "\n".join(lines)
