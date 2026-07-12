import os

import svgwrite

# Branding colors from bess1lie.github.io vibe (Dark/Purple/Blue)
PRIMARY_COLOR = "#6366f1"  # Indigo
SECONDARY_COLOR = "#a855f7"  # Purple
ACCENT_COLOR = "#38bdf8"  # Sky Blue
BG_DARK = "#0f172a"
BG_LIGHT = "#f8fafc"
TEXT_MAIN = "#f8fafc"
TEXT_DIM = "#94a3b8"
TERM_BG = "#0d1117"
TERM_HEADER = "#161b22"


def create_logo(output_path):
    dwg = svgwrite.Drawing(output_path, size=(100, 100), profile="tiny")
    grad = dwg.defs.add(dwg.linearGradient(id="logo_grad", x1="0%", y1="0%", x2="100%", y2="100%"))
    grad.add(dwg.stop(offset="0%", stop_color=PRIMARY_COLOR, stop_opacity="1"))
    grad.add(dwg.stop(offset="100%", stop_color=SECONDARY_COLOR, stop_opacity="1"))

    dwg.add(dwg.rect(insert=(0, 0), size=(100, 100), rx=22, fill="url(#logo_grad)"))
    # Shield icon
    dwg.add(
        dwg.path(
            d="M50 20 L75 30 L75 60 C75 75 50 85 50 85 C50 85 25 75 25 60 L25 30 Z",
            fill="white",
            opacity=0.9,
        )
    )
    # Tiny details
    dwg.add(dwg.circle(center=(50, 45), r=8, fill=BG_DARK, opacity=0.2))
    dwg.save()


def create_banner(output_path):
    dwg = svgwrite.Drawing(output_path, size=(1600, 500), profile="full")
    grad = dwg.defs.add(dwg.linearGradient(id="banner_grad", x1="0%", y1="0%", x2="100%", y2="100%"))
    grad.add(dwg.stop(offset="0%", stop_color="#0f172a", stop_opacity="1"))
    grad.add(dwg.stop(offset="100%", stop_color="#1e1b4b", stop_opacity="1"))

    dwg.add(dwg.rect(insert=(0, 0), size=(1600, 500), fill="url(#banner_grad)"))

    # Pattern
    dwg.add(dwg.rect(insert=(0, 0), size=(1600, 500), fill="#6366f1", opacity=0.05))

    # Text
    dwg.add(
        dwg.text(
            "apihunter",
            insert=(800, 240),
            font_size="140",
            font_family="sans-serif",
            font_weight="bold",
            fill="white",
            text_anchor="middle",
        )
    )
    dwg.add(
        dwg.text(
            "Automated REST API Security Reconnaissance",
            insert=(800, 310),
            font_size="40",
            font_family="sans-serif",
            fill="#94a3b8",
            text_anchor="middle",
        )
    )

    dwg.save()


def create_terminal_mockup(output_path, title, lines):
    width, height = 800, 450
    dwg = svgwrite.Drawing(output_path, size=(width, height))

    # Window
    dwg.add(dwg.rect(insert=(0, 0), size=(width, height), fill=TERM_BG))
    dwg.add(dwg.rect(insert=(0, 0), size=(width, 35), fill=TERM_HEADER))

    # Window buttons
    dwg.add(dwg.circle(center=(20, 17), r=6, fill="#ff5f56"))
    dwg.add(dwg.circle(center=(40, 17), r=6, fill="#ffbd2e"))
    dwg.add(dwg.circle(center=(60, 17), r=6, fill="#27c93f"))

    # Title
    dwg.add(
        dwg.text(
            title,
            insert=(width / 2, 23),
            font_size="14",
            font_family="monospace",
            fill="#94a3b8",
            text_anchor="middle",
        )
    )

    # Content
    y = 60
    for line in lines:
        color = "#f8fafc"
        if "apihunter" in line:
            color = "#60a5fa"
        elif "Discovered" in line or "complete" in line:
            color = "#34d399"
        elif "Error" in line or "Failed" in line:
            color = "#f87171"
        elif "scan" in line or "discover" in line:
            color = "#fbbf24"

        dwg.add(
            dwg.text(
                line.strip(),
                insert=(25, y),
                font_size="16",
                font_family="monospace",
                fill=color,
            )
        )
        y += 25
        if y > height - 20:
            break

    dwg.save()


def create_browser_mockup(output_path, title, rows):
    width, height = 800, 450
    dwg = svgwrite.Drawing(output_path, size=(width, height))

    # Browser Frame
    dwg.add(dwg.rect(insert=(0, 0), size=(width, height), fill="#f1f5f9"))
    dwg.add(dwg.rect(insert=(0, 0), size=(width, 60), fill="#e2e8f0"))
    dwg.add(dwg.rect(insert=(0, 0), size=(width, 60), fill="#ffffff", stroke="#cbd5e1"))

    # Address bar
    dwg.add(dwg.rect(insert=(100, 15), size=(600, 30), rx=15, fill="#f1f5f9"))
    dwg.add(
        dwg.text(
            "https://api.example.com/report",
            insert=(200, 35),
            font_size="14",
            font_family="sans-serif",
            fill="#64748b",
            text_anchor="middle",
        )
    )

    # Content area
    dwg.add(dwg.rect(insert=(20, 80), size=(760, 350), rx=10, fill="#ffffff", stroke="#e2e8f0"))

    # Content Header
    dwg.add(
        dwg.text(
            title,
            insert=(50, 120),
            font_size="28",
            font_family="sans-serif",
            font_weight="bold",
            fill="#0f172a",
        )
    )

    # Summary Cards
    dwg.add(dwg.rect(insert=(50, 150), size=(700, 80), rx=8, fill="#f8fafc", stroke="#e2e8f0"))
    dwg.add(
        dwg.text(
            "Critical: 0 | High: 1 | Medium: 2 | Low: 5",
            insert=(70, 195),
            font_size="20",
            font_family="sans-serif",
            fill="#475569",
        )
    )

    # Findings List
    for i in range(3):
        y_pos = 260 + (i * 50)
        dwg.add(dwg.rect(insert=(50, y_pos), size=(700, 40), rx=5, fill="#ffffff", stroke="#f1f5f9"))
        # Severity badge
        colors = ["#ef4444", "#f59e0b", "#3b82f6"]
        dwg.add(dwg.rect(insert=(65, y_pos + 10), size=(12, 20), rx=3, fill=colors[i % 3]))
        dwg.add(
            dwg.text(
                f"Finding #{i + 1}: Vulnerability at /endpoint/{i}",
                insert=(85, y_pos + 25),
                font_size="16",
                font_family="sans-serif",
                fill="#334155",
            )
        )

    dwg.save()


# Execution
os.makedirs("docs/screenshots", exist_ok=True)

create_logo("docs/logo.svg")
create_banner("docs/banner.svg")

# Terminal Mockups
create_terminal_mockup(
    "docs/screenshots/discover.svg",
    "apihunter discover",
    [
        "apihunter discover https://api.example.com",
        "---------------------------------------",
        "Scanning target: https://api.example.com",
        "Probing paths...",
        "Found /openapi.json (High Confidence)",
        "Found /swagger.json (Medium Confidence)",
        "Scan complete.",
    ],
)

create_terminal_mockup(
    "docs/screenshots/scan.svg",
    "apihunter scan",
    [
        "apihunter scan https://api.example.com",
        "---------------------------------------",
        "Scanning target: https://api.example.com",
        "Run ID: 123",
        "Analyzing /openapi.json...",
        "Analyzing /users...",
        "Analyzing /admin/config...",
        "Scan complete.",
    ],
)

# Browser Mockups
create_browser_mockup("docs/screenshots/report-html.svg", "Security Audit Report", [])
create_browser_mockup("docs/screenshots/report-md.svg", "Markdown Report Preview", [])
create_browser_mockup("docs/screenshots/report-sarif.svg", "SARIF JSON Preview", [])
