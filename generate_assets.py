import svgwrite


def create_terminal_svg(output_path, title, text_lines, width=800, height=450):
    dwg = svgwrite.Drawing(output_path, size=(width, height))

    # Background
    dwg.add(dwg.rect(insert=(0, 0), size=(width, height), fill="#0f172a"))

    # Window Header
    header_h = 30
    dwg.add(dwg.rect(insert=(0, 0), size=(width, header_h), fill="#1e293b"))
    # Window buttons (red, yellow, green)
    dwg.add(dwg.circle(center=(20, 15), r=6, fill="#ef4444"))
    dwg.add(dwg.circle(center=(40, 15), r=6, fill="#f59e0b"))
    dwg.add(dwg.circle(center=(60, 15), r=6, fill="#10b981"))
    dwg.add(
        dwg.text(
            title,
            insert=(width / 2, 20),
            font_size="12",
            font_family="monospace",
            fill="#94a3b8",
            text_anchor="middle",
        )
    )

    # Text content
    y_offset = header_h + 20
    for line in text_lines:
        # Basic syntax highlighting (simple)
        color = "#f8fafc"
        if line.startswith("apihunter"):
            color = "#60a5fa"
        elif "Discovered" in line or "Scan complete" in line:
            color = "#34d399"
        elif "Error" in line or "Failed" in line:
            color = "#f87171"
        elif "blue" in line or "green" in line:
            color = "#fbbf24"

        dwg.add(
            dwg.text(
                line,
                insert=(20, y_offset),
                font_size="14",
                font_family="monospace",
                fill=color,
            )
        )
        y_offset += 20
        if y_offset > height - 20:
            break

    dwg.save()


def create_report_svg(output_path, title, file_type):
    dwg = svgwrite.Drawing(output_path, size=(800, 450))
    dwg.add(dwg.rect(insert=(0, 0), size=(800, 450), fill="#f8fafc"))
    dwg.add(
        dwg.rect(insert=(0, 0), size=(800, 450), fill="#ffffff", stroke="#e2e8f0", stroke_width=1)
    )

    # Header
    dwg.add(dwg.rect(insert=(0, 0), size=(800, 70), fill="#1e293b"))
    dwg.add(
        dwg.text(
            f"{title} - {file_type.upper()} Report",
            insert=(40, 45),
            font_size="24",
            font_family="sans-serif",
            fill="white",
        )
    )

    # Content Placeholder
    dwg.add(
        dwg.text(
            "Summary",
            insert=(40, 110),
            font_size="20",
            font_family="sans-serif",
            font_weight="bold",
            fill="#0f172a",
        )
    )
    dwg.add(dwg.rect(insert=(40, 130), size=(720, 100), rx=10, fill="#f1f5f9"))
    dwg.add(
        dwg.text(
            "Critical: 0 | High: 0 | Medium: 0 | Low: 0",
            insert=(60, 160),
            font_size="16",
            font_family="sans-serif",
            fill="#64748b",
        )
    )

    dwg.add(
        dwg.text(
            "Findings",
            insert=(40, 260),
            font_size="20",
            font_family="sans-serif",
            font_weight="bold",
            fill="#0f172a",
        )
    )
    for i in range(3):
        dwg.add(
            dwg.rect(
                insert=(40, 280 + i * 40), size=(720, 35), rx=5, fill="#ffffff", stroke="#e2e8f0"
            )
        )
        dwg.add(
            dwg.text(
                f"Finding #{i + 1}: Vulnerability detected at /endpoint/{i}",
                insert=(55, 303),
                font_size="14",
                font_family="sans-serif",
                fill="#334155",
            )
        )

    dwg.save()


# 1. Discover Screenshot
with open("discover_output.txt") as f:
    discover_lines = f.readlines()
create_terminal_svg("docs/screenshots/discover.svg", "apihunter discover", discover_lines)

# 2. Scan Screenshot
with open("scan_output.txt") as f:
    scan_lines = f.readlines()
create_terminal_svg("docs/screenshots/scan.svg", "apihunter scan", scan_lines)

# 3. HTML Report (simulated in SVG for better quality)
create_report_svg("docs/screenshots/report-html.svg", "Security Report", "html")
create_report_svg("docs/screenshots/report-md.svg", "Security Report", "markdown")
create_report_svg("docs/screenshots/report-sarif.svg", "Security Report", "sarif")
