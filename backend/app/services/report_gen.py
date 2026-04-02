"""
PDF Report Generation — Jinja2 HTML templates → WeasyPrint → PDF.
"""

from __future__ import annotations
import asyncio
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
import weasyprint

TEMPLATES_DIR = Path(__file__).parent.parent.parent.parent / "reports" / "templates"

jinja_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=True,
)


async def generate_report(scan, client, findings, report_type: str = "executive") -> bytes:
    """Generate a PDF report. Returns raw PDF bytes."""
    template_name = f"{report_type}.html"
    template = jinja_env.get_template(template_name)

    # Group findings by category and severity for the report
    from collections import defaultdict
    by_category: dict[str, list] = defaultdict(list)
    for f in findings:
        by_category[f.category].append(f)

    critical_findings = [f for f in findings if f.severity.value == "critical"]
    high_findings = [f for f in findings if f.severity.value == "high"]

    context = {
        "scan": scan,
        "client": client,
        "findings": findings,
        "findings_by_category": dict(by_category),
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "score": scan.overall_score,
        "risk_level": scan.risk_level,
        "risk_color": _risk_color(scan.risk_level),
        "score_color": _score_color(scan.overall_score),
        "total_findings": len(findings),
        "report_type": report_type,
    }

    html_content = template.render(**context)

    # WeasyPrint is CPU-bound; run in thread pool to avoid blocking async loop
    loop = asyncio.get_event_loop()
    pdf_bytes = await loop.run_in_executor(
        None,
        lambda: weasyprint.HTML(string=html_content, base_url=str(TEMPLATES_DIR)).write_pdf()
    )
    return pdf_bytes


def _risk_color(risk_level: str) -> str:
    colors = {
        "MINIMAL": "#16a34a",
        "LOW": "#65a30d",
        "MODERATE": "#ca8a04",
        "ELEVATED": "#ea580c",
        "HIGH": "#dc2626",
    }
    return colors.get(risk_level, "#6b7280")


def _score_color(score: float) -> str:
    if score >= 90:
        return "#16a34a"
    elif score >= 80:
        return "#65a30d"
    elif score >= 65:
        return "#ca8a04"
    elif score >= 50:
        return "#ea580c"
    else:
        return "#dc2626"
