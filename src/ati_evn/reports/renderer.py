"""Render report HTML from Jinja2 template + convert to PDF."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ati_evn.config import get_settings

logger = logging.getLogger("ati_evn.reports.renderer")


def _get_template_env():
    template_dir = Path(__file__).parent / "templates"
    return Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )


def render_html(report_data: dict, narrative: str) -> str:
    env = _get_template_env()
    template = env.get_template("global_report.html.j2")
    return template.render(narrative=narrative, **report_data)


def _reports_dir() -> Path:
    settings = get_settings()
    d = Path(settings.reports_output_dir)
    d.mkdir(parents=True, exist_ok=True)
    return d


def _output_paths(prefix: str = "global_report") -> tuple[Path, Path]:
    """Return (html_path, pdf_path) with a timestamped day folder."""
    base = _reports_dir()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    day_dir = base / today
    day_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%H%M%S")
    html_path = day_dir / f"{prefix}_{ts}.html"
    pdf_path = day_dir / f"{prefix}_{ts}.pdf"
    return html_path, pdf_path


def _customer_prefix(short_code: str) -> str:
    safe_code = "".join(c if c.isalnum() or c == "_" else "_" for c in (short_code or "unknown"))
    return f"customer_{safe_code}"


def html_to_pdf(html_content: str, pdf_path: Path) -> bool:
    """Convert HTML to PDF via wkhtmltopdf. Returns True on success."""
    try:
        import pdfkit
    except ImportError:
        logger.error("pdfkit not installed. Install: pip install pdfkit")
        return False

    settings = get_settings()
    config = None
    if settings.wkhtmltopdf_path:
        config = pdfkit.configuration(wkhtmltopdf=settings.wkhtmltopdf_path)

    options = {
        "page-size": "A4",
        "encoding": "UTF-8",
        "enable-local-file-access": "",
        "quiet": "",
    }

    try:
        pdfkit.from_string(html_content, str(pdf_path), options=options, configuration=config)
        return True
    except OSError as e:
        logger.error(
            "wkhtmltopdf not found. Install wkhtmltopdf binary "
            "(apt install wkhtmltopdf on Linux, or wkhtmltopdf.org "
            "on Windows). Error: %s", e,
        )
        return False
    except Exception as e:
        logger.exception("PDF generation failed: %s", e)
        return False


async def generate_report_files(
    report_data: dict, narrative: str,
    formats: list[str] | None = None,
) -> dict:
    """Generate report files. Returns dict with paths + status.

    formats: subset of ["html", "pdf"] -- default ["html", "pdf"].
    """
    formats = formats or ["html", "pdf"]
    html_content = render_html(report_data, narrative)
    html_path, pdf_path = _output_paths()

    result = {
        "html_path": None, "pdf_path": None,
        "html_size_bytes": 0, "pdf_size_bytes": 0,
        "errors": [],
    }

    if "html" in formats:
        html_path.write_text(html_content, encoding="utf-8")
        result["html_path"] = str(html_path)
        result["html_size_bytes"] = html_path.stat().st_size

    if "pdf" in formats:
        if html_to_pdf(html_content, pdf_path):
            result["pdf_path"] = str(pdf_path)
            result["pdf_size_bytes"] = pdf_path.stat().st_size
        else:
            result["errors"].append("PDF generation failed — check wkhtmltopdf install")

    return result


def render_customer_html(report_data: dict, narrative: str) -> str:
    env = _get_template_env()
    template = env.get_template("customer_report.html.j2")
    return template.render(narrative=narrative, **report_data)


async def generate_customer_report_files(
    report_data: dict, narrative: str,
    short_code: str, formats: list[str] | None = None,
) -> dict:
    formats = formats or ["html", "pdf"]
    html_content = render_customer_html(report_data, narrative)
    html_path, pdf_path = _output_paths(_customer_prefix(short_code))

    result = {
        "html_path": None, "pdf_path": None,
        "html_size_bytes": 0, "pdf_size_bytes": 0,
        "errors": [],
    }

    if "html" in formats:
        html_path.write_text(html_content, encoding="utf-8")
        result["html_path"] = str(html_path)
        result["html_size_bytes"] = html_path.stat().st_size

    if "pdf" in formats:
        if html_to_pdf(html_content, pdf_path):
            result["pdf_path"] = str(pdf_path)
            result["pdf_size_bytes"] = pdf_path.stat().st_size
        else:
            result["errors"].append("PDF generation failed — check wkhtmltopdf install")

    return result
