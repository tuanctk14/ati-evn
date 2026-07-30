"""Fetch article content from URL / text / PDF.

Returns cleaned text ready for LLM extraction.
"""
from __future__ import annotations

import io
import logging
import re
from typing import BinaryIO

import httpx
import pypdf
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

logger = logging.getLogger("ati_evn.ingestion.fetcher")

FETCH_TIMEOUT = 30.0
MAX_CONTENT_CHARS = 20_000  # LLM input budget
UA = (
    "Mozilla/5.0 (compatible; ATI-EVN CTI ingest; "
    "+https://ti.evn.com.vn)"
)


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(min=1, max=8),
    retry=retry_if_exception_type(httpx.RequestError),
    reraise=True,
)
async def _get(url: str, headers: dict) -> httpx.Response:
    async with httpx.AsyncClient(
        timeout=FETCH_TIMEOUT, follow_redirects=True,
    ) as client:
        return await client.get(url, headers=headers)


async def fetch_url(url: str) -> str:
    """Fetch URL and return cleaned article text."""
    headers = {"User-Agent": UA, "Accept": "text/html,application/xhtml+xml"}
    resp = await _get(url, headers)
    resp.raise_for_status()
    html = resp.text

    # Try trafilatura first for clean extraction
    try:
        import trafilatura
        extracted = trafilatura.extract(
            html, include_comments=False, include_tables=True,
            favor_precision=True,
        )
        if extracted and len(extracted) > 200:
            return extracted[:MAX_CONTENT_CHARS]
    except ImportError:
        logger.warning("trafilatura not installed; falling back to raw text")
    except Exception as e:
        logger.warning("trafilatura extract failed: %s; falling back", e)

    # Fallback: strip HTML tags crudely
    text = re.sub(r"<script[^>]*>.*?</script>", " ", html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<style[^>]*>.*?</style>", " ", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:MAX_CONTENT_CHARS]


def extract_pdf_text(fp: BinaryIO) -> str:
    """Extract text from a PDF file-like object."""
    reader = pypdf.PdfReader(fp)
    pages = []
    for page in reader.pages:
        try:
            pages.append(page.extract_text() or "")
        except Exception as e:
            logger.warning("PDF page extract failed: %s", e)
    text = "\n".join(pages).strip()
    return text[:MAX_CONTENT_CHARS]


async def fetch_from_telegram_pdf(bot, file_id: str) -> tuple[str, str]:
    """Download PDF file from Telegram and extract text.
    Returns (text, filename)."""
    tg_file = await bot.get_file(file_id)
    buffer = io.BytesIO()
    await bot.download(tg_file, destination=buffer)
    buffer.seek(0)
    filename = tg_file.file_path.split("/")[-1] if tg_file.file_path else "attached.pdf"
    text = extract_pdf_text(buffer)
    return text, filename
