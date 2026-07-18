"""Test extraction pipeline standalone (no Telegram).

Usage:
  python scripts/test_ingest.py --url https://example.com/article
  python scripts/test_ingest.py --file /path/to/report.pdf
  python scripts/test_ingest.py --text "paste text here"
"""
import argparse
import asyncio
import json
import sys


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url")
    ap.add_argument("--file")
    ap.add_argument("--text")
    args = ap.parse_args()

    from ati_evn.ingestion.extractor import extract_from_text
    from ati_evn.ingestion.fetcher import extract_pdf_text, fetch_url

    if args.url:
        content = await fetch_url(args.url)
    elif args.file:
        with open(args.file, "rb") as f:
            content = extract_pdf_text(f)
    elif args.text:
        content = args.text
    else:
        ap.error("Need --url, --file, or --text")
        return 2

    print(f"=== Content ({len(content)} chars) ===\n")
    print(content[:1500])
    print("\n=== Extraction ===")
    extracted, model = await extract_from_text(content)
    print(f"Model: {model}")
    print(json.dumps(extracted, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
