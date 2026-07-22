"""GrayHatWarfare API client — Free tier.

Endpoint: GET https://buckets.grayhatwarfare.com/api/v2/files
Auth: Authorization: Bearer <key>
Params: keywords, limit (max 1000/page), start (offset)

Free tier limitation (verified live against the real key): searches
~15% of the full index, no sort, no full-path search, and file listing
isn't enabled for all buckets -- confirmed via the API's own
`meta.notice` field on a live response:

  "As a free user you are searching in 2936 million from the 19298
   million files in the index. Premium users also have sorting
   enabled, full path search instead of only filename and file
   listing enabled for all buckets."

Response shape (verified live, NOT the same as the spec draft assumed --
`bucket` is a plain string, not a nested object):
  {
    "query": {...}, "meta": {"results": N, "notice": "..."},
    "files": [
      {"id": "...", "bucket": "host.s3-eu-west-1.amazonaws.com",
       "bucketId": 6, "filename": "path/to/file.pdf",
       "fullPath": "path/to/file.pdf",
       "url": "http://host.../path/to/file.pdf",
       "size": 2549108, "type": "aws", "lastModified": 1666666666}
    ]
  }
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from ati_evn.config import get_settings

logger = logging.getLogger("ati_evn.external.grayhat")

BASE_URL = "https://buckets.grayhatwarfare.com/api/v2"
PAGE_SIZE = 100  # observed practical page size; API allows up to 1000


class GrayhatConfigError(Exception):
    pass


class GrayhatAPIError(Exception):
    pass


def _extract_extension(filename: str) -> str | None:
    if "." not in filename:
        return None
    ext = filename.rsplit(".", 1)[-1].lower()
    if len(ext) > 20 or not ext.isalnum():
        return None
    return ext


def _normalize_file(raw: dict, keyword: str) -> dict:
    """Convert a GrayHatWarfare file entry into our normalized dict."""
    file_path = raw.get("fullPath") or raw.get("filename") or ""
    bucket_url = raw.get("bucket") or "unknown"
    filename = file_path.rstrip("/").rsplit("/", 1)[-1][:500] if file_path else ""

    last_modified = None
    if raw.get("lastModified"):
        try:
            last_modified = datetime.fromtimestamp(int(raw["lastModified"]), tz=timezone.utc)
        except (ValueError, TypeError, OSError):
            pass

    return {
        "bucket_url": str(bucket_url)[:500],
        "file_path": str(file_path)[:2000],
        "filename": filename,
        "file_extension": _extract_extension(filename),
        "file_size": raw.get("size"),
        "last_modified": last_modified,
        "keyword_matched": keyword,
        "full_url": raw.get("url") or "",  # debug only, not persisted/shown in alerts
        "raw": raw,
    }


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(min=1, max=10),
    retry=retry_if_exception_type(httpx.RequestError),
    reraise=True,
)
async def _search(keyword: str, limit: int, start: int) -> dict:
    settings = get_settings()
    if not settings.grayhatwarfare_api_key:
        raise GrayhatConfigError("GRAYHATWARFARE_API_KEY missing in .env")

    headers = {
        "Authorization": f"Bearer {settings.grayhatwarfare_api_key}",
        "Accept": "application/json",
    }
    params = {"keywords": keyword, "limit": limit, "start": start}

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(f"{BASE_URL}/files", params=params, headers=headers)

    if resp.status_code == 401:
        raise GrayhatConfigError(f"Auth failed (401). Check API key. {resp.text[:200]}")
    if resp.status_code >= 400:
        raise GrayhatAPIError(f"HTTP {resp.status_code}: {resp.text[:300]}")
    return resp.json()


async def search_keyword(keyword: str, max_files: int = 100) -> list[dict]:
    """Search files matching keyword. Paginated, capped at max_files."""
    all_files: list[dict] = []
    start = 0

    while len(all_files) < max_files:
        page_limit = min(PAGE_SIZE, max_files - len(all_files))
        raw = await _search(keyword, page_limit, start)
        files = raw.get("files") or []
        if not files:
            break
        for f in files:
            if len(all_files) >= max_files:
                break
            all_files.append(_normalize_file(f, keyword))

        meta = raw.get("meta") or {}
        total_available = meta.get("results", len(files))
        start += len(files)
        if start >= total_available:
            break

    logger.info("GrayHatWarfare search '%s': %d files (capped %d)", keyword, len(all_files), max_files)
    return all_files
