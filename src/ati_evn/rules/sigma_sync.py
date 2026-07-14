"""Clone/pull SigmaHQ/sigma, parse rules/**/*.yml, upsert into sigma_rules.

Idempotent by (rule_uuid, sha256). Runs in ~30-60s for full sync (~3000
rules). `--update` (see scripts/sync_sigma.py) does a git pull + reindex —
the sha256-gated ON CONFLICT means unchanged rules are skipped, not
rewritten, so a re-sync after a small upstream diff is fast.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import re
from pathlib import Path

import yaml
from git import GitCommandError, Repo
from sqlalchemy.dialects.postgresql import insert as pg_insert

from ati_evn.db.models import SigmaRule
from ati_evn.db.session import async_session

logger = logging.getLogger("ati_evn.rules.sigma_sync")

SIGMA_REPO_URL = "https://github.com/SigmaHQ/sigma.git"
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
UPSERT_BATCH_SIZE = 500


def _clone_or_pull_sync(repo_dir: Path) -> Repo:
    """Shallow clone (--depth 1) if missing, else git pull. Blocking — call
    via asyncio.to_thread, GitPython has no native async API."""
    if repo_dir.exists() and (repo_dir / ".git").exists():
        repo = Repo(repo_dir)
        try:
            repo.remotes.origin.pull()
        except GitCommandError as e:
            logger.warning("git pull failed (%s) — continuing with existing checkout", e)
        return repo

    repo_dir.parent.mkdir(parents=True, exist_ok=True)
    repo = Repo.clone_from(SIGMA_REPO_URL, repo_dir, depth=1)
    return repo


async def clone_or_pull(repo_dir: Path) -> Repo:
    return await asyncio.to_thread(_clone_or_pull_sync, repo_dir)


def _parse_rule(yaml_text: str) -> dict | None:
    """Parse Sigma YAML. Return None on invalid or unrelated file (e.g.
    multi-document files, test-only rules)."""
    try:
        docs = list(yaml.safe_load_all(yaml_text))
    except yaml.YAMLError:
        return None
    # Sigma rules typically one-doc; some correlation rules multi-doc.
    # For MVP, take first doc that has a title + id.
    for d in docs:
        if isinstance(d, dict) and d.get("id") and d.get("title"):
            return d
    return None


def _extract_cve_refs(rule: dict) -> list[str]:
    """CVE references appear in `references:`, or embedded in `description:`
    and `tags:`. Grep all with regex."""
    blob = " ".join([
        rule.get("description") or "",
        " ".join(rule.get("references") or []),
        " ".join(rule.get("tags") or []),
    ])
    return sorted({m.upper() for m in CVE_PATTERN.findall(blob)})


def _extract_attack_tags(rule: dict) -> list[str]:
    """ATT&CK tags in Sigma look like 'attack.t1190' or 'attack.t1059.001'."""
    tags = rule.get("tags") or []
    techniques = []
    for tag in tags:
        m = re.match(r"attack\.(t\d{4}(?:\.\d{3})?)", str(tag).lower())
        if m:
            techniques.append(m.group(1).upper())
    return sorted(set(techniques))


def _extract_logsource(rule: dict) -> tuple[str | None, str | None, str | None]:
    ls = rule.get("logsource") or {}
    return (ls.get("product"), ls.get("service"), ls.get("category"))


def _rule_to_row(yaml_text: str, source_path: str, rule: dict) -> dict:
    product, service, category = _extract_logsource(rule)
    return {
        "rule_uuid": str(rule["id"]).strip(),
        "title": (rule.get("title") or "")[:500],
        "description": rule.get("description"),
        "level": (str(rule.get("level") or "")).lower() or None,
        "status": (str(rule.get("status") or "")).lower() or None,
        "author": str(rule.get("author") or "")[:500] or None,
        "cve_refs": _extract_cve_refs(rule),
        "attack_techniques": _extract_attack_tags(rule),
        "product": product,
        "service": service,
        "category": category,
        "raw_yaml": yaml_text,
        "source_path": source_path,
        "sha256": hashlib.sha256(yaml_text.encode("utf-8")).hexdigest(),
    }


async def sync_sigma_rules(repo_dir: Path) -> dict:
    """Main entry. Return stats dict."""
    logger.info("Cloning/pulling SigmaHQ repo to %s", repo_dir)
    await clone_or_pull(repo_dir)

    rules_root = repo_dir / "rules"
    if not rules_root.exists():
        raise RuntimeError(f"Sigma rules root not found: {rules_root}")

    stats = {"scanned": 0, "parsed": 0, "upserted": 0, "unchanged": 0, "skipped": 0}
    rows_to_upsert: list[dict] = []

    for yml in rules_root.rglob("*.yml"):
        stats["scanned"] += 1
        text = yml.read_text(encoding="utf-8", errors="replace")
        rule = _parse_rule(text)
        if not rule:
            stats["skipped"] += 1
            continue
        row = _rule_to_row(text, yml.relative_to(repo_dir).as_posix(), rule)
        rows_to_upsert.append(row)
        stats["parsed"] += 1

    logger.info("Parsed %d/%d rule files; upserting in batches of %d",
                stats["parsed"], stats["scanned"], UPSERT_BATCH_SIZE)

    async with async_session() as session:
        for i in range(0, len(rows_to_upsert), UPSERT_BATCH_SIZE):
            chunk = rows_to_upsert[i:i + UPSERT_BATCH_SIZE]
            stmt = pg_insert(SigmaRule).values(chunk)
            stmt = stmt.on_conflict_do_update(
                index_elements=["rule_uuid"],
                set_={
                    "title": stmt.excluded.title,
                    "description": stmt.excluded.description,
                    "level": stmt.excluded.level,
                    "status": stmt.excluded.status,
                    "author": stmt.excluded.author,
                    "cve_refs": stmt.excluded.cve_refs,
                    "attack_techniques": stmt.excluded.attack_techniques,
                    "product": stmt.excluded.product,
                    "service": stmt.excluded.service,
                    "category": stmt.excluded.category,
                    "raw_yaml": stmt.excluded.raw_yaml,
                    "source_path": stmt.excluded.source_path,
                    "sha256": stmt.excluded.sha256,
                    "indexed_at": stmt.excluded.indexed_at,
                },
                where=(SigmaRule.sha256 != stmt.excluded.sha256),
            )
            result = await session.execute(stmt)
            stats["upserted"] += result.rowcount or 0
            logger.info("Upsert batch %d-%d: %d changed", i, i + len(chunk), result.rowcount or 0)
        await session.commit()

    stats["unchanged"] = stats["parsed"] - stats["upserted"]
    return stats
