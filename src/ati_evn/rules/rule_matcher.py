"""Find best-matching community Sigma rules for a CVE/Finding.

Scoring:
  + 100 if rule.status == 'stable'
  + 50  if rule.status == 'test'
  + 0   if rule.status == 'experimental' or missing
  - 20  if rule.status == 'deprecated'
  + 30  if rule.level == 'critical'
  + 20  if rule.level == 'high'
  + 10  if rule.level == 'medium'
  + 5 per ATT&CK technique overlap with finding.metadata_.attack_context
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import array
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.types import Text

from ati_evn.db.models import SigmaRule


@dataclass
class ScoredRule:
    rule: SigmaRule
    score: int
    reasoning: str


async def find_community_rules(
    session: AsyncSession, cve_id: str,
    finding_attack_techniques: list[str] | None = None,
) -> list[ScoredRule]:
    """Return community rules for a CVE, sorted by score desc."""
    cve_id_upper = cve_id.upper().strip()

    # Postgres JSONB contains query: cve_refs @> '["CVE-XXX"]'
    stmt = select(SigmaRule).where(
        SigmaRule.cve_refs.contains([cve_id_upper])
    )
    result = await session.execute(stmt)
    rows = list(result.scalars())

    finding_techs = set(finding_attack_techniques or [])
    scored: list[ScoredRule] = []
    for r in rows:
        score = 0
        reasons = []
        status = (r.status or "").lower()
        if status == "stable":
            score += 100
            reasons.append("stable")
        elif status == "test":
            score += 50
            reasons.append("test")
        elif status == "deprecated":
            score -= 20
            reasons.append("deprecated (avoid)")

        level = (r.level or "").lower()
        if level == "critical":
            score += 30
            reasons.append("critical")
        elif level == "high":
            score += 20
            reasons.append("high")
        elif level == "medium":
            score += 10
            reasons.append("medium")

        rule_techs = set(r.attack_techniques or [])
        overlap = rule_techs & finding_techs
        if overlap:
            score += 5 * len(overlap)
            reasons.append(f"ATT&CK overlap: {sorted(overlap)}")

        scored.append(ScoredRule(rule=r, score=score, reasoning=" | ".join(reasons)))

    scored.sort(key=lambda x: (-x.score, x.rule.title))
    return scored


async def find_behavior_rules(
    session: AsyncSession, finding_attack_techniques: list[str],
    *, limit: int = 20,
) -> list[ScoredRule]:
    """Find Sigma rules that match by ATT&CK technique overlap (used when
    direct CVE match returned nothing).

    Most SigmaHQ rules aren't CVE-tagged at all — only 63/3142 have a
    cve_refs entry, while 2796/3142 carry attack.tNNNN tags. This tier
    catches behavior-based coverage (e.g. a JNDI/LDAP lookup detection
    rule that's never mentioned "CVE-2021-44228" by name but targets the
    same T1190 exploitation technique) that find_community_rules misses
    entirely.

    Score reduced compared to CVE-direct match:
      - Base scoring same (status + level)
      - + 10 per ATT&CK overlap (was + 5 for CVE-direct)
      - + 20 bonus if ALL rule techniques are in finding techniques
        (means the rule is highly specific to this attack pattern)
      - Cap at 20 rules to avoid noise; caller filters top-1.
    """
    if not finding_attack_techniques:
        return []
    techs_upper = [t.upper() for t in finding_attack_techniques]

    # Postgres JSONB `?|` requires a real text[] on the right-hand side, not
    # a jsonb array — SQLAlchemy binds a plain Python list as jsonb by
    # default (matching the column type) and Postgres rejects `jsonb ?|
    # jsonb`. array(...).cast(...) forces the bind to text[] instead.
    techs_array = array(techs_upper, type_=Text)
    stmt = select(SigmaRule).where(
        SigmaRule.attack_techniques.op("?|")(techs_array)
    ).limit(200)  # oversample, score, cut
    result = await session.execute(stmt)
    rows = list(result.scalars())

    finding_set = set(techs_upper)
    scored: list[ScoredRule] = []
    for r in rows:
        score = 0
        reasons = ["behavior-based match"]
        status = (r.status or "").lower()
        if status == "stable":
            score += 100
            reasons.append("stable")
        elif status == "test":
            score += 50
            reasons.append("test")
        elif status == "deprecated":
            continue  # skip deprecated in fallback tier

        level = (r.level or "").lower()
        if level == "critical":
            score += 30
            reasons.append("critical")
        elif level == "high":
            score += 20
            reasons.append("high")
        elif level == "medium":
            score += 10
            reasons.append("medium")

        rule_techs = set(r.attack_techniques or [])
        overlap = rule_techs & finding_set
        if overlap:
            score += 10 * len(overlap)
            reasons.append(f"ATT&CK overlap: {sorted(overlap)}")
        # Specificity bonus: rule targets ONLY techniques in our finding
        if rule_techs and rule_techs.issubset(finding_set):
            score += 20
            reasons.append("rule specific to finding techniques")

        scored.append(ScoredRule(rule=r, score=score, reasoning=" | ".join(reasons)))

    scored.sort(key=lambda x: (-x.score, x.rule.title))
    return scored[:limit]
