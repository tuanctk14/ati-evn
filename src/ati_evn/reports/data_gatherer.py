"""Gather all data for a report window in one pass.

Reference: ArgusWatch _gather_report_data pattern -- single upfront
query per section, then the template renders.

Schema notes that diverge from a naive read of other CTI codebases:
  - Finding has NO deleted_at column (no soft-delete on this model).
  - Finding.sources is a plain JSON column (list), not a Postgres
    array -- `func.unnest()` doesn't apply. Source breakdown is
    computed by loading in-window findings and counting in Python.
  - Finding.ioc_type for CVEs is the literal string "cve_id", not "cve".
  - Campaign has no `name`/`detected_at`/`top_techniques` columns --
    the real columns are `window_start` (detection window) and
    `technique_ids`.
  - Exposure/BrandAbuseSighting/ExposedDocument use `first_seen_local`
    (not `first_seen`); BrandAbuseSighting's domain column is `domain`
    (not `page_domain`), and its verdict fields are `verdict_malicious`
    / `engines_malicious_total` (not `verdict_overall_malicious` /
    `verdict_engines_malicious_count`), with `scan_uuid` (not `scan_id`).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import desc, func, select

from ati_evn.db.models import (
    BrandAbuseSighting,
    Campaign,
    CveEnrichmentCache,
    CveProductMap,
    Customer,
    CustomerAsset,
    ExposedDocument,
    Exposure,
    Finding,
    IpAggregatedScore,
    Severity,
)
from ati_evn.db.query_utils import only_live_customer
from ati_evn.db.query_utils_test import is_test_finding
from ati_evn.db.session import async_session
from ati_evn.enrichment_v2.epss_client import enrich_epss
from ati_evn.enrichment_v2.kev_client import refresh_kev_catalog
from ati_evn.reports.asset_risk import compute_asset_risk_ranking

logger = logging.getLogger("ati_evn.reports.data_gatherer")


async def _enrich_cve_findings(cve_findings: list[dict]) -> dict:
    """Attach KEV + EPSS enrichment to a list of CVE finding dicts
    in-place, sort by priority (KEV first, then EPSS desc, then
    severity), and return a summary dict for the report header.
    """
    await refresh_kev_catalog()

    cve_ids = list({c["cve"] for c in cve_findings if c.get("cve")})
    await enrich_epss(cve_ids)

    enrichments: dict[str, dict] = {}
    if cve_ids:
        async with async_session() as session:
            stmt = select(CveEnrichmentCache).where(CveEnrichmentCache.cve_id.in_(cve_ids))
            for row in (await session.execute(stmt)).scalars():
                enrichments[row.cve_id] = {
                    "is_kev": row.is_kev,
                    "kev_vendor": row.kev_vendor,
                    "kev_product": row.kev_product,
                    "kev_short_description": row.kev_short_description,
                    "kev_required_action": row.kev_required_action,
                    "kev_due_date": row.kev_due_date,
                    "epss_score": row.epss_score,
                    "epss_percentile": row.epss_percentile,
                }

    # Vendor/product for the CVE detail block + remediation LLM context --
    # kev_vendor/kev_product above are only populated for CVEs in the CISA
    # KEV catalog (a small minority), so most CVEs need this fallback from
    # cve_product_map (populated by NVD/KEV/Vulners fetchers) or they'd
    # otherwise show as "Unknown/Unknown" in the LLM remediation output.
    product_map: dict[str, tuple[str | None, str | None]] = {}
    if cve_ids:
        async with async_session() as session:
            cve_ids_upper = [c.upper() for c in cve_ids]
            stmt = select(CveProductMap.cve_id, CveProductMap.vendor, CveProductMap.product).where(
                CveProductMap.cve_id.in_(cve_ids_upper),
            ).order_by(CveProductMap.confidence.desc())
            for cve_id, vendor, product in await session.execute(stmt):
                if cve_id not in product_map:
                    product_map[cve_id] = (vendor, product)

    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    for c in cve_findings:
        enrich = enrichments.get(c["cve"], {})
        c["is_kev"] = enrich.get("is_kev", False)
        c["epss_score"] = enrich.get("epss_score")
        c["epss_percentile"] = enrich.get("epss_percentile")
        c["kev_vendor"] = enrich.get("kev_vendor")
        c["kev_product"] = enrich.get("kev_product")
        c["kev_required_action"] = enrich.get("kev_required_action")
        c["nvd_url"] = f"https://nvd.nist.gov/vuln/detail/{c['cve']}"

        vendor, product = product_map.get(c["cve"], (None, None))
        c["vendor"] = c["kev_vendor"] or vendor
        c["product"] = c["kev_product"] or product

    cve_findings.sort(key=lambda c: (
        not c.get("is_kev", False),
        -(c.get("epss_score") or 0),
        severity_rank.get(c.get("severity"), 9),
    ))

    return {
        "total_cves": len(cve_ids),
        "kev_count": sum(1 for c in cve_findings if c.get("is_kev")),
        "high_epss_count": sum(1 for c in cve_findings if (c.get("epss_score") or 0) >= 0.7),
    }


async def gather_global_report(from_dt: datetime, to_dt: datetime) -> dict:
    """Gather all data for global report window [from_dt, to_dt).

    Returns dict with 8 section data (+ N/A section 9) ready for template.
    """
    window_days = (to_dt - from_dt).days or 1

    async with async_session() as session:
        # ── Section 0: Executive header (customer count) ──
        cust_count_r = await session.execute(
            select(func.count(Customer.id)).where(only_live_customer())
        )
        customer_count = cust_count_r.scalar() or 0

        # ── Section 1: Findings breakdown ──
        # Load then filter in Python: excludes test-scenario findings
        # (created via /add_test_campaign, flagged metadata.test_scenario)
        # so ad-hoc test runs never contaminate a real report's numbers.
        in_window_findings_r = await session.execute(
            select(Finding).where(
                Finding.first_seen >= from_dt,
                Finding.first_seen < to_dt,
            )
        )
        in_window_findings = [
            f for f in in_window_findings_r.scalars()
            if not is_test_finding(f)
        ]

        findings_by_severity = {sev.value: 0 for sev in Severity}
        source_counts: dict[str, int] = {}
        customer_ids_in_window = set()
        for f in in_window_findings:
            sev_key = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            findings_by_severity[sev_key] = findings_by_severity.get(sev_key, 0) + 1
            for s in (f.sources or []):
                source_counts[s] = source_counts.get(s, 0) + 1
            customer_ids_in_window.add(f.customer_id)

        total_findings = len(in_window_findings)

        findings_by_source = [
            {"source": s, "count": c}
            for s, c in sorted(source_counts.items(), key=lambda kv: kv[1], reverse=True)
        ][:15]

        # By customer (top 10 affected) -- resolve names in one batch query
        customer_rows = {}
        if customer_ids_in_window:
            cust_r = await session.execute(
                select(Customer).where(Customer.id.in_(customer_ids_in_window))
            )
            customer_rows = {c.id: c for c in cust_r.scalars()}

        cust_finding_counts: dict[int, int] = {}
        for f in in_window_findings:
            cust_finding_counts[f.customer_id] = cust_finding_counts.get(f.customer_id, 0) + 1

        findings_by_customer = [
            {
                "name": customer_rows[cid].name if cid in customer_rows else "(unknown)",
                "short_code": customer_rows[cid].short_code if cid in customer_rows else None,
                "count": cnt,
            }
            for cid, cnt in sorted(cust_finding_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]
        ]

        # Top critical findings (for detail listing) -- reuse the
        # already-filtered in_window_findings instead of a fresh query,
        # so test_scenario findings stay excluded here too.
        top_critical_all = [
            f for f in in_window_findings
            if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)) in ("CRITICAL", "HIGH")
        ]
        top_critical_all.sort(key=lambda f: f.first_seen or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
        top_critical = []
        for f in top_critical_all[:20]:
            cust = customer_rows.get(f.customer_id) or await session.get(Customer, f.customer_id)
            top_critical.append({
                "id": f.id,
                "title": f.title[:120],
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "ioc_type": f.ioc_type,
                "ioc_value": (f.ioc_value or "")[:80],
                "customer": cust.name if cust else "(orphan)",
                "sources": f.sources or [],
                "first_seen": f.first_seen.isoformat() if f.first_seen else None,
            })

        # ── Section 2: Vulnerabilities (CVE-typed Findings) ──
        cve_findings_r = await session.execute(
            select(Finding).where(
                Finding.ioc_type == "cve_id",
                Finding.first_seen >= from_dt,
                Finding.first_seen < to_dt,
            ).order_by(Finding.severity, Finding.first_seen.desc()).limit(30)
        )
        cve_all = [
            f for f in cve_findings_r.scalars()
            if not is_test_finding(f)
        ]
        cve_count = len(cve_all)

        cve_findings = []
        for f in cve_all:
            cust = customer_rows.get(f.customer_id) or await session.get(Customer, f.customer_id)
            cve_findings.append({
                "id": f.id,
                "cve": (f.ioc_value or "").upper(),
                "title": f.title[:100],
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "customer": cust.name if cust else "-",
                "asset": (f.matched_asset or "")[:80],
            })

        # ── Section 3: Campaigns ──
        campaigns_r = await session.execute(
            select(Campaign).where(
                Campaign.window_start >= from_dt,
                Campaign.window_start < to_dt,
            ).order_by(Campaign.confidence.desc())
        )
        campaigns = []
        for c in campaigns_r.scalars():
            campaigns.append({
                "id": c.id,
                "name": f"Campaign #{c.id}",
                "status": c.status if isinstance(c.status, str) else c.status.value,
                "confidence": round(float(c.confidence or 0), 2),
                "detected_at": c.window_start.isoformat() if c.window_start else None,
                "finding_count": c.finding_count or 0,
                "top_techniques": (c.technique_ids or [])[:5],
            })

        # ── Section 4: Exposed Services (Censys) ──
        exposures_r = await session.execute(
            select(Exposure).where(
                Exposure.first_seen_local >= from_dt,
                Exposure.first_seen_local < to_dt,
                Exposure.status == "active",
            ).order_by(Exposure.first_seen_local.desc()).limit(20)
        )
        exposures = []
        for e in exposures_r.scalars():
            cust = None
            if e.customer_id:
                cust = customer_rows.get(e.customer_id) or await session.get(Customer, e.customer_id)
            exposures.append({
                "id": e.id,
                "ip": e.ip,
                "port": e.port,
                "service": e.service_name,
                "customer": cust.name if cust else "(unattributed)",
                "first_seen": e.first_seen_local.isoformat() if e.first_seen_local else None,
            })

        exposures_total = (await session.execute(
            select(func.count(Exposure.id)).where(Exposure.status == "active")
        )).scalar() or 0

        # ── Section 4b: Service aggregate (group active exposures by service) ──
        svc_stmt = select(
            Exposure.service_name,
            func.count(Exposure.id).label("cnt"),
            func.count(func.distinct(Exposure.customer_id)).label("cust_cnt"),
        ).where(
            Exposure.status == "active",
        ).group_by(Exposure.service_name).order_by(desc("cnt")).limit(10)
        service_aggregate = [
            {"service": r.service_name or "unknown", "count": r.cnt, "customer_count": r.cust_cnt}
            for r in await session.execute(svc_stmt)
        ]

        # ── Section 5: Document Leaks (GrayHatWarfare) ──
        doc_leaks_r = await session.execute(
            select(ExposedDocument).where(
                ExposedDocument.first_seen_local >= from_dt,
                ExposedDocument.first_seen_local < to_dt,
                ExposedDocument.status == "active",
            ).order_by(ExposedDocument.first_seen_local.desc()).limit(20)
        )
        doc_leaks = []
        for d in doc_leaks_r.scalars():
            cust = None
            if d.customer_id:
                cust = customer_rows.get(d.customer_id) or await session.get(Customer, d.customer_id)
            doc_leaks.append({
                "id": d.id,
                "filename": d.filename[:100],
                "bucket_url": (d.bucket_url or "")[:120],
                "customer": cust.name if cust else "-",
                "keyword": d.keyword_matched,
                "rule_matched": d.rule_matched,
                "first_seen": d.first_seen_local.isoformat() if d.first_seen_local else None,
            })

        doc_leaks_total = (await session.execute(
            select(func.count(ExposedDocument.id)).where(ExposedDocument.status == "active")
        )).scalar() or 0

        # ── Section 6: Brand Abuse (urlscan) ──
        brand_r = await session.execute(
            select(BrandAbuseSighting).where(
                BrandAbuseSighting.first_seen_local >= from_dt,
                BrandAbuseSighting.first_seen_local < to_dt,
                BrandAbuseSighting.status == "active",
            ).order_by(BrandAbuseSighting.first_seen_local.desc()).limit(20)
        )
        brand_sightings = []
        for b in brand_r.scalars():
            cust = None
            if b.customer_id:
                cust = customer_rows.get(b.customer_id) or await session.get(Customer, b.customer_id)
            brand_sightings.append({
                "id": b.id,
                "url": (b.url or "")[:120],
                "page_domain": b.domain,
                "page_title": (b.page_title or "")[:80],
                "customer": cust.name if cust else "-",
                "rule_matched": b.rule_matched,
                "verdict_malicious": b.verdict_malicious,
                "engines_malicious": b.engines_malicious_total,
                "urlscan_result": f"https://urlscan.io/result/{b.scan_uuid}/",
                "first_seen": b.first_seen_local.isoformat() if b.first_seen_local else None,
            })

        brand_total = (await session.execute(
            select(func.count(BrandAbuseSighting.id)).where(BrandAbuseSighting.status == "active")
        )).scalar() or 0

        # ── Section 7: Malicious IPs (aggregate) ──
        top_ips_r = await session.execute(
            select(IpAggregatedScore).where(
                IpAggregatedScore.aggregate_risk_score >= 40,
            ).order_by(IpAggregatedScore.aggregate_risk_score.desc()).limit(20)
        )
        malicious_ips = []
        for r in top_ips_r.scalars():
            malicious_ips.append({
                "ip": r.ip,
                "aggregate_risk_score": r.aggregate_risk_score,
                "max_provider_score": r.max_provider_score,
                "confidence_score": r.confidence_score,
                "coverage_score": r.coverage_score,
                "positive_count": r.positive_provider_count,
                "responded_count": r.responded_provider_count,
                "enabled_count": r.enabled_provider_count,
                "provider_mask": r.provider_mask,
                "verdicts": r.provider_verdicts or {},
                "consensus_status": r.consensus_status,
                "last_calculated_at": r.last_calculated_at.isoformat() if r.last_calculated_at else None,
            })

        # ── Section 8: Asset Coverage ──
        assets_by_type_r = await session.execute(
            select(
                CustomerAsset.asset_type,
                func.count(CustomerAsset.id).label("cnt"),
            ).where(
                CustomerAsset.deleted_at.is_(None),
            ).group_by(CustomerAsset.asset_type).order_by(desc("cnt"))
        )
        assets_by_type = [
            {"type": (r.asset_type.value if hasattr(r.asset_type, "value") else str(r.asset_type)), "count": r.cnt}
            for r in assets_by_type_r
        ]

        total_assets = sum(a["count"] for a in assets_by_type)

    cve_enrichment_summary = await _enrich_cve_findings(cve_findings)
    asset_risk_ranking = await compute_asset_risk_ranking(from_dt, to_dt, customer_id=None, limit=20)

    return {
        "meta": {
            "from_dt": from_dt.isoformat(),
            "to_dt": to_dt.isoformat(),
            "window_days": window_days,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "customer_count": customer_count,
        },
        "findings": {
            "total": total_findings,
            "by_severity": findings_by_severity,
            "by_source": findings_by_source,
            "by_customer": findings_by_customer,
            "top_critical": top_critical,
        },
        "vulnerabilities": {
            "total": cve_count,
            "findings": cve_findings,
        },
        "campaigns": {
            "total": len(campaigns),
            "list": campaigns,
        },
        "exposures": {
            "in_window": len(exposures),
            "total_active": exposures_total,
            "list": exposures,
        },
        "document_leaks": {
            "in_window": len(doc_leaks),
            "total_active": doc_leaks_total,
            "list": doc_leaks,
        },
        "brand_abuse": {
            "in_window": len(brand_sightings),
            "total_active": brand_total,
            "sightings": brand_sightings,
        },
        "credential_leaks": {
            "status": "not_available",
            "note": "LeakCheck free tier không đủ dữ liệu — cần commercial tier "
                    "(BreachDirectory, HudsonRock, DeHashed) để enable.",
        },
        "malicious_ips": {
            "total": len(malicious_ips),
            "list": malicious_ips,
        },
        "asset_coverage": {
            "total": total_assets,
            "by_type": assets_by_type,
        },
        "asset_risk_ranking": asset_risk_ranking,
        "service_aggregate": service_aggregate,
        "cve_enrichment_summary": cve_enrichment_summary,
    }


async def gather_customer_report(customer_id: int, from_dt: datetime, to_dt: datetime) -> dict:
    """Gather customer-scoped data. Same structure as the global gatherer,
    filtered by customer_id everywhere.

    Schema note: Campaign.customer_id is NOT NULL (every campaign belongs
    to exactly one customer) -- "campaigns relevant to this customer" is
    simply `Campaign.customer_id == customer_id`, not a join through
    CampaignFinding (Campaign has no finding_ids column).
    """
    window_days = (to_dt - from_dt).days or 1

    async with async_session() as session:
        customer = await session.get(Customer, customer_id)
        if not customer:
            raise ValueError(f"Customer #{customer_id} not found")

        # ── Findings for this customer ──
        f_stmt = select(Finding).where(
            Finding.customer_id == customer_id,
            Finding.first_seen >= from_dt,
            Finding.first_seen < to_dt,
        )
        all_findings = [
            f for f in (await session.execute(f_stmt)).scalars()
            if not is_test_finding(f)
        ]

        findings_by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in all_findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            findings_by_severity[sev] = findings_by_severity.get(sev, 0) + 1

        total_findings = len(all_findings)

        source_dict: dict[str, int] = {}
        for f in all_findings:
            for src in (f.sources or []):
                source_dict[src] = source_dict.get(src, 0) + 1
        findings_by_source = sorted(
            [{"source": k, "count": v} for k, v in source_dict.items()],
            key=lambda x: x["count"], reverse=True,
        )[:15]

        critical_findings = [
            f for f in all_findings
            if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)) in ("CRITICAL", "HIGH")
        ]
        critical_findings.sort(key=lambda f: f.first_seen or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
        top_critical = [
            {
                "id": f.id, "title": f.title[:120],
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "ioc_type": f.ioc_type,
                "ioc_value": (f.ioc_value or "")[:80],
                "sources": f.sources or [],
                "matched_asset": (f.matched_asset or "")[:80],
                "first_seen": f.first_seen.isoformat() if f.first_seen else None,
            }
            for f in critical_findings[:20]
        ]

        cve_findings = [
            {
                "id": f.id, "cve": (f.ioc_value or "").upper(),
                "title": f.title[:100],
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "asset": (f.matched_asset or "")[:80],
            }
            for f in all_findings if f.ioc_type == "cve_id"
        ][:30]

        # ── Campaigns for this customer (Campaign.customer_id is NOT NULL) ──
        camp_stmt = select(Campaign).where(
            Campaign.customer_id == customer_id,
            Campaign.window_start >= from_dt,
            Campaign.window_start < to_dt,
        ).order_by(Campaign.confidence.desc())
        relevant_campaigns = []
        for c in (await session.execute(camp_stmt)).scalars():
            relevant_campaigns.append({
                "id": c.id,
                "name": f"Campaign #{c.id}",
                "status": c.status if isinstance(c.status, str) else c.status.value,
                "confidence": round(float(c.confidence or 0), 2),
                "shared_findings": c.finding_count or 0,
                "top_techniques": (c.technique_ids or [])[:5],
            })

        # ── Exposures for this customer ──
        e_stmt = select(Exposure).where(
            Exposure.customer_id == customer_id,
            Exposure.status == "active",
            Exposure.first_seen_local >= from_dt,
            Exposure.first_seen_local < to_dt,
        ).order_by(Exposure.first_seen_local.desc()).limit(20)
        exposures = [
            {
                "id": e.id, "ip": e.ip, "port": e.port,
                "service": e.service_name,
                "first_seen": e.first_seen_local.isoformat() if e.first_seen_local else None,
            }
            for e in (await session.execute(e_stmt)).scalars()
        ]

        exposures_total = (await session.execute(
            select(func.count(Exposure.id)).where(
                Exposure.customer_id == customer_id,
                Exposure.status == "active",
            )
        )).scalar() or 0

        # ── Service aggregate (scoped to this customer's exposures) ──
        svc_stmt = select(
            Exposure.service_name,
            func.count(Exposure.id).label("cnt"),
        ).where(
            Exposure.customer_id == customer_id,
            Exposure.status == "active",
        ).group_by(Exposure.service_name).order_by(desc("cnt")).limit(10)
        service_aggregate = [
            {"service": r.service_name or "unknown", "count": r.cnt}
            for r in await session.execute(svc_stmt)
        ]

        # ── Document leaks ──
        d_stmt = select(ExposedDocument).where(
            ExposedDocument.customer_id == customer_id,
            ExposedDocument.status == "active",
            ExposedDocument.first_seen_local >= from_dt,
            ExposedDocument.first_seen_local < to_dt,
        ).order_by(ExposedDocument.first_seen_local.desc()).limit(20)
        doc_leaks = [
            {
                "id": d.id, "filename": d.filename[:100],
                "bucket_url": (d.bucket_url or "")[:120],
                "keyword": d.keyword_matched,
                "rule_matched": d.rule_matched,
                "first_seen": d.first_seen_local.isoformat() if d.first_seen_local else None,
            }
            for d in (await session.execute(d_stmt)).scalars()
        ]

        # ── Brand abuse ──
        b_stmt = select(BrandAbuseSighting).where(
            BrandAbuseSighting.customer_id == customer_id,
            BrandAbuseSighting.status == "active",
            BrandAbuseSighting.first_seen_local >= from_dt,
            BrandAbuseSighting.first_seen_local < to_dt,
        ).order_by(BrandAbuseSighting.first_seen_local.desc()).limit(20)
        brand_sightings = [
            {
                "id": b.id,
                "url": (b.url or "")[:120],
                "page_domain": b.domain,
                "page_title": (b.page_title or "")[:80],
                "rule_matched": b.rule_matched,
                "verdict_malicious": b.verdict_malicious,
                "engines_malicious": b.engines_malicious_total,
                "urlscan_result": f"https://urlscan.io/result/{b.scan_uuid}/",
                "first_seen": b.first_seen_local.isoformat() if b.first_seen_local else None,
            }
            for b in (await session.execute(b_stmt)).scalars()
        ]

        # ── Malicious IPs linked to this customer's findings ──
        customer_ips = {
            f.ioc_value for f in all_findings
            if f.ioc_type in ("ipv4", "ipv6") and f.ioc_value
        }
        malicious_ips = []
        if customer_ips:
            ip_stmt = select(IpAggregatedScore).where(
                IpAggregatedScore.ip.in_(customer_ips),
                IpAggregatedScore.aggregate_risk_score >= 40,
            ).order_by(IpAggregatedScore.aggregate_risk_score.desc()).limit(20)
            for r in (await session.execute(ip_stmt)).scalars():
                malicious_ips.append({
                    "ip": r.ip,
                    "aggregate_risk_score": r.aggregate_risk_score,
                    "confidence_score": r.confidence_score,
                    "coverage_score": r.coverage_score,
                    "positive_count": r.positive_provider_count,
                    "responded_count": r.responded_provider_count,
                    "enabled_count": r.enabled_provider_count,
                    "provider_mask": r.provider_mask,
                    "verdicts": r.provider_verdicts or {},
                    "consensus_status": r.consensus_status,
                })

        # ── Asset breakdown ──
        asset_stmt = select(
            CustomerAsset.asset_type,
            func.count(CustomerAsset.id).label("cnt"),
        ).where(
            CustomerAsset.customer_id == customer_id,
            CustomerAsset.deleted_at.is_(None),
        ).group_by(CustomerAsset.asset_type)
        assets_by_type = [
            {"type": (r.asset_type.value if hasattr(r.asset_type, "value") else str(r.asset_type)), "count": r.cnt}
            for r in await session.execute(asset_stmt)
        ]
        total_assets = sum(a["count"] for a in assets_by_type)

    cve_enrichment_summary = await _enrich_cve_findings(cve_findings)
    asset_risk_ranking = await compute_asset_risk_ranking(
        from_dt, to_dt, customer_id=customer_id, limit=20,
    )

    return {
        "meta": {
            "from_dt": from_dt.isoformat(),
            "to_dt": to_dt.isoformat(),
            "window_days": window_days,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "customer": {
                "id": customer.id,
                "name": customer.name,
                "short_code": customer.short_code,
                "primary_domain": customer.primary_domain,
            },
        },
        "findings": {
            "total": total_findings,
            "by_severity": findings_by_severity,
            "by_source": findings_by_source,
            "top_critical": top_critical,
        },
        "vulnerabilities": {
            "total": len(cve_findings),
            "findings": cve_findings,
        },
        "campaigns": {
            "total": len(relevant_campaigns),
            "list": relevant_campaigns,
        },
        "exposures": {
            "in_window": len(exposures),
            "total_active": exposures_total,
            "list": exposures,
        },
        "document_leaks": {
            "in_window": len(doc_leaks),
            "sightings": doc_leaks,
        },
        "brand_abuse": {
            "in_window": len(brand_sightings),
            "sightings": brand_sightings,
        },
        "credential_leaks": {
            "status": "not_available",
            "note": "LeakCheck free tier không đủ dữ liệu — cần commercial tier "
                    "(BreachDirectory, HudsonRock, DeHashed) để enable.",
        },
        "malicious_ips": {
            "total": len(malicious_ips),
            "list": malicious_ips,
        },
        "asset_coverage": {
            "total": total_assets,
            "by_type": assets_by_type,
        },
        "asset_risk_ranking": asset_risk_ranking,
        "service_aggregate": service_aggregate,
        "cve_enrichment_summary": cve_enrichment_summary,
    }
