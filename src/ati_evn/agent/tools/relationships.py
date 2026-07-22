"""relationships — graph adjacency lookup for a given entity."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from ati_evn.agent.tools._base import register_tool, tool_error
from ati_evn.db.models import (
    Campaign,
    CampaignFinding,
    Customer,
    CustomerAsset,
    Detection,
    ExposedDocument,
    Exposure,
    Finding,
    SigmaRule,
)
from ati_evn.db.query_utils import customer_name_or_code_match, only_live_asset, only_live_customer
from ati_evn.db.session import async_session
from ati_evn.enrichment.attack_catalog import get_technique_name

CAP = 10


async def _rel_cve(session, cve_id: str) -> dict:
    cve_lower = cve_id.lower()
    cve_upper = cve_id.upper()

    finding_rows = await session.execute(
        select(Finding.id, Finding.title).where(
            Finding.ioc_type == "cve_id", Finding.ioc_value == cve_lower,
        ).limit(CAP)
    )
    findings = [{"id": fid, "label": title} for fid, title in finding_rows.all()]

    asset_values = set()
    techniques = set()
    for fid, _ in [(f["id"], f["label"]) for f in findings]:
        finding = await session.get(Finding, fid)
        if finding and finding.matched_asset:
            asset_values.add(finding.matched_asset)
        ctx = (finding.metadata_ or {}).get("attack_context") or {} if finding else {}
        for t in ctx.get("techniques") or []:
            if t.get("id"):
                techniques.add(t["id"])

    assets = []
    if asset_values:
        asset_rows = await session.execute(
            select(CustomerAsset).where(CustomerAsset.asset_value.in_(asset_values)).limit(CAP)
        )
        assets = [{"id": a.id, "label": a.asset_value} for a in asset_rows.scalars()]

    technique_list = [
        {"id": t, "label": get_technique_name(t)} for t in list(techniques)[:CAP]
    ]

    rule_rows = await session.execute(
        select(SigmaRule).where(SigmaRule.cve_refs.contains([cve_upper])).limit(CAP)
    )
    sigma_rules = [{"id": r.rule_uuid, "label": r.title} for r in rule_rows.scalars()]

    return {
        "findings": findings,
        "assets": assets,
        "techniques": technique_list,
        "sigma_rules": sigma_rules,
    }


async def _rel_ioc(session, ioc_value: str) -> dict:
    value_norm = ioc_value.strip().lower()
    det_rows = await session.execute(
        select(Detection).where(Detection.ioc_value == value_norm, Detection.ioc_type != "cve_id")
    )
    detections = list(det_rows.scalars())
    feeds = sorted({d.source for d in detections})[:CAP]

    finding_rows = await session.execute(
        select(Finding.id, Finding.title).where(Finding.ioc_value == value_norm).limit(CAP)
    )
    findings = [{"id": fid, "label": title} for fid, title in finding_rows.all()]

    return {
        "findings": findings,
        "feeds": [{"id": f, "label": f} for f in feeds],
    }


async def _rel_finding(session, finding_id: str) -> dict:
    try:
        fid = int(finding_id)
    except ValueError:
        return {}
    finding = await session.get(Finding, fid)
    if not finding:
        return {}

    related: dict = {"findings": [], "assets": [], "cves": [], "techniques": [], "sigma_rules": []}
    if finding.ioc_type == "cve_id":
        related["cves"] = [{"id": finding.ioc_value.upper(), "label": finding.ioc_value.upper()}]

    if finding.matched_asset:
        asset_rows = await session.execute(
            select(CustomerAsset).where(
                CustomerAsset.customer_id == finding.customer_id,
                CustomerAsset.asset_value == finding.matched_asset,
            ).limit(1)
        )
        asset = asset_rows.scalar_one_or_none()
        if asset:
            related["assets"] = [{"id": asset.id, "label": asset.asset_value}]

    customer = await session.get(Customer, finding.customer_id)
    if customer:
        related["customer"] = [{"id": customer.id, "label": customer.name}]

    ctx = (finding.metadata_ or {}).get("attack_context") or {}
    related["techniques"] = [
        {"id": t.get("id"), "label": get_technique_name(t.get("id"))}
        for t in (ctx.get("techniques") or [])[:CAP] if t.get("id")
    ]
    return related


async def _rel_asset(session, asset_id: str) -> dict:
    try:
        aid = int(asset_id)
    except ValueError:
        return {}
    asset = await session.get(CustomerAsset, aid)
    if not asset:
        return {}

    customer = await session.get(Customer, asset.customer_id)
    finding_rows = await session.execute(
        select(Finding.id, Finding.title, Finding.ioc_value).where(
            Finding.customer_id == asset.customer_id,
            Finding.matched_asset == asset.asset_value,
        ).limit(CAP)
    )
    findings = []
    cves = []
    for fid, title, ioc_value in finding_rows.all():
        findings.append({"id": fid, "label": title})
        cves.append({"id": ioc_value.upper(), "label": ioc_value.upper()})

    return {
        "customer": [{"id": customer.id, "label": customer.name}] if customer else [],
        "findings": findings,
        "cves": cves,
    }


async def _rel_customer(session, customer_id_or_name: str) -> dict:
    cust = None
    if customer_id_or_name.isdigit():
        cust = await session.get(Customer, int(customer_id_or_name))
    if not cust:
        result = await session.execute(
            select(Customer).where(customer_name_or_code_match(customer_id_or_name)).limit(1)
        )
        cust = result.scalar_one_or_none()
    if not cust:
        return {}

    asset_rows = await session.execute(
        select(CustomerAsset).where(
            CustomerAsset.customer_id == cust.id, only_live_asset(),
        ).limit(CAP)
    )
    assets = [{"id": a.id, "label": a.asset_value} for a in asset_rows.scalars()]

    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    finding_rows = await session.execute(
        select(Finding.id, Finding.title).where(
            Finding.customer_id == cust.id, Finding.first_seen >= cutoff,
        ).limit(CAP)
    )
    findings = [{"id": fid, "label": title} for fid, title in finding_rows.all()]

    return {"assets": assets, "findings": findings}


async def _rel_technique(session, technique_id: str) -> dict:
    tid = technique_id.upper()
    cve_ids = set()
    finding_hits = []
    finding_rows = await session.execute(select(Finding))
    for f in finding_rows.scalars():
        ctx = (f.metadata_ or {}).get("attack_context") or {}
        tech_ids = {t.get("id") for t in ctx.get("techniques") or []}
        if tid in tech_ids:
            finding_hits.append({"id": f.id, "label": f.title})
            if f.ioc_type == "cve_id":
                cve_ids.add(f.ioc_value.upper())
        if len(finding_hits) >= CAP:
            break

    return {
        "findings": finding_hits[:CAP],
        "cves": [{"id": c, "label": c} for c in list(cve_ids)[:CAP]],
    }


async def _rel_exposure(session, exposure_id: str) -> dict:
    try:
        eid = int(exposure_id)
    except ValueError:
        return tool_error("exposure_id must be int")
    exp = await session.get(Exposure, eid)
    if not exp:
        return tool_error(f"Exposure #{eid} not found")

    # Finding.metadata_ is a plain JSON column (not JSONB) — no SQL-level
    # ->>/astext filter available, so load and check metadata_ in Python
    # (same pattern as exposure_rules/finding_creator.py's dedup check).
    rows = await session.execute(select(Finding))
    findings = [
        f for f in rows.scalars()
        if (f.metadata_ or {}).get("exposure_id") == eid
    ][:CAP]

    asset_label = None
    if exp.asset_id:
        asset = await session.get(CustomerAsset, exp.asset_id)
        if asset:
            asset_label = f"{asset.asset_value} ({asset.asset_type.value})"

    return {
        "findings": [
            {"id": f.id, "label":
             f"{f.title[:50]} ({f.severity.value if hasattr(f.severity,'value') else str(f.severity)})"}
            for f in findings
        ],
        "assets": [{"id": exp.asset_id, "label": asset_label}] if asset_label else [],
        "cves": [
            {"id": (f.metadata_ or {}).get("cve_id"), "label": (f.metadata_ or {}).get("cve_id")}
            for f in findings if (f.metadata_ or {}).get("cve_id")
        ][:CAP],
    }


async def _rel_exposed_document(session, document_id: str) -> dict:
    try:
        did = int(document_id)
    except ValueError:
        return tool_error("document_id must be int")
    doc = await session.get(ExposedDocument, did)
    if not doc:
        return tool_error(f"Document #{did} not found")

    # Finding.metadata_ is a plain JSON column (not JSONB) — no SQL-level
    # ->>/astext filter available, so load and check metadata_ in Python
    # (same pattern as exposure_rules/finding_creator.py's dedup check).
    rows = await session.execute(select(Finding))
    findings = [
        f for f in rows.scalars()
        if (f.metadata_ or {}).get("document_id") == did
    ][:CAP]

    customer_label = None
    if doc.customer_id:
        c = await session.get(Customer, doc.customer_id)
        if c:
            customer_label = c.name

    return {
        "findings": [
            {"id": f.id, "label":
             f"{f.title[:50]} ({f.severity.value if hasattr(f.severity,'value') else str(f.severity)})"}
            for f in findings
        ],
        "customers": [{"id": doc.customer_id, "label": customer_label}] if customer_label else [],
        "bucket": doc.bucket_url,
        "filename": doc.filename,
        "keyword": doc.keyword_matched,
    }


async def _rel_campaign(session, campaign_id: str) -> dict:
    try:
        cid = int(campaign_id)
    except ValueError:
        return tool_error(f"campaign_id must be int, got '{campaign_id}'")
    campaign = await session.get(Campaign, cid)
    if not campaign:
        return tool_error(f"Campaign #{cid} not found")

    f_stmt = select(Finding).join(
        CampaignFinding, Finding.id == CampaignFinding.finding_id,
    ).where(CampaignFinding.campaign_id == cid).limit(CAP)
    findings = list((await session.execute(f_stmt)).scalars())

    assets_set = {(f.matched_asset or "") for f in findings if f.matched_asset}
    cves = sorted({f.ioc_value.upper() for f in findings if f.ioc_type == "cve_id"})
    iocs = sorted({f.ioc_value for f in findings if f.ioc_type != "cve_id"})
    techniques = [{"id": tid, "label": get_technique_name(tid)}
                  for tid in (campaign.technique_ids or [])]

    return {
        "findings": [
            {"id": f.id, "label":
             f"{f.ioc_value[:30]} ({f.severity.value if hasattr(f.severity, 'value') else str(f.severity)})"}
            for f in findings[:CAP]
        ],
        "assets": [{"id": None, "label": a} for a in sorted(assets_set)[:CAP]],
        "cves": [{"id": c, "label": c} for c in cves[:CAP]],
        "iocs": [{"id": None, "label": i} for i in iocs[:CAP]],
        "techniques": techniques[:CAP],
    }


@register_tool(
    name="relationships",
    description="Get graph adjacency (related entities) for a CVE, IOC, finding, asset, customer, ATT&CK technique, or Campaign.",
    parameters={
        "type": "object",
        "properties": {
            "entity_type": {"type": "string", "enum":
                            ["cve", "ioc", "finding", "asset", "customer",
                             "technique", "campaign", "exposure", "exposed_document"]},
            "entity_id": {"type": "string", "description": "Identifier for the entity (ID or value)"},
        },
        "required": ["entity_type", "entity_id"],
    },
)
async def relationships(entity_type: str, entity_id: str) -> dict:
    entity_type = entity_type.lower()
    async with async_session() as session:
        if entity_type == "cve":
            related = await _rel_cve(session, entity_id)
        elif entity_type == "ioc":
            related = await _rel_ioc(session, entity_id)
        elif entity_type == "finding":
            related = await _rel_finding(session, entity_id)
        elif entity_type == "asset":
            related = await _rel_asset(session, entity_id)
        elif entity_type == "customer":
            related = await _rel_customer(session, entity_id)
        elif entity_type == "technique":
            related = await _rel_technique(session, entity_id)
        elif entity_type == "campaign":
            related = await _rel_campaign(session, entity_id)
            if isinstance(related, dict) and related.get("success") is False:
                return related
        elif entity_type == "exposure":
            related = await _rel_exposure(session, entity_id)
            if isinstance(related, dict) and related.get("success") is False:
                return related
        elif entity_type == "exposed_document":
            related = await _rel_exposed_document(session, entity_id)
            if isinstance(related, dict) and related.get("success") is False:
                return related
        else:
            return tool_error(
                f"Unknown entity_type '{entity_type}'",
                hint="Use one of: cve, ioc, finding, asset, customer, technique, campaign, exposure, exposed_document.",
            )

    return {
        "entity_type": entity_type,
        "entity_id": entity_id,
        "related": related,
    }
