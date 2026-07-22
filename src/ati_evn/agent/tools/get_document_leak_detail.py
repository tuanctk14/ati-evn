"""get_document_leak_detail -- full detail of one exposed document + findings."""
from __future__ import annotations

from sqlalchemy import select

from ati_evn.agent.tools._base import register_tool, tool_error
from ati_evn.db.models import Customer, ExposedDocument, Finding
from ati_evn.db.session import async_session


@register_tool(
    name="get_document_leak_detail",
    description="Full detail of one exposed document by ID, including derived findings.",
    parameters={
        "type": "object",
        "properties": {"document_id": {"type": "integer"}},
        "required": ["document_id"],
    },
)
async def get_document_leak_detail(document_id: int) -> dict:
    async with async_session() as session:
        doc = await session.get(ExposedDocument, document_id)
        if not doc:
            return tool_error(f"Document #{document_id} not found")

        # Finding.metadata_ is a plain JSON column (not JSONB), so it can't
        # be filtered with a SQL-level ->>/astext operator -- load
        # candidates and check metadata_ in Python (same pattern as
        # exposure_rules/finding_creator.py's dedup check, slice 9B).
        rows = await session.execute(select(Finding))
        findings = [
            f for f in rows.scalars()
            if (f.metadata_ or {}).get("document_id") == document_id
        ]

        customer_name = None
        if doc.customer_id:
            c = await session.get(Customer, doc.customer_id)
            if c:
                customer_name = c.name

        return {
            "document": {
                "id": doc.id, "bucket_url": doc.bucket_url,
                "file_path": doc.file_path, "filename": doc.filename,
                "extension": doc.file_extension, "file_size": doc.file_size,
                "keyword_matched": doc.keyword_matched,
                "customer": customer_name,
                "bucket_whitelisted": doc.bucket_whitelisted,
                "rule_matched": doc.rule_matched,
                "rule_severity": doc.rule_severity,
                "llm_relevance_checked": doc.llm_relevance_checked,
                "llm_relevance_score": doc.llm_relevance_score,
                "llm_reasoning": doc.llm_reasoning,
                "status": doc.status,
                "first_seen_local": doc.first_seen_local.isoformat() if doc.first_seen_local else None,
                "last_seen_local": doc.last_seen_local.isoformat() if doc.last_seen_local else None,
            },
            "findings": [
                {
                    "id": f.id, "title": f.title,
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "status": f.status.value if hasattr(f.status, "value") else str(f.status),
                }
                for f in findings
            ],
        }
