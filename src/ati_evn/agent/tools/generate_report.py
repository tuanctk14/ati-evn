"""generate_report — reuses /export weekly_report logic, returns markdown content."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ati_evn.agent.tools._base import register_tool, tool_error
from ati_evn.telegram.commands.export import _export_weekly_report


@register_tool(
    name="generate_report",
    description="Generate a weekly threat report (markdown) for all customers or a single customer.",
    parameters={
        "type": "object",
        "properties": {
            "scope": {"type": "string", "description": "'all' or 'customer'"},
            "customer": {"type": "string", "description": "Customer name (required if scope=customer)"},
            "since_days": {"type": "integer", "description": "Window size in days", "default": 7},
            "format": {"type": "string", "description": "Output format (markdown only for MVP)", "default": "markdown"},
        },
        "required": ["scope"],
    },
)
async def generate_report(
    scope: str, customer: str | None = None, since_days: int = 7, format: str = "markdown",
) -> dict:
    if scope not in ("all", "customer"):
        return tool_error("scope must be 'all' or 'customer'")
    if scope == "customer" and not customer:
        return tool_error("customer is required when scope='customer'")

    since = datetime.now(timezone.utc) - timedelta(days=since_days)
    customer_filter = customer if scope == "customer" else None

    content, filename, _mime = await _export_weekly_report(since, customer_filter, "md")
    markdown_content = content.decode("utf-8")

    return {
        "markdown_content": markdown_content,
        "metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scope": scope,
            "customer": customer,
            "since_days": since_days,
            "filename": filename,
        },
    }
