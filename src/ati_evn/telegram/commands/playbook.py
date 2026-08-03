"""Generate NIST 800-61 playbook. Cache by (cve_id, network_segment).

Cache logic:
  - Look up PlaybookCache row for (cve_id, network_segment)
  - If exists: return cached playbook_md, bump reused_count
  - If not: call LLM, cache result, return

Format decision:
  - If playbook_md < 3500 chars: send inline
  - Else: upload as .md file
"""
from __future__ import annotations

import logging

from aiogram import Router
from aiogram.exceptions import TelegramBadRequest
from aiogram.filters import Command
from aiogram.types import BufferedInputFile, Message
from sqlalchemy import select

from ati_evn.agent.loop.postfilter import sanitize_telegram_markdown
from ati_evn.config import get_settings
from ati_evn.db.models import CustomerAsset, CveCweMap, CveProductMap, Detection, Finding, PlaybookCache
from ati_evn.db.session import async_session
from ati_evn.llm.client import LLMClient
from ati_evn.telegram.argparse_util import parse_args
from ati_evn.telegram.audit import log_command

logger = logging.getLogger("ati_evn.telegram.playbook")
router = Router()

PLAYBOOK_SYSTEM = """You are an incident response playbook author for
a Vietnamese electric utility SOC. Generate a NIST 800-61 (Rev 2) playbook
for a specific CVE affecting a specific network segment.

Output JSON with keys:
  markdown: full playbook as markdown string
  confidence: 0.0-1.0

The markdown MUST include these 5 sections in order (Vietnamese headers):

  ## 1. Identification (Nhận diện)
  ## 2. Containment (Ngăn chặn)
  ## 3. Eradication (Loại bỏ)
  ## 4. Recovery (Phục hồi)
  ## 5. Lessons Learned (Bài học)

Each section:
- 2-4 concrete action items (be concise, one short line per item;
  include a command only when it directly helps, not for every item)
- Vietnamese narrative, English technical terms (CVE-ID, ATT&CK, tool
  names) preserved
- Reference the specific vendor/product/version and network_segment
- For SCADA network segments (ot_control, ot_process), emphasize safety
  (do NOT reboot PLCs mid-operation, coordinate with plant operators)
- For DMZ, focus on isolation + traffic filtering
- For internal IT, focus on patching + credential rotation

Keep the ENTIRE markdown value under ~1800 words total across all 5
sections combined -- this is a quick-reference playbook for an
analyst mid-incident, not an exhaustive runbook. Prioritize the most
critical action per section over covering every possibility.

Do NOT hallucinate CVE facts, CVSS scores, or vendor advisories.
Do NOT include disclaimers about being an AI.

Return ONLY the JSON, no markdown fences."""


async def _load_cve_context(session, cve_id: str) -> dict:
    """Fill in description/cvss/vendor/product/version_range/cwe_ids for a
    CVE — same tables rule.py / rules/orchestrator.py already read from."""
    det_row = await session.execute(
        select(Detection.raw_text, Detection.metadata_).where(
            Detection.ioc_value == cve_id.lower(),
            Detection.source == "nvd",
        ).limit(1)
    )
    row = det_row.first()
    description = (row[0] if row else None) or ""
    det_meta = (row[1] if row else None) or {}

    cpm_row = await session.execute(
        select(CveProductMap).where(CveProductMap.cve_id == cve_id)
        .order_by(CveProductMap.confidence.desc()).limit(1)
    )
    cpm = cpm_row.scalar_one_or_none()

    cwe_rows = await session.execute(
        select(CveCweMap.cwe_id).where(CveCweMap.cve_id == cve_id)
    )
    cwe_ids = sorted({r[0] for r in cwe_rows})

    return {
        "description": description,
        "cvss": det_meta.get("cvss_score") or (cpm.cvss_score if cpm else None),
        "vendor": cpm.vendor if cpm else None,
        "product": cpm.product if cpm else None,
        "version_range": cpm.version_range if cpm else None,
        "cwe_ids": cwe_ids,
    }


async def _get_or_generate(session, cve_id: str, network_segment: str | None,
                            context: dict) -> tuple[str, bool]:
    """Return (markdown, was_cached)."""
    stmt = select(PlaybookCache).where(
        PlaybookCache.cve_id == cve_id,
        PlaybookCache.network_segment == network_segment,
    )
    cached = (await session.execute(stmt)).scalar_one_or_none()
    if cached:
        cached.reused_count = (cached.reused_count or 0) + 1
        await session.commit()
        return cached.playbook_md, True

    settings = get_settings()
    client = LLMClient(settings)
    user_prompt = (
        f"CVE: {cve_id}\n"
        f"Network segment: {network_segment or 'unknown'}\n"
        f"Vendor/Product: {context.get('vendor')} / {context.get('product')}\n"
        f"Version affected: {context.get('version_range', '')}\n"
        f"CVSS: {context.get('cvss', 'unknown')}\n"
        f"CVE description: {(context.get('description') or '')[:1500]}\n"
        f"ATT&CK techniques: {context.get('attack_techniques', [])}\n"
        f"Kill chain phases: {context.get('kill_chain_phases', [])}\n"
        f"CWEs: {context.get('cwe_ids', [])}\n\n"
        f"Generate the NIST 800-61 playbook JSON."
    )
    raw = await client.chat_json(
        system=PLAYBOOK_SYSTEM, user=user_prompt,
        # 4096 was observed truncating mid-JSON for CVEs with rich context
        # (5 Vietnamese sections + commands can run long) -- see
        # scripts/audit_14b_backlog.md's "/playbook can fail with 'Could
        # not extract valid JSON'" entry.
        max_tokens=6144, temperature=0.3,
    )
    markdown = raw.get("markdown", "")
    if not markdown:
        raise RuntimeError("LLM returned empty playbook markdown")

    cache = PlaybookCache(
        cve_id=cve_id,
        network_segment=network_segment,
        playbook_md=markdown,
        model_used=settings.llm_model,
        reused_count=0,
    )
    session.add(cache)
    await session.commit()
    return markdown, False


async def generate_playbook_for(
    target: str, *, network_segment_override: str | None = None,
) -> dict:
    """Public entry point for /playbook's generation logic, usable outside
    the Telegram handler (added for the agent tool -- see
    agent/tools/generate_playbook.py). `target` is a CVE-ID or a Finding id
    (same as /playbook's positional arg). Returns
    {"cve_id", "network_segment", "markdown", "was_cached"} or
    {"error": "..."} on a resolvable failure (not found / not a CVE
    finding) -- raises on generation failure same as _get_or_generate."""
    is_cve = target.upper().startswith("CVE-")
    network_segment: str | None = network_segment_override
    context: dict = {}

    async with async_session() as session:
        if is_cve:
            cve_id = target.upper()
        else:
            try:
                finding_id = int(target)
            except ValueError:
                return {"error": f"ID không hợp lệ: {target}"}
            finding = await session.get(Finding, finding_id)
            if not finding:
                return {"error": f"Không tìm thấy Finding #{finding_id}"}
            if finding.ioc_type != "cve_id":
                return {"error": (
                    f"Finding #{finding_id} không phải CVE finding, "
                    f"playbook chưa hỗ trợ IOC finding."
                )}
            cve_id = finding.ioc_value.upper()

            if network_segment_override is None and finding.matched_asset:
                asset_row = await session.execute(
                    select(CustomerAsset).where(
                        CustomerAsset.customer_id == finding.customer_id,
                        CustomerAsset.asset_value == finding.matched_asset,
                    ).limit(1)
                )
                asset = asset_row.scalar_one_or_none()
                if asset and asset.network_segment:
                    network_segment = asset.network_segment.value

            ctx = (finding.metadata_ or {}).get("attack_context") or {}
            context["attack_techniques"] = [t.get("id") for t in ctx.get("techniques", [])]
            context["kill_chain_phases"] = ctx.get("kill_chain_phases", [])
            context["cwe_ids"] = ctx.get("cwe_ids", [])

        cve_context = await _load_cve_context(session, cve_id)
        context = {**cve_context, **context}

        markdown, was_cached = await _get_or_generate(session, cve_id, network_segment, context)

    return {
        "cve_id": cve_id,
        "network_segment": network_segment,
        "markdown": markdown,
        "was_cached": was_cached,
    }


@router.message(Command("playbook"))
@log_command("playbook")
async def cmd_playbook(message: Message):
    args = parse_args(message.text or "", "playbook")
    pos = args.get("_positional", [])
    if not pos:
        await message.answer("Cú pháp: /playbook <CVE-ID | finding_id>")
        return
    target = pos[0]

    thinking = await message.answer(f"📖 Đang generate playbook cho {target}...")

    try:
        result = await generate_playbook_for(target)
    except Exception as e:
        await thinking.delete()
        logger.exception("Playbook generation failed: %s", e)
        await message.answer(f"⚠️ Playbook generation lỗi: {str(e)[:200]}")
        return

    if "error" in result:
        await thinking.delete()
        await message.answer(result["error"])
        return

    cve_id = result["cve_id"]
    network_segment = result["network_segment"]
    markdown = result["markdown"]
    was_cached = result["was_cached"]

    await thinking.delete()

    header = (
        f"📖 Playbook cho {cve_id}"
        + (f" (network_segment={network_segment})" if network_segment else "")
        + (" [cached]" if was_cached else " [freshly generated]")
    )

    if len(markdown) < 3500:
        # Sanitize only for the inline-Telegram-message path -- the
        # raw markdown (## headings etc.) is correct as-is for the
        # .md file download below, where a real Markdown reader
        # renders it properly.
        body = sanitize_telegram_markdown(markdown)
        try:
            await message.answer(f"{header}\n\n{body}", parse_mode="Markdown")
        except TelegramBadRequest:
            await message.answer(f"{header}\n\n{body}")
    else:
        f = BufferedInputFile(markdown.encode("utf-8"), filename=f"{cve_id}_playbook.md")
        await message.answer_document(f, caption=header)
