"""SQLAlchemy 2.0 ORM models — ATI-EVN schema.

Design notes
------------
- Customer = EVN corporate + each subsidiary (parent_id chain, self-referential).
- CustomerAsset covers BOTH the "match surface" (ip/cidr/domain/keyword/brand)
  and the "device inventory" (IT servers, workstations, and SCADA/ICS gear).
  Device rows use asset_type='device' and populate vendor/product/version +
  device_type + is_ics + network_segment.
- Detection = one row per (source, ioc_value) sighting. customer_id nullable
  before routing; set after customer_router matches.
- Finding = merged view — one row per (customer_id, ioc_type, normalized_value).
  Multiple detections roll into one finding; source_count bumps on merge.
- Alert = one row per (finding, dispatch event). Holds Telegram message_id
  so inline-button callbacks can update the same message. Ack/close/FP state
  tracked here for the analyst workflow.
- FpMemory = analyst decisions. When re-matched, ingest checks FpMemory and
  auto-closes as false_positive without dispatching a new alert.
- CveProductMap = CVE → (vendor, product, version_range). Populated by NVD
  (from CPE), KEV, Vulners, and lazily by LLM inference when a CVE hits our
  scope but has no structured product data.
- ProbableExposure = "we think you MIGHT be exposed but can't confirm".
  Created when product matches but customer version is unknown or CVE has
  no version_range.
"""
from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Enum as SAEnum,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


# ═══════════════════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════════════════

class Severity(str, enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DetectionStatus(str, enum.Enum):
    NEW = "new"
    ROUTED = "routed"       # matched to a customer
    UNMATCHED = "unmatched" # no customer match; kept for global correlation
    ENRICHED = "enriched"
    MERGED = "merged"       # rolled into a finding


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    ACKED = "acknowledged"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"
    EXPIRED = "expired"    # internal IOCs past TTL (see alerts/ttl_worker.py)


class AlertState(str, enum.Enum):
    PENDING = "pending"      # dispatched, not yet ack'd
    ACKED = "acknowledged"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class AssetType(str, enum.Enum):
    IP = "ip"
    CIDR = "cidr"
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    EMAIL = "email"
    EMAIL_DOMAIN = "email_domain"
    KEYWORD = "keyword"
    BRAND_NAME = "brand_name"
    ORG_NAME = "org_name"
    TECH_STACK = "tech_stack"   # legacy free-text "nginx/1.18.0"
    DEVICE = "device"           # structured: IT server, workstation, PLC, HMI, SCADA server


class DeviceType(str, enum.Enum):
    # IT
    SERVER = "server"
    WORKSTATION = "workstation"
    NETWORK_SWITCH = "network_switch"
    FIREWALL = "firewall"
    ROUTER = "router"
    # ICS/SCADA
    PLC = "plc"
    RTU = "rtu"
    HMI = "hmi"
    SCADA_SERVER = "scada_server"
    HISTORIAN = "historian"
    ENGINEERING_WORKSTATION = "engineering_workstation"
    OTHER = "other"


class NetworkSegment(str, enum.Enum):
    DMZ = "dmz"
    INTERNAL_IT = "internal_it"
    OT_CORPORATE = "ot_corporate"     # Purdue Level 3
    OT_CONTROL = "ot_control"         # Purdue Level 2
    OT_PROCESS = "ot_process"         # Purdue Level 1/0
    ISOLATED = "isolated"
    UNKNOWN = "unknown"


# ═══════════════════════════════════════════════════════════════════════════
# Customer & Assets
# ═══════════════════════════════════════════════════════════════════════════

class Customer(Base):
    __tablename__ = "customers"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False, unique=True)
    short_code = Column(String(50), nullable=True)   # e.g. "EVN_HANOI", "EVNNPC"
    parent_id = Column(Integer, ForeignKey("customers.id", ondelete="SET NULL"), nullable=True)
    industry = Column(String(100), default="electric_utility")
    tier = Column(String(20), default="critical")
    primary_domain = Column(String(255), nullable=True)
    contact_name = Column(String(255), nullable=True)
    contact_email = Column(String(255), nullable=True)
    active = Column(Boolean, default=True)

    # Onboarding state: created → assets_added → monitoring → tuning → production
    onboarding_state = Column(String(30), default="created")

    created_at = Column(DateTime(timezone=True), default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    deleted_at = Column(DateTime(timezone=True), nullable=True)
    deleted_by = Column(String(120), nullable=True)

    parent = relationship("Customer", remote_side=[id], backref="subsidiaries")
    assets = relationship("CustomerAsset", back_populates="customer", cascade="all, delete-orphan")


class CustomerAsset(Base):
    __tablename__ = "customer_assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    customer_id = Column(Integer, ForeignKey("customers.id", ondelete="CASCADE"), nullable=False)

    asset_type = Column(SAEnum(AssetType, values_callable=lambda e: [x.value for x in e]),
                        nullable=False)
    asset_value = Column(String(500), nullable=False)  # ip / cidr / domain / keyword / free-text
    criticality = Column(String(20), default="medium")  # low, medium, high, critical

    # Structured device inventory (used when asset_type == DEVICE)
    device_type = Column(SAEnum(DeviceType, values_callable=lambda e: [x.value for x in e]),
                         nullable=True)
    vendor = Column(String(120), nullable=True)      # e.g. "siemens", "microsoft", "fortinet"
    product = Column(String(200), nullable=True)     # e.g. "simatic s7-1200", "windows server", "fortios"
    version = Column(String(80), nullable=True)      # e.g. "4.5.2"
    ip_address = Column(String(45), nullable=True)   # device's own IP, e.g. "10.12.4.1" (v4 or v6)
    is_ics = Column(Boolean, default=False)
    is_internet_facing = Column(Boolean, default=False)
    network_segment = Column(SAEnum(NetworkSegment, values_callable=lambda e: [x.value for x in e]),
                             nullable=True)

    # Provenance
    discovery_source = Column(String(100), nullable=True)  # "manual", "censys", "leakix", "recon", "seed"
    confidence = Column(Float, default=1.0)
    ioc_hit_count = Column(Integer, default=0)
    last_seen_in_ioc = Column(DateTime(timezone=True), nullable=True)
    notes = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), default=_utcnow)

    deleted_at = Column(DateTime(timezone=True), nullable=True)
    deleted_by = Column(String(120), nullable=True)

    customer = relationship("Customer", back_populates="assets")

    __table_args__ = (
        Index("ix_asset_customer_type", "customer_id", "asset_type"),
        Index("ix_asset_value", "asset_value"),
        Index("ix_asset_vendor_product", "vendor", "product"),
        Index("ix_asset_ip_address", "ip_address"),
    )


# ═══════════════════════════════════════════════════════════════════════════
# Detection → Finding → Alert pipeline
# ═══════════════════════════════════════════════════════════════════════════

class Detection(Base):
    """Raw sighting from a single collector. Many detections may merge into one Finding."""
    __tablename__ = "detections"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=True)  # nullable pre-routing

    source = Column(String(80), nullable=False)      # "threatfox", "nvd", "otx", ...
    ioc_type = Column(String(50), nullable=False)    # "ipv4", "domain", "url", "sha256", "cve_id", ...
    ioc_value = Column(Text, nullable=False)         # normalized lowercase
    raw_text = Column(Text, nullable=True)           # original context (e.g. CVE description, malware tag)

    severity = Column(SAEnum(Severity), default=Severity.MEDIUM)
    status = Column(SAEnum(DetectionStatus), default=DetectionStatus.NEW)
    confidence = Column(Float, default=0.5)

    matched_asset = Column(String(500), nullable=True)    # what customer asset triggered the match
    correlation_type = Column(String(50), nullable=True)  # exact_ip, ip_range, exact_domain, subdomain, tech_stack, keyword

    finding_id = Column(BigInteger, ForeignKey("findings.id"), nullable=True)

    first_seen = Column(DateTime(timezone=True), default=_utcnow)
    last_seen = Column(DateTime(timezone=True), default=_utcnow)
    expires_at = Column(DateTime(timezone=True), nullable=True)
        # NULL = no expiry (default). Set when analyst uses /add_ioc --expire.
        # ttl_worker.py transitions the linked Finding to EXPIRED once past.
    metadata_ = Column("metadata", JSON, default=dict)

    created_at = Column(DateTime(timezone=True), default=_utcnow)

    deleted_at = Column(DateTime(timezone=True), nullable=True)
    deleted_by = Column(String(120), nullable=True)

    finding = relationship("Finding", back_populates="detections", foreign_keys=[finding_id])

    __table_args__ = (
        Index("ix_det_ioc", "ioc_type", "ioc_value"),
        Index("ix_det_customer_status", "customer_id", "status"),
        Index("ix_det_source", "source"),
        Index("ix_det_created", "created_at"),
    )


class Finding(Base):
    """Deduplicated, analyst-facing record. One per (customer_id, ioc_type, ioc_value)."""
    __tablename__ = "findings"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)

    ioc_type = Column(String(50), nullable=False)
    ioc_value = Column(Text, nullable=False)
    title = Column(String(500), nullable=False)
    cve_id = Column(String(30), nullable=True, index=True)  # only for CVE findings

    severity = Column(SAEnum(Severity), default=Severity.MEDIUM, nullable=False)
    status = Column(SAEnum(FindingStatus), default=FindingStatus.OPEN, nullable=False)
    confidence = Column(Float, default=0.5)

    matched_asset = Column(String(500), nullable=True)
    correlation_type = Column(String(50), nullable=True)
    detection_reason = Column(Text, nullable=True)  # human-readable "why detected"

    source_count = Column(Integer, default=1)
    sources = Column(JSON, default=list)  # list of source names

    first_seen = Column(DateTime(timezone=True), default=_utcnow)
    last_seen = Column(DateTime(timezone=True), default=_utcnow)
    closed_at = Column(DateTime(timezone=True), nullable=True)
    closed_by = Column(String(120), nullable=True)      # telegram username or user_id
    closed_reason = Column(Text, nullable=True)

    metadata_ = Column("metadata", JSON, default=dict)

    detections = relationship("Detection", back_populates="finding",
                              foreign_keys="[Detection.finding_id]")
    alerts = relationship("Alert", back_populates="finding", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("customer_id", "ioc_type", "ioc_value", name="uq_finding_customer_ioc"),
        Index("ix_finding_status_sev", "status", "severity"),
    )


class Alert(Base):
    """One row per dispatch attempt. Holds Telegram message_id for inline-button callbacks."""
    __tablename__ = "alerts"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    finding_id = Column(BigInteger, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)

    dispatched_at = Column(DateTime(timezone=True), default=_utcnow)
    dispatch_reason = Column(Text, nullable=True)  # "severity=HIGH" or "MEDIUM+2sources"

    # Telegram wiring
    telegram_chat_id = Column(String(80), nullable=True)
    telegram_message_id = Column(BigInteger, nullable=True)

    # State transitions driven by button clicks or /commands
    state = Column(SAEnum(AlertState), default=AlertState.PENDING, nullable=False)
    acked_by = Column(String(120), nullable=True)
    acked_at = Column(DateTime(timezone=True), nullable=True)
    closed_by = Column(String(120), nullable=True)
    closed_at = Column(DateTime(timezone=True), nullable=True)
    close_reason = Column(Text, nullable=True)

    finding = relationship("Finding", back_populates="alerts")

    __table_args__ = (
        Index("ix_alert_state", "state"),
        Index("ix_alert_tg_msg", "telegram_message_id"),
    )


class FpMemory(Base):
    """Analyst FP decisions. Next matching detection auto-closes, no dispatch.

    asset_id scoping: NULL means "false positive for ALL of this customer's
    assets" (customer-wide); a specific asset_id narrows the FP rule to just
    that asset. Without this, marking one asset's CVE as FP silently
    suppressed the SAME CVE against every other asset that customer owns —
    a real detection on a different, still-vulnerable device would vanish
    with no alert. is_false_positive() checks both scopes and auto-closes
    if either matches.
    """
    __tablename__ = "fp_memory"

    id = Column(Integer, primary_key=True, autoincrement=True)
    customer_id = Column(Integer, ForeignKey("customers.id", ondelete="CASCADE"), nullable=False)
    asset_id = Column(Integer, ForeignKey("customer_assets.id", ondelete="CASCADE"), nullable=True)
    ioc_type = Column(String(50), nullable=False)
    ioc_value_hash = Column(String(64), nullable=False)  # sha256 of normalized value
    ioc_value_sample = Column(Text, nullable=True)       # for analyst readability

    reason = Column(Text, nullable=True)
    marked_by = Column(String(120), nullable=True)
    marked_at = Column(DateTime(timezone=True), default=_utcnow)
    hit_count = Column(Integer, default=0)               # how many times this rule auto-closed a new det
    last_hit_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("customer_id", "asset_id", "ioc_type", "ioc_value_hash", name="uq_fp_memory"),
    )


# ═══════════════════════════════════════════════════════════════════════════
# CVE-specific tables
# ═══════════════════════════════════════════════════════════════════════════

class CveProductMap(Base):
    """CVE → vendor/product/version_range. Populated by NVD (from CPE), KEV, Vulners.
    Rows with source='llm_inferred' come from lazy LLM CPE inference."""
    __tablename__ = "cve_product_map"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(30), nullable=False, index=True)
    vendor = Column(String(120), nullable=True)
    product = Column(String(200), nullable=False)
    version_range = Column(String(200), nullable=True)  # ">= 4.0, < 4.5" style
    cvss_score = Column(Float, nullable=True)
    actively_exploited = Column(Boolean, default=False)  # from KEV
    source = Column(String(30), default="nvd")           # nvd, kev, vulners, llm_inferred
    confidence = Column(Float, default=1.0)              # < 1.0 for llm_inferred
    reasoning = Column(Text, nullable=True)              # LLM explanation if inferred
    created_at = Column(DateTime(timezone=True), default=_utcnow)

    __table_args__ = (
        Index("ix_cpm_product", "vendor", "product"),
        UniqueConstraint("cve_id", "vendor", "product", "source", name="uq_cpm_row"),
    )


class CveCweMap(Base):
    """CVE → CWE (weakness category). Populated by NVD (from weaknesses[])
    and lazily by LLM inference (source='llm_inferred') when NVD hasn't
    attached a CWE yet."""
    __tablename__ = "cve_cwe_map"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(30), nullable=False, index=True)
    cwe_id = Column(String(20), nullable=False)          # e.g. "CWE-79"
    source = Column(String(30), default="nvd")           # nvd, llm_inferred
    confidence = Column(Float, default=1.0)              # < 1.0 for llm_inferred
    reasoning = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)

    __table_args__ = (
        UniqueConstraint("cve_id", "cwe_id", "source", name="uq_cwe_row"),
    )


class ProbableExposure(Base):
    """Customer might be affected, but we cannot confirm (version unknown, range missing, etc)."""
    __tablename__ = "probable_exposures"

    id = Column(Integer, primary_key=True, autoincrement=True)
    customer_id = Column(Integer, ForeignKey("customers.id", ondelete="CASCADE"), nullable=False)
    exposure_type = Column(String(50), nullable=False)   # probable_cve, unknown_version, llm_inferred_match
    cve_id = Column(String(30), nullable=True)
    product_name = Column(String(200), nullable=True)
    source_detail = Column(Text, nullable=True)
    confidence = Column(Float, default=0.5)
    risk_points = Column(Float, default=0.0)
    created_at = Column(DateTime(timezone=True), default=_utcnow)

    __table_args__ = (Index("ix_probexp_customer", "customer_id"),)


# ═══════════════════════════════════════════════════════════════════════════
# Sigma rules (slice 4.7)
# ═══════════════════════════════════════════════════════════════════════════

class SigmaRule(Base):
    """Community Sigma rules synced from github.com/SigmaHQ/sigma.

    cve_refs and attack_techniques use JSONB (not the plain JSON used
    elsewhere in this schema) because they need GIN-indexed containment
    queries (`.contains([...])`) for rule_matcher's CVE/ATT&CK lookups —
    a plain `json` column can't back a GIN index on Postgres.
    """
    __tablename__ = "sigma_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    rule_uuid = Column(String(40), nullable=False, unique=True)  # UUID from Sigma YAML `id` field
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    level = Column(String(20), nullable=True)     # low/medium/high/critical
    status = Column(String(20), nullable=True)    # stable/test/experimental/deprecated
    author = Column(String(500), nullable=True)

    # For matching:
    cve_refs = Column(JSONB, default=list)              # ["CVE-2022-42475", ...]
    attack_techniques = Column(JSONB, default=list)     # ["T1190", "T1210", ...]
    product = Column(String(120), nullable=True)        # logsource.product
    service = Column(String(120), nullable=True)        # logsource.service
    category = Column(String(120), nullable=True)       # logsource.category

    raw_yaml = Column(Text, nullable=False)             # full YAML content
    source_path = Column(String(500), nullable=True)    # rules/windows/xxx.yml
    sha256 = Column(String(64), nullable=False)         # for change detection

    indexed_at = Column(DateTime(timezone=True), default=_utcnow)

    __table_args__ = (
        Index("ix_sigma_cve", "cve_refs", postgresql_using="gin"),
        Index("ix_sigma_attack", "attack_techniques", postgresql_using="gin"),
        Index("ix_sigma_level_status", "level", "status"),
        Index("ix_sigma_product", "product"),
    )


# ═══════════════════════════════════════════════════════════════════════════
# Alert dispatch (slice 5A)
# ═══════════════════════════════════════════════════════════════════════════

class AlertQueue(Base):
    """Pending alert dispatches. Bot 1 (telegram/bot_alert.py) worker pulls
    from here — customer_router only ever pushes rows, never sends
    Telegram messages itself."""
    __tablename__ = "alert_queue"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    finding_id = Column(BigInteger, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)

    state = Column(String(20), default="pending", nullable=False)
            # pending → dispatching → dispatched | deduped | batched | failed
    dispatch_reason = Column(Text, nullable=True)
            # e.g. "severity=HIGH" or "MEDIUM+2sources"

    # Dedup tracking
    dedupe_key = Column(String(200), nullable=False)
            # hash of (customer_id, ioc_value, asset_id) for lookup
    deduped_of_id = Column(BigInteger, ForeignKey("alert_queue.id"), nullable=True)
            # if state=deduped, points to the alert_queue row this merged into

    # Batch tracking
    batch_id = Column(BigInteger, ForeignKey("alert_batch.id"), nullable=True)

    # Retry
    attempt_count = Column(Integer, default=0)
    last_error = Column(Text, nullable=True)
    next_retry_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), default=_utcnow)
    dispatched_at = Column(DateTime(timezone=True), nullable=True)

    # Result of dispatch (set after send)
    telegram_message_id = Column(BigInteger, nullable=True)

    __table_args__ = (
        Index("ix_alertq_state_next", "state", "next_retry_at"),
        Index("ix_alertq_dedupe", "dedupe_key", "created_at"),
        Index("ix_alertq_customer_created", "customer_id", "created_at"),
    )


class AlertBatch(Base):
    """Groups multiple alerts into one Telegram message when spike."""
    __tablename__ = "alert_batch"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)
    finding_count = Column(Integer, default=0)
    severities = Column(JSON, default=dict)  # {"CRITICAL": 1, "HIGH": 3}
    created_at = Column(DateTime(timezone=True), default=_utcnow)
    dispatched_at = Column(DateTime(timezone=True), nullable=True)
    telegram_message_id = Column(BigInteger, nullable=True)

    __table_args__ = (
        Index("ix_alertbatch_customer_created", "customer_id", "created_at"),
    )


class CommandLog(Base):
    """Audit log for Bot 2 (analyst command bot) commands. Empty in slice
    5A; populated starting slice 5B."""
    __tablename__ = "command_log"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    telegram_user_id = Column(BigInteger, nullable=False)
    telegram_username = Column(String(100), nullable=True)
    command = Column(String(50), nullable=False)
    args = Column(JSON, default=dict)
    result_status = Column(String(20), nullable=True)  # ok/rejected/error
    result_summary = Column(Text, nullable=True)
    error = Column(Text, nullable=True)
    latency_ms = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)

    __table_args__ = (
        Index("ix_cmdlog_user_created", "telegram_user_id", "created_at"),
        Index("ix_cmdlog_command", "command"),
    )


class PlaybookCache(Base):
    """LLM-generated playbook cache keyed by (cve_id, network_segment).
    Empty in slice 5A; populated starting slice 5C."""
    __tablename__ = "playbook_cache"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(30), nullable=False)
    network_segment = Column(String(30), nullable=True)  # dmz/ot_control/... or NULL
    playbook_md = Column(Text, nullable=False)           # markdown content
    model_used = Column(String(80), nullable=True)
    generated_at = Column(DateTime(timezone=True), default=_utcnow)
    reused_count = Column(Integer, default=0)

    __table_args__ = (
        UniqueConstraint("cve_id", "network_segment", name="uq_playbook_cve_seg"),
    )


class AgentSession(Base):
    """Short-term memory for a Telegram user's agentic chat.

    state stores structured context (last customer/CVE/finding/asset/IOC
    + last result IDs + filters). conversation_history stores turn list
    for LLM context.
    """
    __tablename__ = "agent_sessions"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    telegram_user_id = Column(BigInteger, nullable=False)
    state = Column(JSON, default=dict)
    conversation_history = Column(JSON, default=list)
    last_active = Column(DateTime(timezone=True), default=_utcnow,
                          nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow,
                         nullable=False)

    __table_args__ = (
        Index("ix_agent_user_active", "telegram_user_id", "last_active"),
    )


# ═══════════════════════════════════════════════════════════════════════════
# Campaign detection (slice 6.2A)
# ═══════════════════════════════════════════════════════════════════════════

class CampaignStatus(str, enum.Enum):
    CANDIDATE = "candidate"     # detected, awaiting analyst review
    CONFIRMED = "confirmed"     # analyst confirmed as real campaign
    REJECTED = "rejected"       # analyst confirmed NOT campaign
    EXPIRED = "expired"         # 7 days without decision -> auto-expire


class Campaign(Base):
    """Detected attack campaign (cluster of related findings)."""
    __tablename__ = "campaigns"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)

    # Detection window
    window_start = Column(DateTime(timezone=True), nullable=False)
    window_end = Column(DateTime(timezone=True), nullable=False)

    # Aggregated features
    finding_count = Column(Integer, default=0)
    asset_count = Column(Integer, default=0)
    technique_ids = Column(JSON, default=list)      # ["T1190", "T1059"]
    tactic_ids = Column(JSON, default=list)          # ["initial-access", "execution"]
    source_ids = Column(JSON, default=list)          # ["nvd", "threatfox"]
    severities = Column(JSON, default=dict)          # {"HIGH": 3, "MEDIUM": 2}

    # Detection scoring
    confidence = Column(Float, nullable=False)
    detection_reason = Column(Text, nullable=True)
    # e.g. "5 findings, 6h window, T1190 overlap 80%, 4 assets, 2 sources"

    # Lifecycle
    # Plain String (not SAEnum) — matches AlertQueue.state's pattern: the
    # DDL below creates this column as VARCHAR, not a Postgres native enum
    # type, so a SAEnum column here would emit `::campaignstatus` casts
    # against a type that was never created.
    status = Column(String(20), default=CampaignStatus.CANDIDATE.value, nullable=False)
    reviewed_by = Column(String(120), nullable=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    review_notes = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    __table_args__ = (
        Index("ix_campaign_customer_status", "customer_id", "status"),
        Index("ix_campaign_status_created", "status", "created_at"),
    )


class CampaignFinding(Base):
    """Many-to-many between Campaign and Finding."""
    __tablename__ = "campaign_findings"
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    campaign_id = Column(BigInteger, ForeignKey("campaigns.id", ondelete="CASCADE"),
                          nullable=False)
    finding_id = Column(BigInteger, ForeignKey("findings.id"), nullable=False)
    added_at = Column(DateTime(timezone=True), default=_utcnow)

    __table_args__ = (
        UniqueConstraint("campaign_id", "finding_id", name="uq_campaign_finding"),
        Index("ix_cf_finding", "finding_id"),
    )


# ═══════════════════════════════════════════════════════════════════════════
# Article ingestion (slice 7A)
# ═══════════════════════════════════════════════════════════════════════════

class IngestionStatus(str, enum.Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    EXPIRED = "expired"   # 24h no action


class IngestionSource(str, enum.Enum):
    URL = "url"
    TEXT = "text"
    PDF = "pdf"


class IngestionSession(Base):
    """Analyst-driven article ingestion for data enrichment.

    Flow:
      1. Analyst /ingest URL/text/PDF -> PENDING
      2. LLM extracts IOCs/CVEs/malware/techniques
      3. Analyst reviews preview -> confirm/reject/edit
      4. On CONFIRMED (7B): creates Detections + auto-fetches missing CVEs
         + triggers matcher -> potentially Findings
    """
    __tablename__ = "ingestion_sessions"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    telegram_user_id = Column(BigInteger, nullable=False)
    telegram_username = Column(String(100), nullable=True)

    source_type = Column(String(10), nullable=False)  # url/text/pdf
    source_url = Column(String(2000), nullable=True)
    source_text = Column(Text, nullable=True)  # truncated to 8000 chars
    source_filename = Column(String(500), nullable=True)  # for PDFs

    # LLM output — see ati_evn.ingestion.extractor.EXTRACTION_SYSTEM for schema
    extracted_data = Column(JSON, default=dict)

    extraction_model = Column(String(80), nullable=True)
    extraction_error = Column(Text, nullable=True)  # if LLM failed

    # State — plain String, not SAEnum (see Campaign.status comment above
    # for why: avoids emitting `::ingestionstatus` casts against a type
    # that was never created in Postgres).
    status = Column(String(20), nullable=False, default=IngestionStatus.PENDING.value)
    confirmed_at = Column(DateTime(timezone=True), nullable=True)
    rejected_at = Column(DateTime(timezone=True), nullable=True)
    rejected_reason = Column(Text, nullable=True)

    # Downstream links (populated in 7B on confirm)
    detection_ids_created = Column(JSON, default=list)
    finding_ids_created = Column(JSON, default=list)

    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        Index("ix_ingest_user_status", "telegram_user_id", "status"),
        Index("ix_ingest_expires", "expires_at", "status"),
    )


# ═══════════════════════════════════════════════════════════════════════════
# External exposure monitoring — Censys (slice 9A)
# ═══════════════════════════════════════════════════════════════════════════

class ExposureStatus(str, enum.Enum):
    ACTIVE = "active"             # last seen recently
    DISAPPEARED = "disappeared"   # was seen but not in latest scan
    STALE = "stale"               # not scanned in >30d


class Exposure(Base):
    """Raw observation of an internet-facing service, as seen by Censys.

    One row per (ip, port, service_name) tuple. Rescanning updates
    last_seen_local in place rather than inserting a duplicate.

    Attribution:
      - asset_id populated if the IP matches a CustomerAsset (exact IP
        or CIDR containment)
      - customer_id denormalized from the asset for query speed
      - If the IP has no matching asset, asset_id is NULL unless the
        caller opts into auto-discovery (see external/attribution.py)

    Finding linkage (9B): Exposures are raw data; Findings are derived
    by a rule engine that hasn't landed yet. A single Exposure may
    spawn 0-N Findings depending on rules.
    """
    __tablename__ = "exposures"

    id = Column(BigInteger, primary_key=True, autoincrement=True)

    ip = Column(String(45), nullable=False)  # v4 or v6
    port = Column(Integer, nullable=False)
    service_name = Column(String(60), nullable=True)  # http, ssh, dns, ...
    transport = Column(String(10), nullable=True)      # tcp, udp

    # Service metadata (from Censys)
    product = Column(String(120), nullable=True)
    version = Column(String(80), nullable=True)
    vendor = Column(String(120), nullable=True)
    banner = Column(Text, nullable=True)  # truncated to 2000 chars

    # Configuration signals (used by 9B rule engine)
    tls_enabled = Column(Boolean, default=False)
    tls_version = Column(String(20), nullable=True)
    tls_expired = Column(Boolean, default=False)
    tls_self_signed = Column(Boolean, default=False)
    auth_required = Column(Boolean, nullable=True)  # NULL if unknown
    capabilities = Column(JSON, default=dict)
    # e.g. {"http.default_page": true, "http.directory_listing": true}

    # Attribution
    asset_id = Column(BigInteger, ForeignKey("customer_assets.id"), nullable=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=True)
    asn = Column(String(20), nullable=True)
    asn_organization = Column(String(200), nullable=True)
    country = Column(String(80), nullable=True)

    # Timeline
    first_seen_censys = Column(DateTime(timezone=True), nullable=True)
    last_seen_censys = Column(DateTime(timezone=True), nullable=True)
    first_seen_local = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_seen_local = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    # Plain String, not SAEnum — see Campaign.status comment above for why.
    status = Column(String(20), nullable=False, default=ExposureStatus.ACTIVE.value)

    censys_raw = Column(JSON, default=dict)  # full Censys service dict

    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint("ip", "port", "service_name", name="uq_exposure_ip_port_svc"),
        Index("ix_exposure_asset", "asset_id"),
        Index("ix_exposure_customer", "customer_id"),
        Index("ix_exposure_ip", "ip"),
        Index("ix_exposure_status_last_seen", "status", "last_seen_local"),
    )
