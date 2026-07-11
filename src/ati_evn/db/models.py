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

    customer = relationship("Customer", back_populates="assets")

    __table_args__ = (
        Index("ix_asset_customer_type", "customer_id", "asset_type"),
        Index("ix_asset_value", "asset_value"),
        Index("ix_asset_vendor_product", "vendor", "product"),
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
    metadata_ = Column("metadata", JSON, default=dict)

    created_at = Column(DateTime(timezone=True), default=_utcnow)

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
    """Analyst FP decisions. Next matching detection auto-closes, no dispatch."""
    __tablename__ = "fp_memory"

    id = Column(Integer, primary_key=True, autoincrement=True)
    customer_id = Column(Integer, ForeignKey("customers.id", ondelete="CASCADE"), nullable=False)
    ioc_type = Column(String(50), nullable=False)
    ioc_value_hash = Column(String(64), nullable=False)  # sha256 of normalized value
    ioc_value_sample = Column(Text, nullable=True)       # for analyst readability

    reason = Column(Text, nullable=True)
    marked_by = Column(String(120), nullable=True)
    marked_at = Column(DateTime(timezone=True), default=_utcnow)
    hit_count = Column(Integer, default=0)               # how many times this rule auto-closed a new det
    last_hit_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("customer_id", "ioc_type", "ioc_value_hash", name="uq_fp_memory"),
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
