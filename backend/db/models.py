"""Relational persistence model. Public API contracts live in backend/schemas."""

from __future__ import annotations

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.db.base import Base


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    role: Mapped[str] = mapped_column(String(40), default="analyst", server_default="analyst")
    active: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"))
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    locked_until: Mapped[str | None] = mapped_column(String(40), nullable=True)
    created_at: Mapped[str] = mapped_column(String(40))


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        CheckConstraint("kind IN ('Website','Server')", name="ck_assets_kind"),
        CheckConstraint(
            "compliance IS NULL OR (compliance >= 0 AND compliance <= 100)",
            name="ck_assets_compliance",
        ),
        Index("ix_assets_kind_class_status", "kind", "classification", "status"),
    )
    id: Mapped[str] = mapped_column(String(120), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    kind: Mapped[str] = mapped_column(String(20))
    classification: Mapped[str] = mapped_column(
        String(40), default="Unknown", server_default="Unknown"
    )
    owner: Mapped[str] = mapped_column(String(255), default="", server_default="")
    environment: Mapped[str] = mapped_column(
        String(80), default="Unknown", server_default="Unknown"
    )
    criticality: Mapped[str] = mapped_column(String(20), default="Medium", server_default="Medium")
    compliance: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(40), default="Active", server_default="Active")
    waf: Mapped[str | None] = mapped_column(String(40), nullable=True)
    source: Mapped[str] = mapped_column(String(80), default="manual", server_default="manual")
    source_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    attributes: Mapped[str] = mapped_column(Text, default="{}", server_default="{}")
    created_at: Mapped[str] = mapped_column(String(40))
    updated_at: Mapped[str] = mapped_column(String(40))
    findings: Mapped[list[Finding]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("source", "source_finding_id", "asset_id", name="uq_findings_source_ref"),
        Index("ix_findings_asset_state_severity_due", "asset_id", "state", "severity", "due_at"),
    )
    id: Mapped[str] = mapped_column(String(150), primary_key=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    source: Mapped[str] = mapped_column(String(80), default="manual", server_default="manual")
    source_finding_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    title: Mapped[str] = mapped_column(String(500))
    cve: Mapped[str | None] = mapped_column(String(40), nullable=True)
    severity: Mapped[str] = mapped_column(String(24))
    state: Mapped[str] = mapped_column(String(40), default="Open", server_default="Open")
    first_seen: Mapped[str | None] = mapped_column(String(40), nullable=True)
    last_seen: Mapped[str | None] = mapped_column(String(40), nullable=True)
    due_at: Mapped[str | None] = mapped_column(String(40), nullable=True)
    evidence: Mapped[str] = mapped_column(Text, default="{}", server_default="{}")
    created_at: Mapped[str] = mapped_column(String(40))
    updated_at: Mapped[str] = mapped_column(String(40))
    asset: Mapped[Asset] = relationship(back_populates="findings")
    cve_links: Mapped[list[FindingCVE]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class FindingCVE(Base):
    """Normalized CVE references attached to a provider or manually created finding."""

    __tablename__ = "finding_cves"
    __table_args__ = (Index("ix_finding_cves_cve", "cve"),)

    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True
    )
    cve: Mapped[str] = mapped_column(String(40), primary_key=True)
    finding: Mapped[Finding] = relationship(back_populates="cve_links")


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_events_created_at", "created_at"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(120))
    object_type: Mapped[str] = mapped_column(String(80))
    object_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    detail: Mapped[str] = mapped_column(Text, default="{}", server_default="{}")
    created_at: Mapped[str] = mapped_column(String(40))
    previous_hash: Mapped[str] = mapped_column(String(64), default="", server_default="")
    entry_hash: Mapped[str] = mapped_column(String(64), default="", server_default="")


class AuditChainHead(Base):
    __tablename__ = "audit_chain_heads"
    chain_name: Mapped[str] = mapped_column(String(80), primary_key=True)
    entry_hash: Mapped[str] = mapped_column(String(64), default="", server_default="")


class Session(Base):
    __tablename__ = "sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    expires_at: Mapped[str] = mapped_column(String(40), index=True)
    created_at: Mapped[str] = mapped_column(String(40))
    family_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    revoked_at: Mapped[str | None] = mapped_column(String(40), nullable=True)


class RefreshSession(Base):
    __tablename__ = "refresh_sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    family_id: Mapped[str] = mapped_column(String(64), index=True)
    expires_at: Mapped[str] = mapped_column(String(40), index=True)
    created_at: Mapped[str] = mapped_column(String(40))
    replaced_by_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    revoked_at: Mapped[str | None] = mapped_column(String(40), nullable=True)


class SyncRun(Base):
    __tablename__ = "sync_runs"
    __table_args__ = (
        Index(
            "uq_sync_runs_active_source",
            "source",
            unique=True,
            sqlite_where=text("status IN ('queued', 'running')"),
            postgresql_where=text("status IN ('queued', 'running')"),
        ),
    )
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    source: Mapped[str] = mapped_column(String(80), index=True)
    status: Mapped[str] = mapped_column(String(40))
    started_at: Mapped[str] = mapped_column(String(40))
    finished_at: Mapped[str | None] = mapped_column(String(40), nullable=True)
    records_read: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    records_written: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class ExceptionRequest(Base):
    __tablename__ = "exception_requests"
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[str | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True
    )
    requested_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    reason: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[str] = mapped_column(String(40), index=True)
    status: Mapped[str] = mapped_column(
        String(40), default="Pending", server_default="Pending", index=True
    )
    reviewed_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    review_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(40))
    updated_at: Mapped[str] = mapped_column(String(40))


class ContainmentAction(Base):
    __tablename__ = "containment_actions"
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    action: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(60), index=True)
    impact: Mapped[str] = mapped_column(Text)
    requested_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    approved_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[str] = mapped_column(String(40))
    updated_at: Mapped[str] = mapped_column(String(40))


class WorkflowRequest(Base):
    __tablename__ = "workflow_requests"
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    kind: Mapped[str] = mapped_column(String(60), index=True)
    asset_id: Mapped[str | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    finding_id: Mapped[str | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(40), default="Pending", server_default="Pending", index=True
    )
    payload: Mapped[str] = mapped_column(Text, default="{}", server_default="{}")
    requested_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[str] = mapped_column(String(40))
    updated_at: Mapped[str] = mapped_column(String(40))


class ZeroDaySignal(Base):
    __tablename__ = "zero_day_signals"
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    title: Mapped[str] = mapped_column(String(500))
    severity: Mapped[str] = mapped_column(String(24))
    confidence: Mapped[str] = mapped_column(String(24))
    status: Mapped[str] = mapped_column(String(40), index=True)
    source: Mapped[str] = mapped_column(String(120))
    evidence: Mapped[str] = mapped_column(Text, default="{}", server_default="{}")
    created_at: Mapped[str] = mapped_column(String(40))


class ThreatIntelRecord(Base):
    __tablename__ = "threat_intel_records"
    __table_args__ = (
        CheckConstraint(
            "epss_score IS NULL OR (epss_score >= 0 AND epss_score <= 1)",
            name="ck_threat_intel_epss_score",
        ),
        CheckConstraint(
            "epss_percentile IS NULL OR (epss_percentile >= 0 AND epss_percentile <= 1)",
            name="ck_threat_intel_epss_percentile",
        ),
        Index("ix_threat_intel_kev_epss", "kev_listed", "epss_score"),
    )

    cve: Mapped[str] = mapped_column(String(40), primary_key=True)
    kev_listed: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))
    kev_catalog_version: Mapped[str | None] = mapped_column(String(80), nullable=True)
    kev_date_added: Mapped[str | None] = mapped_column(String(10), nullable=True)
    kev_due_date: Mapped[str | None] = mapped_column(String(10), nullable=True)
    kev_vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    kev_product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    kev_vulnerability_name: Mapped[str | None] = mapped_column(String(500), nullable=True)
    kev_short_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    kev_required_action: Mapped[str | None] = mapped_column(Text, nullable=True)
    kev_ransomware_use: Mapped[str | None] = mapped_column(String(32), nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_date: Mapped[str | None] = mapped_column(String(10), nullable=True)
    updated_at: Mapped[str] = mapped_column(String(40))


class ImportJob(Base):
    __tablename__ = "import_jobs"
    __table_args__ = (Index("uq_import_jobs_idempotency", "idempotency_hash", unique=True),)
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    source: Mapped[str] = mapped_column(String(80), index=True)
    status: Mapped[str] = mapped_column(String(40), index=True)
    filename: Mapped[str] = mapped_column(String(255))
    job_type: Mapped[str] = mapped_column(String(24), default="import", server_default="import")
    input_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    column_mapping: Mapped[str] = mapped_column(Text, default="{}", server_default="{}")
    task_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    idempotency_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    request_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    total_rows: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    processed_rows: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    rejected_rows: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    result_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    error_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(40))
    updated_at: Mapped[str] = mapped_column(String(40))


class IdempotencyRecord(Base):
    __tablename__ = "idempotency_records"
    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    operation: Mapped[str] = mapped_column(String(120))
    response_status: Mapped[int] = mapped_column(Integer)
    response_body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(String(40), index=True)


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    expires_at: Mapped[str] = mapped_column(String(40), index=True)
    used_at: Mapped[str | None] = mapped_column(String(40), nullable=True)
    created_at: Mapped[str] = mapped_column(String(40))


class TicketLink(Base):
    __tablename__ = "ticket_links"
    __table_args__ = (
        UniqueConstraint("correlation_id", name="uq_ticket_links_correlation"),
        UniqueConstraint("idempotency_hash", name="uq_ticket_links_idempotency"),
        Index("ix_ticket_links_finding_created", "finding_ref", "created_at"),
        CheckConstraint(
            "status IN ('processing','created','failed','unknown')", name="ck_ticket_links_status"
        ),
    )

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    finding_id: Mapped[str | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True
    )
    asset_id: Mapped[str | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    finding_ref: Mapped[str] = mapped_column(String(150))
    asset_ref: Mapped[str] = mapped_column(String(120))
    source: Mapped[str] = mapped_column(
        String(40), default="servicenow", server_default="servicenow"
    )
    correlation_id: Mapped[str] = mapped_column(String(40))
    idempotency_hash: Mapped[str] = mapped_column(String(64))
    request_hash: Mapped[str] = mapped_column(String(64))
    external_sys_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    external_number: Mapped[str | None] = mapped_column(String(80), nullable=True)
    status: Mapped[str] = mapped_column(
        String(24), default="processing", server_default="processing"
    )
    error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    requested_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[str] = mapped_column(String(40))
    updated_at: Mapped[str] = mapped_column(String(40))


class ExternalDiscoveryTarget(Base):
    """Explicitly authorized DNS domains monitored through passive CT data."""

    __tablename__ = "external_discovery_targets"
    __table_args__ = (
        UniqueConstraint("domain", name="uq_external_discovery_targets_domain"),
        Index("ix_external_discovery_targets_active_domain", "active", "domain"),
    )

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    domain: Mapped[str] = mapped_column(String(253), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"))
    authorization_note: Mapped[str] = mapped_column(Text)
    authorized_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[str] = mapped_column(String(40))
    updated_at: Mapped[str] = mapped_column(String(40))
    last_run_at: Mapped[str | None] = mapped_column(String(40), nullable=True)


class ExternalDiscoveryRun(Base):
    """Durable status for a bounded pass through a passive certificate-transparency feed."""

    __tablename__ = "external_discovery_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('queued','running','completed','failed')",
            name="ck_external_discovery_runs_status",
        ),
        Index("ix_external_discovery_runs_target_started", "target_id", "started_at"),
        Index(
            "uq_external_discovery_runs_active_target",
            "target_id",
            unique=True,
            sqlite_where=text("status IN ('queued', 'running')"),
            postgresql_where=text("status IN ('queued', 'running')"),
        ),
    )

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    target_id: Mapped[str] = mapped_column(
        ForeignKey("external_discovery_targets.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(24), index=True)
    started_at: Mapped[str] = mapped_column(String(40))
    finished_at: Mapped[str | None] = mapped_column(String(40), nullable=True)
    pages_read: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    records_read: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    candidates_created: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    candidates_updated: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class DiscoveredExternalAsset(Base):
    """Certificate-transparency hostname awaiting an operator decision."""

    __tablename__ = "discovered_external_assets"
    __table_args__ = (
        UniqueConstraint("target_id", "hostname", name="uq_discovered_external_target_hostname"),
        CheckConstraint(
            "status IN ('pending_review','accepted','dismissed')",
            name="ck_discovered_external_assets_status",
        ),
        Index("ix_discovered_external_status_last_seen", "status", "last_seen_at"),
    )

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    target_id: Mapped[str] = mapped_column(
        ForeignKey("external_discovery_targets.id", ondelete="CASCADE"), index=True
    )
    hostname: Mapped[str] = mapped_column(String(253), nullable=False)
    status: Mapped[str] = mapped_column(
        String(24), default="pending_review", server_default="pending_review"
    )
    first_seen_at: Mapped[str] = mapped_column(String(40))
    last_seen_at: Mapped[str] = mapped_column(String(40))
    evidence: Mapped[str] = mapped_column(Text, default="{}", server_default="{}")
    last_run_id: Mapped[str | None] = mapped_column(
        ForeignKey("external_discovery_runs.id", ondelete="SET NULL"), nullable=True
    )
    asset_id: Mapped[str | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True
    )
    reviewed_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    reviewed_at: Mapped[str | None] = mapped_column(String(40), nullable=True)
    review_note: Mapped[str | None] = mapped_column(Text, nullable=True)
