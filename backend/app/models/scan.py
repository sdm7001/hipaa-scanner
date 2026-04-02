"""Scan, Host, Finding, and Remediation models."""

import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Float, Boolean, DateTime, ForeignKey, Text, JSON, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from ..database import Base
import enum


class ScanStatus(str, enum.Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanProfile(str, enum.Enum):
    FULL = "full"
    QUICK = "quick"
    PHI_ONLY = "phi_only"
    CUSTOM = "custom"


class FindingSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    REMEDIATED = "remediated"
    RISK_ACCEPTED = "risk_accepted"
    NOT_APPLICABLE = "not_applicable"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    client_id: Mapped[str] = mapped_column(String(36), ForeignKey("clients.id"), nullable=False)
    msp_id: Mapped[str] = mapped_column(String(36), ForeignKey("msp_organizations.id"), nullable=False)
    scanner_version: Mapped[str] = mapped_column(String(20), nullable=False)
    profile: Mapped[ScanProfile] = mapped_column(SAEnum(ScanProfile), default=ScanProfile.FULL)
    environment_type: Mapped[str] = mapped_column(String(50), nullable=False)  # active_directory / workgroup
    status: Mapped[ScanStatus] = mapped_column(SAEnum(ScanStatus), default=ScanStatus.COMPLETED)
    overall_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False, default="UNKNOWN")
    hosts_scanned: Mapped[int] = mapped_column(Integer, default=0)
    hosts_failed: Mapped[int] = mapped_column(Integer, default=0)
    total_checks: Mapped[int] = mapped_column(Integer, default=0)
    checks_passed: Mapped[int] = mapped_column(Integer, default=0)
    checks_failed: Mapped[int] = mapped_column(Integer, default=0)
    findings_critical: Mapped[int] = mapped_column(Integer, default=0)
    findings_high: Mapped[int] = mapped_column(Integer, default=0)
    findings_medium: Mapped[int] = mapped_column(Integer, default=0)
    findings_low: Mapped[int] = mapped_column(Integer, default=0)
    is_baseline: Mapped[bool] = mapped_column(Boolean, default=False)
    technician_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    client: Mapped["Client"] = relationship("Client", back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="scan", lazy="select")
    hosts: Mapped[list["Host"]] = relationship("Host", back_populates="scan", lazy="select")


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(50), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_build: Mapped[str | None] = mapped_column(String(50), nullable=True)
    role: Mapped[str] = mapped_column(String(50), default="workstation")
    scan_status: Mapped[str] = mapped_column(String(20), default="completed")

    scan: Mapped["Scan"] = relationship("Scan", back_populates="hosts")
    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="host", lazy="select")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)
    host_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("hosts.id"), nullable=True)
    check_id: Mapped[str] = mapped_column(String(20), nullable=False)
    check_name: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    hipaa_reference: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[FindingSeverity] = mapped_column(SAEnum(FindingSeverity), nullable=False)
    status: Mapped[FindingStatus] = mapped_column(SAEnum(FindingStatus), default=FindingStatus.OPEN)
    result: Mapped[str] = mapped_column(String(20), nullable=False)  # pass/fail/error/na
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    details: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation_script: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    points_deducted: Mapped[float] = mapped_column(Float, default=0.0)
    assigned_to: Mapped[str | None] = mapped_column(String(255), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")
    host: Mapped[Host | None] = relationship("Host", back_populates="findings")
