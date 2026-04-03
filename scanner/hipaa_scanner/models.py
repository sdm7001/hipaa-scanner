"""Shared data models for the scanner engine."""

from __future__ import annotations
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field
import uuid
from datetime import datetime


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CheckResult(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


class EnvironmentType(str, Enum):
    ACTIVE_DIRECTORY = "active_directory"
    WORKGROUP = "workgroup"


class TargetRole(str, Enum):
    WORKSTATION = "workstation"
    SERVER = "server"
    DOMAIN_CONTROLLER = "domain_controller"


class Target(BaseModel):
    hostname: str
    ip_address: str
    role: TargetRole = TargetRole.WORKSTATION
    os_version: Optional[str] = None
    os_build: Optional[str] = None


class Finding(BaseModel):
    check_id: str
    check_name: str
    category: str
    hipaa_reference: str
    severity: Severity
    result: CheckResult
    target: str
    details: str
    remediation: str
    remediation_script: Optional[str] = None  # PowerShell one-liner if available
    evidence: dict[str, Any] = Field(default_factory=dict)
    points_deducted: float = 0.0


class CategoryScore(BaseModel):
    category: str
    score: float
    weight: float
    findings_critical: int = 0
    findings_high: int = 0
    findings_medium: int = 0
    findings_low: int = 0
    findings_pass: int = 0


class ScanSummary(BaseModel):
    total_checks: int
    passed: int
    failed: int
    errors: int
    not_applicable: int
    by_severity: dict[str, int]
    by_category: dict[str, dict[str, int]]


class ScanReport(BaseModel):
    scanner_version: str
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    msp_api_key: Optional[str] = None
    client_id: Optional[str] = None
    started_at: datetime
    completed_at: Optional[datetime] = None
    environment_type: EnvironmentType
    targets_scanned: int = 0
    targets_failed: int = 0
    overall_score: float = 0.0
    risk_level: str = "UNKNOWN"
    targets: list[Target] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    category_scores: list[CategoryScore] = Field(default_factory=list)
    summary: Optional[ScanSummary] = None
