"""Scan routes — upload from scanner, list, detail."""

from __future__ import annotations
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Header, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel
from datetime import datetime
from ...database import get_db
from ...models import Scan, Host, Finding, Client, MspOrganization, FindingStatus
from ...auth.dependencies import get_current_user, require_any_user
from ...models.user import User

router = APIRouter(prefix="/scans", tags=["scans"])


class ScanUploadPayload(BaseModel):
    """Matches ScanReport from scanner engine."""
    scanner_version: str
    scan_id: str
    client_id: str
    started_at: datetime
    completed_at: datetime | None = None
    environment_type: str
    targets_scanned: int
    targets_failed: int
    overall_score: float
    risk_level: str
    findings: list[dict]
    summary: dict | None = None


@router.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_scan(
    payload: ScanUploadPayload,
    x_scanner_api_key: Annotated[str | None, Header()] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Called by the scanner CLI after a scan completes.
    Authenticates via X-Scanner-Api-Key header (MSP API key).
    """
    if not x_scanner_api_key:
        raise HTTPException(status_code=401, detail="X-Scanner-API-Key header required")

    # Validate API key
    result = await db.execute(
        select(MspOrganization).where(
            MspOrganization.api_key == x_scanner_api_key,
            MspOrganization.is_active == True
        )
    )
    msp: MspOrganization | None = result.scalar_one_or_none()
    if not msp:
        raise HTTPException(status_code=401, detail="Invalid API key")

    # Verify client belongs to this MSP
    client_result = await db.execute(
        select(Client).where(Client.id == payload.client_id, Client.msp_id == msp.id)
    )
    client = client_result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found for this MSP")

    # Count findings by severity
    from collections import Counter
    sev_counts: Counter = Counter()
    for f in payload.findings:
        if f.get("result") == "fail":
            sev_counts[f.get("severity", "low")] += 1

    summary = payload.summary or {}

    # Create Scan record
    scan = Scan(
        id=payload.scan_id,
        client_id=payload.client_id,
        msp_id=msp.id,
        scanner_version=payload.scanner_version,
        environment_type=payload.environment_type,
        overall_score=payload.overall_score,
        risk_level=payload.risk_level,
        hosts_scanned=payload.targets_scanned,
        hosts_failed=payload.targets_failed,
        total_checks=summary.get("total_checks", len(payload.findings)),
        checks_passed=summary.get("passed", 0),
        checks_failed=summary.get("failed", 0),
        findings_critical=sev_counts["critical"],
        findings_high=sev_counts["high"],
        findings_medium=sev_counts["medium"],
        findings_low=sev_counts["low"],
        started_at=payload.started_at,
        completed_at=payload.completed_at,
    )
    db.add(scan)

    # Create Finding records (only failures + errors for storage efficiency)
    for f_data in payload.findings:
        if f_data.get("result") in ("fail", "error"):
            finding = Finding(
                scan_id=scan.id,
                check_id=f_data.get("check_id", ""),
                check_name=f_data.get("check_name", ""),
                category=f_data.get("category", ""),
                hipaa_reference=f_data.get("hipaa_reference", ""),
                severity=f_data.get("severity", "low"),
                result=f_data.get("result", "fail"),
                target=f_data.get("target", ""),
                details=f_data.get("details", ""),
                remediation=f_data.get("remediation"),
                remediation_script=f_data.get("remediation_script"),
                evidence=f_data.get("evidence", {}),
                points_deducted=f_data.get("points_deducted", 0.0),
            )
            db.add(finding)

    await db.commit()
    return {"scan_id": scan.id, "message": "Scan results uploaded successfully"}


@router.get("/")
async def list_scans(
    client_id: str | None = None,
    current_user: User = Depends(require_any_user),
    db: AsyncSession = Depends(get_db),
):
    """List scans, filtered to the current user's MSP (and client if client_admin)."""
    query = select(Scan).where(Scan.msp_id == current_user.msp_id)
    if client_id:
        query = query.where(Scan.client_id == client_id)
    if current_user.role.value == "client_admin" and current_user.client_id:
        query = query.where(Scan.client_id == current_user.client_id)
    query = query.order_by(desc(Scan.created_at)).limit(100)
    result = await db.execute(query)
    scans = result.scalars().all()
    return scans


@router.get("/{scan_id}")
async def get_scan(
    scan_id: str,
    current_user: User = Depends(require_any_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.msp_id == current_user.msp_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/findings")
async def get_scan_findings(
    scan_id: str,
    severity: str | None = None,
    status: str | None = None,
    category: str | None = None,
    current_user: User = Depends(require_any_user),
    db: AsyncSession = Depends(get_db),
):
    # Verify scan access
    scan_result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.msp_id == current_user.msp_id)
    )
    if not scan_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Scan not found")

    query = select(Finding).where(Finding.scan_id == scan_id)
    if severity:
        query = query.where(Finding.severity == severity)
    if status:
        query = query.where(Finding.status == status)
    if category:
        query = query.where(Finding.category == category)

    result = await db.execute(query.order_by(Finding.severity, Finding.category))
    return result.scalars().all()


@router.patch("/{scan_id}/findings/{finding_id}")
async def update_finding(
    scan_id: str,
    finding_id: str,
    body: dict,
    current_user: User = Depends(require_any_user),
    db: AsyncSession = Depends(get_db),
):
    """Update finding status, assigned_to, or notes."""
    result = await db.execute(
        select(Finding)
        .join(Scan)
        .where(Finding.id == finding_id, Finding.scan_id == scan_id, Scan.msp_id == current_user.msp_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    allowed = {"status", "assigned_to", "notes"}
    for key, val in body.items():
        if key in allowed:
            setattr(finding, key, val)

    # Set resolved_at when marking as remediated
    if body.get("status") == FindingStatus.REMEDIATED.value and not finding.resolved_at:
        from datetime import timezone
        finding.resolved_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(finding)
    return finding
