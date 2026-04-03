"""
Audit log API — read-only, MSP Admin only.
HIPAA 164.312(b): Audit Controls — access logs must be reviewable.
"""

from __future__ import annotations
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from pydantic import BaseModel
from ...database import get_db
from ...models import User
from ...models.audit_log import AuditLog
from ...auth.dependencies import require_msp_admin

router = APIRouter(prefix="/audit-log", tags=["Audit Log"])


class AuditLogEntry(BaseModel):
    id: str
    user_id: Optional[str]
    user_email: Optional[str]
    action: str
    resource_type: str
    resource_id: Optional[str]
    http_method: str
    path: str
    status_code: Optional[int]
    ip_address: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class AuditLogResponse(BaseModel):
    items: list[AuditLogEntry]
    total: int
    page: int
    page_size: int


@router.get("/", response_model=AuditLogResponse)
async def list_audit_log(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    action: Optional[str] = Query(None, description="Filter by action prefix, e.g. CREATE_USER"),
    resource_type: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
    from_date: Optional[datetime] = Query(None),
    to_date: Optional[datetime] = Query(None),
    current_user: User = Depends(require_msp_admin),
    db: AsyncSession = Depends(get_db),
) -> AuditLogResponse:
    """
    List audit log entries for the current MSP (most recent first).
    Filtered to the current user's msp_id.
    """
    conditions = [AuditLog.msp_id == current_user.msp_id]

    if action:
        conditions.append(AuditLog.action.ilike(f"{action}%"))
    if resource_type:
        conditions.append(AuditLog.resource_type == resource_type)
    if user_id:
        conditions.append(AuditLog.user_id == user_id)
    if from_date:
        conditions.append(AuditLog.created_at >= from_date)
    if to_date:
        conditions.append(AuditLog.created_at <= to_date)

    # Count total
    count_q = select(AuditLog).where(and_(*conditions))
    count_result = await db.execute(count_q)
    total = len(count_result.scalars().all())

    # Paginated results
    offset = (page - 1) * page_size
    result = await db.execute(
        select(AuditLog)
        .where(and_(*conditions))
        .order_by(AuditLog.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    items = result.scalars().all()

    return AuditLogResponse(
        items=[AuditLogEntry.model_validate(e) for e in items],
        total=total,
        page=page,
        page_size=page_size,
    )
