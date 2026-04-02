"""PDF report generation routes."""

from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ...database import get_db
from ...models import Scan, Finding, Client
from ...auth.dependencies import require_any_user
from ...models.user import User
from ...services.report_gen import generate_report

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("/{scan_id}/generate")
async def generate_scan_report(
    scan_id: str,
    report_type: str = Query(default="executive", pattern="^(executive|technical)$"),
    current_user: User = Depends(require_any_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate a PDF report for a scan. Returns PDF bytes."""
    # Verify access
    scan_result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.msp_id == current_user.msp_id)
    )
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Load client
    client_result = await db.execute(select(Client).where(Client.id == scan.client_id))
    client = client_result.scalar_one_or_none()

    # Load findings
    findings_result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.severity, Finding.category)
    )
    findings = findings_result.scalars().all()

    pdf_bytes = await generate_report(
        scan=scan,
        client=client,
        findings=findings,
        report_type=report_type,
    )

    filename = f"hipaa-report-{client.name if client else scan_id}-{report_type}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
