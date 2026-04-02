"""Client management routes (MSP users only)."""

from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from pydantic import BaseModel
from ...database import get_db
from ...models import Client, Scan
from ...auth.dependencies import require_msp_user, require_msp_admin
from ...models.user import User

router = APIRouter(prefix="/clients", tags=["clients"])


class ClientCreate(BaseModel):
    name: str
    contact_name: str | None = None
    contact_email: str | None = None
    contact_phone: str | None = None
    industry: str = "Healthcare"
    notes: str | None = None


class ClientResponse(BaseModel):
    id: str
    name: str
    contact_name: str | None
    contact_email: str | None
    industry: str | None
    is_active: bool
    latest_score: float | None = None
    latest_risk_level: str | None = None

    model_config = {"from_attributes": True}


@router.get("/")
async def list_clients(
    current_user: User = Depends(require_msp_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Client).where(
            Client.msp_id == current_user.msp_id,
            Client.is_active == True
        ).order_by(Client.name)
    )
    clients = result.scalars().all()

    # Enrich with latest scan score
    enriched = []
    for client in clients:
        scan_result = await db.execute(
            select(Scan.overall_score, Scan.risk_level)
            .where(Scan.client_id == client.id)
            .order_by(desc(Scan.completed_at))
            .limit(1)
        )
        latest = scan_result.first()
        enriched.append({
            "id": client.id,
            "name": client.name,
            "contact_name": client.contact_name,
            "contact_email": client.contact_email,
            "industry": client.industry,
            "is_active": client.is_active,
            "latest_score": latest[0] if latest else None,
            "latest_risk_level": latest[1] if latest else None,
        })
    return enriched


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_client(
    body: ClientCreate,
    current_user: User = Depends(require_msp_admin),
    db: AsyncSession = Depends(get_db),
):
    client = Client(
        msp_id=current_user.msp_id,
        **body.model_dump()
    )
    db.add(client)
    await db.commit()
    await db.refresh(client)
    return client


@router.get("/{client_id}")
async def get_client(
    client_id: str,
    current_user: User = Depends(require_msp_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Client).where(Client.id == client_id, Client.msp_id == current_user.msp_id)
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return client


@router.patch("/{client_id}")
async def update_client(
    client_id: str,
    body: dict,
    current_user: User = Depends(require_msp_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Client).where(Client.id == client_id, Client.msp_id == current_user.msp_id)
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    allowed = {"name", "contact_name", "contact_email", "contact_phone", "industry", "notes", "is_active"}
    for key, val in body.items():
        if key in allowed:
            setattr(client, key, val)

    await db.commit()
    await db.refresh(client)
    return client


@router.get("/{client_id}/dashboard")
async def get_client_dashboard(
    client_id: str,
    current_user: User = Depends(require_msp_user),
    db: AsyncSession = Depends(get_db),
):
    """Aggregate stats for a single client dashboard."""
    # Verify access
    client_result = await db.execute(
        select(Client).where(Client.id == client_id, Client.msp_id == current_user.msp_id)
    )
    if not client_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Client not found")

    # Last 5 scans for trend
    scans_result = await db.execute(
        select(Scan).where(Scan.client_id == client_id).order_by(desc(Scan.completed_at)).limit(5)
    )
    recent_scans = scans_result.scalars().all()

    return {
        "client_id": client_id,
        "recent_scans": [
            {
                "id": s.id,
                "score": s.overall_score,
                "risk_level": s.risk_level,
                "completed_at": s.completed_at,
                "hosts_scanned": s.hosts_scanned,
                "findings_critical": s.findings_critical,
                "findings_high": s.findings_high,
            }
            for s in recent_scans
        ],
        "latest_score": recent_scans[0].overall_score if recent_scans else None,
        "latest_risk_level": recent_scans[0].risk_level if recent_scans else None,
        "scan_count": len(recent_scans),
    }
