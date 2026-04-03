"""API key management — get, rotate the MSP scanner API key."""

from __future__ import annotations
import secrets
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from ...database import get_db
from ...models.user import User, UserRole, MspOrganization
from ...auth.dependencies import get_current_user

router = APIRouter(prefix="/api-keys", tags=["api-keys"])


def _require_msp_admin(current_user: User) -> User:
    if current_user.role != UserRole.MSP_ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="MSP admin role required")
    return current_user


class ApiKeyResponse(BaseModel):
    api_key: str
    msp_name: str
    note: str = "Keep this key secret — it allows scanner uploads to your MSP account."


@router.get("/", response_model=ApiKeyResponse)
async def get_api_key(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return the current MSP API key. Requires msp_admin role."""
    _require_msp_admin(current_user)

    result = await db.execute(
        select(MspOrganization).where(MspOrganization.id == current_user.msp_id)
    )
    msp: MspOrganization | None = result.scalar_one_or_none()
    if not msp:
        raise HTTPException(status_code=404, detail="MSP organization not found")

    return ApiKeyResponse(api_key=msp.api_key, msp_name=msp.name)


@router.post("/rotate", response_model=ApiKeyResponse)
async def rotate_api_key(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate a new API key, invalidating the old one immediately. Requires msp_admin role."""
    _require_msp_admin(current_user)

    result = await db.execute(
        select(MspOrganization).where(MspOrganization.id == current_user.msp_id)
    )
    msp: MspOrganization | None = result.scalar_one_or_none()
    if not msp:
        raise HTTPException(status_code=404, detail="MSP organization not found")

    new_key = secrets.token_urlsafe(32)
    msp.api_key = new_key
    await db.commit()

    return ApiKeyResponse(
        api_key=new_key,
        msp_name=msp.name,
        note="New API key generated. Update your scanner configuration immediately — the old key is now invalid.",
    )
