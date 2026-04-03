"""User management routes — list, create, update, deactivate."""

from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, EmailStr
from ...database import get_db
from ...models.user import User, UserRole, MspOrganization
from ...auth.jwt import hash_password
from ...auth.dependencies import get_current_user

router = APIRouter(prefix="/users", tags=["users"])


def _require_msp_admin(current_user: User) -> User:
    if current_user.role != UserRole.MSP_ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="MSP admin role required")
    return current_user


class UserResponse(BaseModel):
    id: str
    email: str
    first_name: str
    last_name: str
    role: str
    msp_id: str
    client_id: str | None
    is_active: bool

    model_config = {"from_attributes": True}


class CreateUserRequest(BaseModel):
    email: EmailStr
    password: str
    first_name: str
    last_name: str
    role: UserRole = UserRole.MSP_TECH
    client_id: str | None = None


class UpdateUserRequest(BaseModel):
    first_name: str | None = None
    last_name: str | None = None
    role: UserRole | None = None
    is_active: bool | None = None
    client_id: str | None = None


@router.get("/", response_model=list[UserResponse])
async def list_users(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all users in the current MSP organization."""
    result = await db.execute(
        select(User).where(User.msp_id == current_user.msp_id).order_by(User.created_at)
    )
    return result.scalars().all()


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: CreateUserRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new user in the current MSP org. Requires msp_admin role."""
    _require_msp_admin(current_user)

    # Check email uniqueness
    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    user = User(
        msp_id=current_user.msp_id,
        client_id=body.client_id,
        email=body.email,
        hashed_password=hash_password(body.password),
        first_name=body.first_name,
        last_name=body.last_name,
        role=body.role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    body: UpdateUserRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update user fields. Requires msp_admin role."""
    _require_msp_admin(current_user)

    result = await db.execute(
        select(User).where(User.id == user_id, User.msp_id == current_user.msp_id)
    )
    user: User | None = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if body.first_name is not None:
        user.first_name = body.first_name
    if body.last_name is not None:
        user.last_name = body.last_name
    if body.role is not None:
        user.role = body.role
    if body.is_active is not None:
        user.is_active = body.is_active
    if body.client_id is not None:
        user.client_id = body.client_id

    await db.commit()
    await db.refresh(user)
    return user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_user(
    user_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Deactivate (soft-delete) a user. Requires msp_admin role."""
    _require_msp_admin(current_user)

    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")

    result = await db.execute(
        select(User).where(User.id == user_id, User.msp_id == current_user.msp_id)
    )
    user: User | None = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_active = False
    await db.commit()
