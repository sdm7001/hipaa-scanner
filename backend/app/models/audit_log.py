"""Append-only audit log model for HIPAA compliance tracking."""

import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column
from ..database import Base


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    # Who performed the action
    user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)   # null for unauthenticated
    user_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    msp_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    # What was done
    action: Mapped[str] = mapped_column(String(100), nullable=False)         # e.g. "CREATE_USER", "DELETE_CLIENT"
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)  # e.g. "user", "client", "scan"
    resource_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    # Request details
    http_method: Mapped[str] = mapped_column(String(10), nullable=False)
    path: Mapped[str] = mapped_column(String(500), nullable=False)
    status_code: Mapped[int | None] = mapped_column(nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # Payload snapshot (sanitized — no passwords)
    request_body: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # When
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
