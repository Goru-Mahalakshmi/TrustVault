import uuid
from datetime import datetime
from typing import Optional, Dict, Any
from sqlalchemy import String, BigInteger, Integer, DateTime, JSON, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column
from src.db.base import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    sequence_number: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    actor_id: Mapped[Optional[uuid.UUID]] = mapped_column(Uuid(as_uuid=True), nullable=True)
    actor_username: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    actor_role: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(32), nullable=False)
    resource_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    ip_address: Mapped[str] = mapped_column(String(64), nullable=False)
    user_agent: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)  # SUCCESS, DENIED, ERROR
    reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    row_hash: Mapped[str] = mapped_column(String(64), nullable=False)
