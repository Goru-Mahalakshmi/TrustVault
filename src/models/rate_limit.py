from datetime import datetime
from sqlalchemy import String, BigInteger, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column
from src.db.base import Base


class RateLimitBucket(Base):
    __tablename__ = "rate_limit_buckets"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    count: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
