import uuid
from datetime import datetime
from typing import Literal, Optional
from pydantic import BaseModel, ConfigDict, EmailStr, Field, model_validator

class GrantCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    grantee_email: EmailStr
    level: Literal["read", "edit"] = "read"
    expires_at: Optional[datetime] = None

class TransferRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_email: EmailStr

class GrantRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    grantee_user_id: uuid.UUID
    level: str
    granted_at: datetime
    expires_at: Optional[datetime]
    revoked_at: Optional[datetime]


class DecisionIn(BaseModel):
    """The owner's decision on ONE suggested person. The server, not the client, works out whether it counts as
    'accepted' (read, no expiry, exactly as suggested) or 'modified' (anything else)."""
    model_config = ConfigDict(extra="forbid")
    user_id: uuid.UUID
    action: Literal["grant", "reject"]
    level: Literal["read", "edit"] = "read"
    expires_at: Optional[datetime] = None


class DocumentUpdate(BaseModel):
    """Owner-only metadata edit. Titles and categories are labels: they never carry or change access."""
    model_config = ConfigDict(extra="forbid")
    title: Optional[str] = Field(None, min_length=1, max_length=200)
    category: Optional[str] = Field(None, max_length=100)

    @model_validator(mode="after")
    def _something_to_change(self):
        if self.title is None and self.category is None:
            raise ValueError("provide title and/or category")
        return self
