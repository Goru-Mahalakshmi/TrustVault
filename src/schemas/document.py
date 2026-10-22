import uuid
from datetime import datetime
from typing import Literal, Optional
from pydantic import BaseModel, ConfigDict, EmailStr

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
