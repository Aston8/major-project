from pydantic import BaseModel, Field
from datetime import datetime
from typing import List, Dict, Any, Optional

class BlacklistCreate(BaseModel):
    value: str
    type: str  # domain, keyword, ip
    notes: Optional[str] = None

class BlacklistItem(BlacklistCreate):
    id: str = Field(..., alias="_id")
    created_at: datetime

    class Config:
        populate_by_name = True

class UserRoleUpdate(BaseModel):
    user_id: str
    role: str

class SystemStats(BaseModel):
    total_users: int
    total_scans: int
    scans_by_type: Dict[str, int]
    scans_by_category: Dict[str, int]
    blacklist_count: int
    active_sandbox_containers: int
    redis_connected: bool
    mongodb_connected: bool

class AuditLogResponse(BaseModel):
    id: str = Field(..., alias="_id")
    user_id: str
    user_email: str
    action: str
    details: str
    ip_address: Optional[str] = None
    created_at: datetime

    class Config:
        populate_by_name = True
