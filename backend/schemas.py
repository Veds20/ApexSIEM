from pydantic import BaseModel
from datetime import datetime

class AlertCreate(BaseModel):
    source_ip: str
    attack_type: str

class AlertResponse(BaseModel):
    id: int
    source_ip: str
    attack_type: str
    severity: str
    trust_score: int
    timestamp: datetime

    class Config:
        from_attributes = True