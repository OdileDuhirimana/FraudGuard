from pydantic import BaseModel, EmailStr
from pydantic import ConfigDict
from typing import Optional, Dict, Any, List
from datetime import datetime


class UserCreate(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: int
    email: EmailStr
    role: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TransactionIn(BaseModel):
    amount: float
    currency: str = "USD"
    merchant: Optional[str] = None
    mcc: Optional[str] = None
    ip: Optional[str] = None
    gps_lat: Optional[float] = None
    gps_lon: Optional[float] = None
    device_id: Optional[str] = None
    features: Optional[Dict[str, Any]] = None
    card_hash: Optional[str] = None
    timezone_mismatch: Optional[bool] = None
    device_compromised: Optional[bool] = None


class ScoreOut(BaseModel):
    score: float
    decision: str
    reason: str
    transaction_id: int


class BehaviorEventIn(BaseModel):
    event_type: str
    data: Dict[str, Any]


class DeviceIn(BaseModel):
    device_id: str
    fingerprint: Dict[str, Any]


class FeedbackIn(BaseModel):
    transaction_id: int
    label: bool  # True = Fraud, False = Legit


class OTPInitIn(BaseModel):
    transaction_id: int


class OTPVerifyIn(BaseModel):
    transaction_id: int
    code: str


class CaseCreateIn(BaseModel):
    alert_id: int
    notes: Optional[str] = None


class CaseUpdateIn(BaseModel):
    case_id: int
    status: str
    notes: Optional[str] = None


class RoleUpdateIn(BaseModel):
    user_id: int
    role: str
