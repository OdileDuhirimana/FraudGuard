from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from .models import CASE_STATUSES, USER_ROLES

# Minimum password length is a deliberately modest floor (not a full
# complexity policy) — the goal here is to reject trivially weak passwords
# ("a", "") at the API boundary rather than relying solely on hashing to
# absorb bad input. A production system would layer a breached-password
# check (e.g. HaveIBeenPwned k-anonymity API) on top of this.
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)


class UserLogin(BaseModel):
    """
    Separate from UserCreate: login must accept whatever password a user
    already has (no length re-validation), while registration enforces the
    minimum-strength policy. Reusing UserCreate for both (as the original
    code did) silently rejected valid login attempts if password policy
    ever tightened after a user registered.
    """

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
    model_config = ConfigDict(extra="ignore")

    amount: float = Field(gt=0, le=10_000_000, description="Transaction amount; must be positive")
    currency: str = Field(default="USD", min_length=3, max_length=3)
    merchant: Optional[str] = Field(default=None, max_length=255)
    mcc: Optional[str] = Field(default=None, min_length=4, max_length=4)
    ip: Optional[str] = Field(default=None, max_length=45)
    gps_lat: Optional[float] = Field(default=None, ge=-90, le=90)
    gps_lon: Optional[float] = Field(default=None, ge=-180, le=180)
    device_id: Optional[str] = Field(default=None, max_length=128)
    features: Optional[Dict[str, Any]] = None
    card_hash: Optional[str] = Field(default=None, max_length=128)
    timezone_mismatch: Optional[bool] = None
    device_compromised: Optional[bool] = None

    @field_validator("currency")
    @classmethod
    def currency_must_be_upper_alpha(cls, v: str) -> str:
        if not v.isalpha():
            raise ValueError("currency must be a 3-letter ISO 4217 code")
        return v.upper()

    @field_validator("mcc")
    @classmethod
    def mcc_must_be_numeric(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not v.isdigit():
            raise ValueError("mcc must be a 4-digit numeric code")
        return v


class ScoreOut(BaseModel):
    score: float
    decision: str
    reason: str
    transaction_id: int


class BehaviorEventIn(BaseModel):
    model_config = ConfigDict(extra="ignore")
    event_type: str = Field(min_length=1, max_length=32)
    data: Dict[str, Any]

    @field_validator("event_type")
    @classmethod
    def event_type_must_be_known(cls, v: str) -> str:
        allowed = {"typing", "mouse", "touch"}
        if v not in allowed:
            raise ValueError(f"event_type must be one of {sorted(allowed)}")
        return v


class DeviceIn(BaseModel):
    model_config = ConfigDict(extra="ignore")
    device_id: str = Field(min_length=1, max_length=128)
    fingerprint: Dict[str, Any]


class FeedbackIn(BaseModel):
    transaction_id: int = Field(gt=0)
    label: bool  # True = Fraud, False = Legit


class OTPInitIn(BaseModel):
    transaction_id: int = Field(gt=0)


class OTPVerifyIn(BaseModel):
    transaction_id: int = Field(gt=0)
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class CaseCreateIn(BaseModel):
    alert_id: int = Field(gt=0)
    notes: Optional[str] = Field(default=None, max_length=2000)


class CaseUpdateIn(BaseModel):
    case_id: int = Field(gt=0)
    status: str
    notes: Optional[str] = Field(default=None, max_length=2000)

    @field_validator("status")
    @classmethod
    def status_must_be_valid(cls, v: str) -> str:
        if v not in CASE_STATUSES:
            raise ValueError(f"status must be one of {list(CASE_STATUSES)}")
        return v


class RoleUpdateIn(BaseModel):
    user_id: int = Field(gt=0)
    role: str

    @field_validator("role")
    @classmethod
    def role_must_be_valid(cls, v: str) -> str:
        if v not in USER_ROLES:
            raise ValueError(f"role must be one of {list(USER_ROLES)}")
        return v


class TransactionSummaryOut(BaseModel):
    """
    Minimal transaction context nested inside AlertOut. Deliberately not
    the full Transaction row (no encrypted `features` blob, no `ip`/GPS) —
    an alert-feed consumer needs enough to triage without this becoming a
    second way to fetch a full transaction record.
    """

    id: int
    user_id: int
    amount: float
    currency: str
    decision: str
    model_config = ConfigDict(from_attributes=True)


class AlertOut(BaseModel):
    id: int
    transaction_id: int
    risk_score: float
    decision: str
    reason: Optional[str] = None
    created_at: datetime
    # PERF-02: populated via AlertRepository's joinedload(Alert.transaction)
    # — see repositories/alerts.py. Nullable because the FK is NOT NULL at
    # the DB level but a defensive None is cheaper than a 500 if that ever
    # changes.
    transaction: Optional[TransactionSummaryOut] = None
    model_config = ConfigDict(from_attributes=True)


class AuditLogOut(BaseModel):
    id: int
    actor_user_id: Optional[int] = None
    # PERF-02: sourced from AuditLog.actor_email (a Python property backed
    # by the eager-loaded `actor` relationship — see
    # repositories/audit_logs.py's joinedload(AuditLog.actor)), not a
    # second query per row.
    actor_email: Optional[str] = None
    action: str
    target: Optional[str] = None
    details: Optional[str] = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)
