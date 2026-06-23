from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, ForeignKey, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="analyst")  # analyst, investigator, admin, manager
    created_at = Column(DateTime, default=datetime.utcnow)


class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    amount = Column(Float, nullable=False)
    currency = Column(String, default="USD")
    merchant = Column(String)
    mcc = Column(String)
    ip = Column(String)
    gps_lat = Column(Float)
    gps_lon = Column(Float)
    device_id = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    features = Column(JSON)
    score = Column(Float, default=0.0)
    decision = Column(String, default="allow")  # allow, challenge, block


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    transaction_id = Column(Integer, ForeignKey("transactions.id"))
    risk_score = Column(Float, nullable=False)
    decision = Column(String, nullable=False)
    reason = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)


class Case(Base):
    __tablename__ = "cases"
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"))
    status = Column(String, default="open")
    notes = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    actor_user_id = Column(Integer)
    action = Column(String)
    target = Column(String)
    details = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)


class BehaviorEvent(Base):
    __tablename__ = "behavior_events"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    event_type = Column(String)  # typing, mouse, touch
    data = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)


class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    device_id = Column(String, index=True)
    fingerprint = Column(JSON)
    compromised = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class OTPChallenge(Base):
    __tablename__ = "otp_challenges"
    id = Column(Integer, primary_key=True, index=True)
    transaction_id = Column(Integer, ForeignKey("transactions.id"), index=True)
    user_id = Column(Integer, index=True)
    code = Column(String)
    verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
