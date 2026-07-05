from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import models
from ..auth import (
    create_access_token,
    get_current_user,
    get_password_hash,
    get_token_payload,
    needs_rehash,
    verify_password,
)
from ..database import get_db
from ..errors import ConflictError, UnauthorizedError
from ..logging_config import get_logger
from ..repositories import UserRepository, get_user_repository
from ..schemas import Token, UserCreate, UserLogin, UserOut
from ..services import tokens as token_service
from ..services.audit import record as record_audit

router = APIRouter()
logger = get_logger("fraudguard.auth")


@router.post("/register", response_model=UserOut, status_code=201)
def register(
    payload: UserCreate,
    db: Session = Depends(get_db),
    repo: UserRepository = Depends(get_user_repository),
):
    existing = repo.get_by_email(payload.email)
    if existing:
        raise ConflictError("email_already_registered", "An account with this email already exists")

    # First registered user becomes admin so a freshly deployed instance
    # always has at least one admin account. Every subsequent registration
    # defaults to the least-privileged role.
    is_first_user = repo.count() == 0
    role = "admin" if is_first_user else "analyst"

    user = repo.create(
        email=payload.email,
        hashed_password=get_password_hash(payload.password),
        role=role,
    )
    db.flush()
    record_audit(db, actor_user_id=user.id, action="user_registered", target=f"user:{user.id}")
    db.commit()
    db.refresh(user)
    logger.info("user_registered", extra={"user_id": user.id, "role": user.role})
    return user


@router.post("/login", response_model=Token)
def login(
    payload: UserLogin,
    db: Session = Depends(get_db),
    repo: UserRepository = Depends(get_user_repository),
):
    user = repo.get_by_email(payload.email)
    if not user or not verify_password(payload.password, user.hashed_password):
        # Deliberately do not distinguish "unknown email" from "wrong
        # password" in the response or the audit target — doing so would
        # let an attacker enumerate valid accounts.
        record_audit(db, actor_user_id=None, action="login_failed", target=payload.email)
        db.commit()
        logger.warning("login_failed", extra={"email": payload.email})
        raise UnauthorizedError("invalid_credentials", "Invalid email or password")

    # Transparent hash-scheme migration: if this user's stored hash was
    # produced under a previous KDF (e.g. pbkdf2_sha256, pre-argon2
    # migration), re-hash with the current default now that the plaintext
    # is available. This is the only point in the request lifecycle where
    # the plaintext password exists, so it is the only place this upgrade
    # can happen without forcing a mass password reset.
    if needs_rehash(user.hashed_password):
        user.hashed_password = get_password_hash(payload.password)
        db.add(user)

    record_audit(db, actor_user_id=user.id, action="login_succeeded", target=f"user:{user.id}")
    db.commit()
    logger.info("login_succeeded", extra={"user_id": user.id})

    token = create_access_token({"sub": user.email, "role": user.role})
    return Token(access_token=token)


@router.post("/logout", status_code=200)
def logout(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
    token_payload: dict = Depends(get_token_payload),
):
    """
    AUTH-02 FIX: previously there was no logout endpoint at all, and no
    mechanism to invalidate an access token before its natural 8-hour
    expiry under any circumstance. This revokes the *specific token
    presented on this request* by recording its `jti` in the server-side
    denylist (services/tokens.py); get_current_user checks every
    subsequent request's jti against that table, so the presented token
    (and only that token — other active sessions/tokens for the same user
    are unaffected, matching standard single-session logout semantics)
    stops working immediately rather than at natural expiry.
    """
    jti = token_payload.get("jti")
    exp_claim = token_payload.get("exp")
    expires_at = datetime.utcfromtimestamp(exp_claim) if exp_claim else datetime.utcnow()

    if jti:
        token_service.revoke(db, jti=jti, user_id=user.id, expires_at=expires_at)

    record_audit(db, actor_user_id=user.id, action="logout", target=f"user:{user.id}")
    db.commit()
    logger.info("logout", extra={"user_id": user.id})
    return {"status": "logged_out"}
