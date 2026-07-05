import uuid
from datetime import datetime, timedelta
from typing import Optional

import jwt
from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from . import models
from .config import settings
from .database import get_db
from .errors import ForbiddenError, UnauthorizedError
from .services import tokens as token_service

SECRET_KEY = settings.jwt_secret_key
ALGORITHM = settings.jwt_algorithm
ACCESS_TOKEN_EXPIRE_MINUTES = settings.access_token_expire_minutes

# DEPENDENCY-DRIFT FIX: requirements.txt previously pinned `passlib[bcrypt]`
# while this module actually configured `pbkdf2_sha256` — a real mismatch
# between the declared dependency and runtime behavior (flagged as AUTH-03
# in the portfolio audit: pbkdf2_sha256, while a legitimate NIST-approved
# KDF, doesn't match bcrypt/argon2/scrypt). Switching the *default* scheme
# to `argon2` (OWASP's current recommendation) rather than bcrypt
# specifically: this environment's pinned `bcrypt==5.0.0` is incompatible
# with `passlib==1.7.4`'s bcrypt backend (passlib probes
# `bcrypt.__about__`, which bcrypt removed in 4.1+, causing every
# hash/verify call to raise at runtime) — verified directly in this
# environment. Rather than pin an old, unmaintained bcrypt release to route
# around that, argon2 is used: it is explicitly one of the three algorithms
# the audit accepts, has no such compatibility landmine via `argon2-cffi`,
# and is arguably the stronger default for new code (memory-hard,
# GPU-resistant).
#
# `pbkdf2_sha256` is kept as a *verifiable* legacy scheme (not the default
# for new hashes) so any password hashed under the previous scheme still
# authenticates correctly instead of being locked out by this change;
# `deprecated="auto"` flags those hashes via `needs_update()`, and
# routers/auth.py's login handler transparently re-hashes to argon2 on the
# next successful login — the standard rolling-migration pattern for
# changing a KDF without a forced mass password reset.
pwd_context = CryptContext(
    schemes=["argon2", "pbkdf2_sha256"],
    default="argon2",
    deprecated="auto",
)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/v1/auth/login")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def needs_rehash(hashed_password: str) -> bool:
    """
    True if `hashed_password` was produced by a scheme other than the
    current default (e.g. a legacy `pbkdf2_sha256` hash from before the
    argon2 migration) and should be replaced with a fresh hash the next
    time the plaintext password is available (i.e. right after a
    successful login verification).
    """
    return pwd_context.needs_update(hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Every issued token carries a unique `jti` (JWT ID) claim, which is what
    makes server-side revocation (logout) possible for an otherwise
    stateless JWT: revoking a token means recording its jti, not the token
    itself (see services/tokens.py).
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "jti": str(uuid.uuid4())})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.InvalidTokenError:
        raise UnauthorizedError("invalid_token", "Could not validate credentials")


def get_token_payload(token: str = Depends(oauth2_scheme)) -> dict:
    """
    Exposes the decoded JWT payload as its own dependency so route handlers
    that need claims beyond the resolved User (currently: /auth/logout,
    which needs `jti` and `exp` to revoke the *current* token) don't have
    to re-parse the Authorization header themselves.
    """
    return decode_token(token)


def get_current_user(
    db: Session = Depends(get_db),
    payload: dict = Depends(get_token_payload),
) -> models.User:
    unauthorized = UnauthorizedError("invalid_token", "Could not validate credentials")
    # AUTH-02 FIX: a token that decodes and validates cryptographically can
    # still have been explicitly revoked (logout) — that check has to live
    # here, on every authenticated request, not only at issuance time.
    if token_service.is_revoked(db, payload.get("jti")):
        raise UnauthorizedError("token_revoked", "This session has been logged out")
    email: Optional[str] = payload.get("sub")
    if email is None:
        raise unauthorized
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise unauthorized
    return user


def require_role(*roles: str):
    def role_dep(user: models.User = Depends(get_current_user)) -> models.User:
        if user.role not in roles:
            raise ForbiddenError("insufficient_permissions", "Insufficient permissions for this action")
        return user

    return role_dep
