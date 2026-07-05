from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from .. import models
from ..auth import require_role
from ..database import get_db
from ..errors import NotFoundError
from ..logging_config import get_logger
from ..models import USER_ROLES
from ..pagination import Page, PageParams
from ..repositories import (
    AuditLogRepository,
    UserRepository,
    get_audit_log_repository,
    get_user_repository,
)
from ..schemas import AuditLogOut, RoleUpdateIn, UserOut
from ..services.audit import record as record_audit

router = APIRouter()
logger = get_logger("fraudguard.admin")


@router.get(
    "/audit",
    response_model=Page[AuditLogOut],
    dependencies=[Depends(require_role("admin", "manager"))],
)
def list_audit(
    repo: AuditLogRepository = Depends(get_audit_log_repository),
    params: PageParams = Depends(),
    action: Optional[str] = Query(default=None, description="Filter by exact action name"),
    actor_user_id: Optional[int] = Query(default=None, description="Filter by acting user id"),
    sort: str = Query(
        default="-created_at",
        description="Sort field, prefix with '-' for descending. One of: created_at, -created_at",
    ),
):
    items, meta = repo.list_paginated(params, action=action, actor_user_id=actor_user_id, sort=sort)
    return Page(items=items, meta=meta)


@router.get(
    "/users",
    response_model=Page[UserOut],
    dependencies=[Depends(require_role("admin", "manager"))],
)
def list_users(
    repo: UserRepository = Depends(get_user_repository),
    params: PageParams = Depends(),
    role: Optional[str] = Query(default=None, description=f"Filter by role. One of: {list(USER_ROLES)}"),
    sort: str = Query(
        default="-created_at",
        description="Sort field, prefix with '-' for descending. One of: created_at, -created_at, email, -email",
    ),
):
    items, meta = repo.list_paginated(params, role=role, sort=sort)
    return Page(items=items, meta=meta)


@router.post("/role", response_model=UserOut, dependencies=[Depends(require_role("admin"))])
def set_role(
    payload: RoleUpdateIn,
    db: Session = Depends(get_db),
    repo: UserRepository = Depends(get_user_repository),
    actor: models.User = Depends(require_role("admin")),
):
    user = repo.get_by_id(payload.user_id)
    if not user:
        raise NotFoundError("user_not_found", f"No user with id {payload.user_id}")

    previous_role = user.role
    user.role = payload.role
    db.add(user)
    record_audit(
        db,
        actor_user_id=actor.id,
        action="role_changed",
        target=f"user:{user.id}",
        details=f"{previous_role} -> {payload.role}",
    )
    db.commit()
    db.refresh(user)
    logger.info(
        "role_changed",
        extra={"actor_user_id": actor.id, "target_user_id": user.id, "previous_role": previous_role, "new_role": user.role},
    )
    return user
