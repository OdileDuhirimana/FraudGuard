from __future__ import annotations

from typing import Optional

from fastapi import Depends
from sqlalchemy.orm import Session

from .. import models
from ..database import get_db
from ..pagination import PageMeta, PageParams, paginate

_SORT_MAP = {
    "created_at": models.User.created_at.asc(),
    "-created_at": models.User.created_at.desc(),
    "email": models.User.email.asc(),
    "-email": models.User.email.desc(),
}


class UserRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def get_by_email(self, email: str) -> Optional[models.User]:
        return self.db.query(models.User).filter(models.User.email == email).first()

    def get_by_id(self, user_id: int) -> Optional[models.User]:
        return self.db.query(models.User).filter(models.User.id == user_id).first()

    def count(self) -> int:
        return self.db.query(models.User).count()

    def create(self, *, email: str, hashed_password: str, role: str) -> models.User:
        user = models.User(email=email, hashed_password=hashed_password, role=role)
        self.db.add(user)
        return user

    def list_paginated(
        self, params: PageParams, *, role: Optional[str], sort: str
    ) -> tuple[list[models.User], PageMeta]:
        query = self.db.query(models.User)
        if role:
            query = query.filter(models.User.role == role)
        query = query.order_by(_SORT_MAP.get(sort, models.User.created_at.desc()))
        return paginate(query, params)


def get_user_repository(db: Session = Depends(get_db)) -> UserRepository:
    return UserRepository(db)
