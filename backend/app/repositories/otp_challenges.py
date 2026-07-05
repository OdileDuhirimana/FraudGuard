from __future__ import annotations

from typing import Optional

from fastapi import Depends
from sqlalchemy.orm import Session

from .. import models
from ..database import get_db


class OTPChallengeRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create(self, *, transaction_id: int, user_id: int, code: str) -> models.OTPChallenge:
        challenge = models.OTPChallenge(transaction_id=transaction_id, user_id=user_id, code=code)
        self.db.add(challenge)
        return challenge

    def get_latest_for_transaction(self, transaction_id: int) -> Optional[models.OTPChallenge]:
        return (
            self.db.query(models.OTPChallenge)
            .filter(models.OTPChallenge.transaction_id == transaction_id)
            .order_by(models.OTPChallenge.created_at.desc())
            .first()
        )


def get_otp_challenge_repository(db: Session = Depends(get_db)) -> OTPChallengeRepository:
    return OTPChallengeRepository(db)
