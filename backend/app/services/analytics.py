from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from .. import models


def count_user_tx_last_minutes(db: Session, user_id: int, minutes: int = 1) -> int:
    since = datetime.utcnow() - timedelta(minutes=minutes)
    return db.query(models.Transaction).filter(
        models.Transaction.user_id == user_id,
        models.Transaction.timestamp >= since,
    ).count()
