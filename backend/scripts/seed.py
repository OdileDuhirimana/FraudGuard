"""
Seed script for local development and demos.

Why a script instead of app-boot-time seeding: seeding on every app start
(as the "first user becomes admin" register-time logic effectively does)
is not a real seeder — it's an incidental side effect. This script is
explicit, idempotent, and run on demand (`python -m scripts.seed`), which
is the pattern any reviewer or teammate would expect to reset a local demo
environment to a known state across all four roles.

Usage:
    cd backend
    source ../.venv/bin/activate
    python -m scripts.seed

Idempotency: re-running this script is safe — it skips creating a user
whose email already exists, and does not duplicate transactions/alerts
beyond the fixed demo set below.
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta

from app import models
from app.auth import get_password_hash
from app.database import SessionLocal

DEMO_PASSWORD = "DemoPass123!"

DEMO_USERS = [
    ("admin@fraudguard.demo", "admin"),
    ("manager@fraudguard.demo", "manager"),
    ("investigator@fraudguard.demo", "investigator"),
    ("analyst@fraudguard.demo", "analyst"),
]


def seed_users(db) -> dict[str, models.User]:
    created: dict[str, models.User] = {}
    for email, role in DEMO_USERS:
        existing = db.query(models.User).filter(models.User.email == email).first()
        if existing:
            created[role] = existing
            continue
        user = models.User(email=email, hashed_password=get_password_hash(DEMO_PASSWORD), role=role)
        db.add(user)
        db.flush()
        created[role] = user
        print(f"created user: {email} ({role})")
    return created


def seed_transactions_and_alerts(db, analyst: models.User) -> None:
    if db.query(models.Transaction).count() > 0:
        print("transactions already present, skipping transaction/alert seed")
        return

    now = datetime.utcnow()
    demo_transactions = [
        {"amount": 42.50, "mcc": "5411", "decision": "allow", "score": 0.12, "ip": "203.0.113.5"},
        {"amount": 1850.00, "mcc": "7995", "decision": "block", "score": 0.91, "ip": "198.51.100.23"},
        {"amount": 620.00, "mcc": "6051", "decision": "challenge", "score": 0.68, "ip": "192.0.2.77"},
    ]
    for i, tx_data in enumerate(demo_transactions):
        tx = models.Transaction(
            user_id=analyst.id,
            amount=tx_data["amount"],
            currency="USD",
            merchant="Demo Merchant",
            mcc=tx_data["mcc"],
            ip=tx_data["ip"],
            device_id=f"demo-device-{i}",
            timestamp=now - timedelta(hours=i),
            score=tx_data["score"],
            decision=tx_data["decision"],
        )
        db.add(tx)
        db.flush()
        if tx_data["decision"] in ("block", "challenge"):
            db.add(
                models.Alert(
                    transaction_id=tx.id,
                    risk_score=tx_data["score"],
                    decision=tx_data["decision"],
                    reason="Seeded demo alert",
                )
            )
        print(f"created transaction id={tx.id} decision={tx_data['decision']}")


def main() -> int:
    db = SessionLocal()
    try:
        users_by_role = seed_users(db)
        db.commit()
        seed_transactions_and_alerts(db, users_by_role["analyst"])
        db.commit()
        print("\nSeed complete. Demo credentials (all roles share one password):")
        for email, role in DEMO_USERS:
            print(f"  {role:14s} {email}")
        print(f"  password: {DEMO_PASSWORD}")
        return 0
    except Exception as exc:  # pragma: no cover - operational script, not unit tested
        db.rollback()
        print(f"seed failed: {exc}", file=sys.stderr)
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
