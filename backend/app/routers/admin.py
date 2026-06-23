from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..database import get_db
from .. import models
from ..auth import require_role
from ..schemas import RoleUpdateIn

router = APIRouter()


@router.get("/audit", dependencies=[Depends(require_role("admin", "manager"))])
def list_audit(db: Session = Depends(get_db)):
    return db.query(models.AuditLog).order_by(models.AuditLog.created_at.desc()).limit(200).all()


@router.get("/users", dependencies=[Depends(require_role("admin", "manager"))])
def list_users(db: Session = Depends(get_db)):
    return db.query(models.User).all()


@router.post("/role", dependencies=[Depends(require_role("admin"))])
def set_role(payload: RoleUpdateIn, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == payload.user_id).first()
    if not user:
        return {"error": "user_not_found"}
    user.role = payload.role
    db.add(user)
    db.commit()
    return {"status": "updated", "user_id": user.id, "role": user.role}
