from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import active_user
from app.db.models import AuditLog, User
from app.db.session import get_db


router = APIRouter(prefix="/logs", tags=["Logs"])


@router.get("")
def logs(user: User = Depends(active_user), db: Session = Depends(get_db)):
    query = db.query(AuditLog).order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
    if user.role != "admin":
        query = query.filter(AuditLog.user_id == user.id)
    rows = query.limit(300).all()
    return [
        {
            "id": row.id,
            "user_id": row.user_id,
            "action": row.action,
            "entity": row.entity,
            "entity_id": row.entity_id,
            "details": row.details,
            "created_at": row.created_at,
        }
        for row in rows
    ]
