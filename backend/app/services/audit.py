from sqlalchemy.orm import Session

from app.db.models import AuditLog, User


def audit(db: Session, user: User | None, action: str, entity: str, entity_id: object | None = None, details: str | None = None) -> None:
    db.add(AuditLog(user_id=user.id if user else None, action=action, entity=entity, entity_id=str(entity_id) if entity_id else None, details=details))
