import json

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from app.api.deps import active_user
from app.core.errors import AppError
from app.db.models import DomainScan, User
from app.db.session import get_db
from app.services.ruleset_generator import build_ruleset, safe_ruleset_filename


router = APIRouter(prefix="/ruleset", tags=["Ruleset"])


@router.get("/{scan_id}")
def get_ruleset(scan_id: int, user: User = Depends(active_user), db: Session = Depends(get_db)):
    scan = db.get(DomainScan, scan_id)
    if not scan or (scan.user_id != user.id and user.role != "admin"):
        raise AppError(404, "SCAN_NOT_FOUND", "Результат анализа не найден.")
    if scan.status != "SUCCESS":
        raise AppError(409, "RULESET_NOT_READY", "Ruleset доступен только после успешного анализа.")
    ruleset = build_ruleset([item.domain for item in scan.results])
    filename = safe_ruleset_filename(scan.normalized_domain)
    return Response(
        content=json.dumps(ruleset, ensure_ascii=False, indent=2).encode("utf-8"),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
