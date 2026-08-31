import json

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from app.core.errors import AppError
from app.db.session import get_db
from app.services.domain_catalog import public_ruleset


router = APIRouter(prefix="/public", tags=["Public ruleset"])


@router.get("/ruleset/{token}.json")
def get_public_ruleset(token: str, db: Session = Depends(get_db)):
    ruleset = public_ruleset(db, token)
    if ruleset is None:
        raise AppError(404, "RULESET_NOT_FOUND", "Ruleset не найден.")
    return Response(content=json.dumps(ruleset, ensure_ascii=False, indent=2).encode("utf-8"), media_type="application/json")
