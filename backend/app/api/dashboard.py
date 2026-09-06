import json

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import active_user
from app.db.models import GlobalRuleset, User, UserCustomService
from app.db.session import get_db
from app.services.domain_catalog import all_catalog_services, export_services, load_export_payload, selection_map


router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("")
def dashboard(user: User = Depends(active_user), db: Session = Depends(get_db)):
    exported, generated_at, catalog_error = export_services()
    services, _generated_at, _error = all_catalog_services(db, user)
    selected = selection_map(db, user)
    ruleset = db.query(GlobalRuleset).first()
    domains = []
    cidrs = []
    if ruleset:
        try:
            domains = json.loads(ruleset.domains_json or "[]")
        except Exception:
            domains = []
        try:
            cidrs = json.loads(ruleset.cidrs_json or "[]")
        except Exception:
            cidrs = []
    custom_count = db.query(UserCustomService).count()
    return {
        "groups_count": len({service.group_key for service in services} | {"custom-user-services"}),
        "services_total": len(exported) + custom_count,
        "imported_services_count": len(exported),
        "custom_services_count": custom_count,
        "enabled_services_count": sum(1 for value in selected.values() if value),
        "ruleset_domains_count": len(domains) if isinstance(domains, list) else 0,
        "ruleset_cidrs_count": len(cidrs) if isinstance(cidrs, list) else 0,
        "source_json_updated_at": generated_at,
        "ruleset_updated_at": ruleset.updated_at if ruleset else None,
        "catalog_error": catalog_error,
    }
