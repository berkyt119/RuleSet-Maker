import json
from datetime import datetime

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from app.api.deps import active_user
from app.core.errors import AppError
from app.db.models import User, UserCustomCidr, UserCustomDomain, UserCustomService
from app.db.session import get_db
from app.schemas import CustomDomainIn, CustomServiceIn, SelectionIn
from app.services.audit import audit
from app.services.domain_catalog import add_custom_cidr, add_custom_domain, catalog_response, create_custom_service, current_ruleset, save_selection_and_build_ruleset
from app.services.ruleset_generator import safe_ruleset_filename


router = APIRouter(prefix="/domains", tags=["Domain catalog"])


@router.get("/catalog")
def get_catalog(user: User = Depends(active_user), db: Session = Depends(get_db)):
    return catalog_response(db, user)


@router.put("/selection")
def save_selection(payload: SelectionIn, user: User = Depends(active_user), db: Session = Depends(get_db)):
    result = save_selection_and_build_ruleset(db, user, payload.enabled_service_keys)
    audit(db, user, "save_domain_selection", "domains", details=f"services={len(payload.enabled_service_keys)}, domains={result['domains_count']}")
    db.commit()
    return result


@router.get("/ruleset")
def get_current_ruleset(user: User = Depends(active_user), db: Session = Depends(get_db)):
    ruleset, meta = current_ruleset(db, user)
    db.commit()
    return {"ruleset": ruleset, "domains_count": meta.domains_count, "cidrs_count": meta.cidrs_count, "updated_at": meta.updated_at, "public_token": meta.public_token}


@router.get("/ruleset/download")
def download_current_ruleset(user: User = Depends(active_user), db: Session = Depends(get_db)):
    ruleset, _meta = current_ruleset(db, user)
    audit(db, user, "download_ruleset", "ruleset")
    db.commit()
    return Response(
        content=json.dumps(ruleset, ensure_ascii=False, indent=2).encode("utf-8"),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{safe_ruleset_filename(user.username)}"'},
    )


@router.post("/custom-services")
def add_service(payload: CustomServiceIn, user: User = Depends(active_user), db: Session = Depends(get_db)):
    try:
        service = create_custom_service(db, user, payload.name, payload.root_domain)
    except ValueError as exc:
        raise AppError(400, "INVALID_DOMAIN", str(exc)) from exc
    audit(db, user, "create_custom_service", "custom_service", service.id, service.name)
    db.commit()
    return {"id": service.id}


@router.delete("/custom-services/{service_id}", status_code=204)
def delete_service(service_id: int, user: User = Depends(active_user), db: Session = Depends(get_db)):
    service = db.get(UserCustomService, service_id)
    if not service:
        raise AppError(404, "CUSTOM_SERVICE_NOT_FOUND", "Пользовательский сервис не найден.")
    audit(db, user, "delete_custom_service", "custom_service", service.id, service.name)
    db.query(UserCustomCidr).filter(UserCustomCidr.service_id == service.id).delete()
    db.query(UserCustomDomain).filter(UserCustomDomain.service_id == service.id).delete()
    db.delete(service)
    db.commit()
    return Response(status_code=204)


@router.post("/custom-services/{service_id}/domains")
def add_domain(service_id: int, payload: CustomDomainIn, user: User = Depends(active_user), db: Session = Depends(get_db)):
    service = db.get(UserCustomService, service_id)
    if not service:
        raise AppError(404, "CUSTOM_SERVICE_NOT_FOUND", "Пользовательский сервис не найден.")
    try:
        if payload.value_type == "ip_cidr":
            cidr = add_custom_cidr(db, service, payload.domain)
            audit(db, user, "add_custom_cidr", "custom_cidr", cidr.id, cidr.cidr)
            result = {"id": cidr.id, "cidr": cidr.cidr, "value_type": "ip_cidr"}
        elif payload.value_type == "domain":
            domain = add_custom_domain(db, service, payload.domain)
            audit(db, user, "add_custom_domain", "custom_domain", domain.id, domain.domain)
            result = {"id": domain.id, "domain": domain.domain, "value_type": "domain"}
        else:
            raise AppError(400, "INVALID_VALUE_TYPE", "Тип должен быть domain или ip_cidr.")
    except ValueError as exc:
        raise AppError(400, "INVALID_CUSTOM_VALUE", str(exc)) from exc
    service.updated_at = datetime.utcnow()
    db.commit()
    return result


@router.delete("/custom-services/{service_id}/domains/{domain_id}", status_code=204)
def delete_domain(service_id: int, domain_id: int, user: User = Depends(active_user), db: Session = Depends(get_db)):
    service = db.get(UserCustomService, service_id)
    domain = db.get(UserCustomDomain, domain_id)
    if not service or not domain or domain.service_id != service.id:
        raise AppError(404, "CUSTOM_DOMAIN_NOT_FOUND", "Пользовательский домен не найден.")
    audit(db, user, "delete_custom_domain", "custom_domain", domain.id, domain.domain)
    db.delete(domain)
    service.updated_at = datetime.utcnow()
    db.commit()
    return Response(status_code=204)


@router.delete("/custom-services/{service_id}/cidrs/{cidr_id}", status_code=204)
def delete_cidr(service_id: int, cidr_id: int, user: User = Depends(active_user), db: Session = Depends(get_db)):
    service = db.get(UserCustomService, service_id)
    cidr = db.get(UserCustomCidr, cidr_id)
    if not service or not cidr or cidr.service_id != service.id:
        raise AppError(404, "CUSTOM_CIDR_NOT_FOUND", "Пользовательский CIDR не найден.")
    audit(db, user, "delete_custom_cidr", "custom_cidr", cidr.id, cidr.cidr)
    db.delete(cidr)
    service.updated_at = datetime.utcnow()
    db.commit()
    return Response(status_code=204)
