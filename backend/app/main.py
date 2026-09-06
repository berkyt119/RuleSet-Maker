from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from app.api import admin, auth, dashboard, domain, domain_json_export, domains_catalog, logs, public, ruleset
from app.core.config import get_settings
from app.core.errors import http_exception_handler, unhandled_exception_handler, validation_exception_handler
from app.core.security import hash_password
from app.db.models import GlobalDomainSelection, GlobalRuleset, PasswordPolicy, User, UserCustomCidr, UserCustomDomain, UserCustomService, UserDomainSelection, UserRuleset
from app.db.session import Base, SessionLocal, engine


settings = get_settings()
app = FastAPI(title=settings.app_name)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)
app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(Exception, unhandled_exception_handler)
app.include_router(auth.router, prefix="/api")
app.include_router(domain.router, prefix="/api")
app.include_router(ruleset.router, prefix="/api")
app.include_router(admin.router, prefix="/api")
app.include_router(domain_json_export.router, prefix="/api")
app.include_router(domains_catalog.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(logs.router, prefix="/api")
app.include_router(public.router, prefix="/api")


def bootstrap() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        for statement in [
            "ALTER TABLE user_rulesets ADD COLUMN cidrs_json TEXT DEFAULT '[]'",
            "ALTER TABLE user_rulesets ADD COLUMN cidrs_count INTEGER DEFAULT 0",
        ]:
            try:
                db.execute(text(statement))
                db.commit()
            except Exception:
                db.rollback()
        if not db.query(GlobalDomainSelection).first():
            migrated = {}
            for row in db.query(UserDomainSelection).order_by(UserDomainSelection.updated_at).all():
                migrated[row.service_key] = row
            for row in migrated.values():
                db.add(GlobalDomainSelection(service_key=row.service_key, is_enabled=row.is_enabled, updated_at=row.updated_at))
        if not db.query(GlobalRuleset).first():
            ruleset = db.query(UserRuleset).order_by(UserRuleset.updated_at.desc()).first()
            if ruleset:
                db.add(
                    GlobalRuleset(
                        domains_json=ruleset.domains_json,
                        cidrs_json=ruleset.cidrs_json,
                        domains_count=ruleset.domains_count,
                        cidrs_count=ruleset.cidrs_count,
                        public_token=ruleset.public_token,
                        updated_at=ruleset.updated_at,
                    )
                )
        service_ids = {row.id for row in db.query(UserCustomService.id).all()}
        if service_ids:
            db.query(UserCustomCidr).filter(UserCustomCidr.service_id.notin_(service_ids)).delete(synchronize_session=False)
            db.query(UserCustomDomain).filter(UserCustomDomain.service_id.notin_(service_ids)).delete(synchronize_session=False)
        else:
            db.query(UserCustomCidr).delete(synchronize_session=False)
            db.query(UserCustomDomain).delete(synchronize_session=False)
        db.commit()
        if not db.query(PasswordPolicy).first():
            db.add(PasswordPolicy())
        if not db.query(User).filter(User.username == settings.bootstrap_admin_username).first():
            db.add(
                User(
                    username=settings.bootstrap_admin_username,
                    password_hash=hash_password(settings.bootstrap_admin_password),
                    role="admin",
                    is_active=True,
                    must_change_password=False,
                )
            )
        db.commit()
    finally:
        db.close()


@app.on_event("startup")
def on_startup() -> None:
    bootstrap()


@app.get("/api/health")
def health():
    return {"status": "ok"}


frontend_dist = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if frontend_dist.exists():
    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend")
