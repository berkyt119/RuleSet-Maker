from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends
from sqlalchemy.orm import Session

from app.api.deps import active_user
from app.core.errors import AppError
from app.db.models import DomainScan, DomainScanResult, User
from app.db.session import SessionLocal, get_db
from app.schemas import DomainScanIn, DomainScanOut, DomainScanStarted
from app.services.audit import audit
from app.services.prefix_finder import PrefixFinderError, normalize_hostname, run_related_domains, validate_domain


router = APIRouter(prefix="/domain", tags=["Domain analysis"])


def scan_to_schema(scan: DomainScan) -> DomainScanOut:
    return DomainScanOut(
        id=scan.id,
        input_domain=scan.input_domain,
        normalized_domain=scan.normalized_domain,
        status=scan.status,
        error_code=scan.error_code,
        error_message=scan.error_message,
        domains_count=len(scan.results),
        domains=scan.results,
        created_at=scan.created_at,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
    )


def execute_scan(scan_id: int) -> None:
    db = SessionLocal()
    try:
        scan = db.get(DomainScan, scan_id)
        if not scan:
            return
        scan.started_at = datetime.utcnow()
        scan.status = "PROCESSING"
        db.commit()
        try:
            domains = run_related_domains(scan.normalized_domain)
            for item in domains:
                db.add(DomainScanResult(scan_id=scan.id, domain=item["domain"], source=item["source"]))
            scan.status = "SUCCESS" if domains else "EMPTY"
            scan.finished_at = datetime.utcnow()
            audit(db, db.get(User, scan.user_id), "domain_scan_success", "domain_scan", scan.id, f"domains={len(domains)}")
            db.commit()
        except PrefixFinderError as exc:
            scan.status = "ERROR"
            scan.error_code = "PREFIX_FINDER_ERROR"
            scan.error_message = str(exc)
            scan.finished_at = datetime.utcnow()
            audit(db, db.get(User, scan.user_id), "domain_scan_failed", "domain_scan", scan.id, str(exc))
            db.commit()
        except Exception:
            scan.status = "ERROR"
            scan.error_code = "DOMAIN_SCAN_ERROR"
            scan.error_message = "Не удалось выполнить анализ домена."
            scan.finished_at = datetime.utcnow()
            audit(db, db.get(User, scan.user_id), "domain_scan_failed", "domain_scan", scan.id, "internal error")
            db.commit()
    finally:
        db.close()


@router.post("/scan", response_model=DomainScanStarted)
def start_scan(payload: DomainScanIn, background_tasks: BackgroundTasks, user: User = Depends(active_user), db: Session = Depends(get_db)):
    try:
        normalized = validate_domain(payload.domain)
    except ValueError as exc:
        raise AppError(400, "INVALID_DOMAIN", str(exc)) from exc
    scan = DomainScan(user_id=user.id, input_domain=normalize_hostname(payload.domain), normalized_domain=normalized, status="PROCESSING", started_at=datetime.utcnow())
    db.add(scan)
    db.flush()
    audit(db, user, "domain_scan_started", "domain_scan", scan.id, normalized)
    db.commit()
    background_tasks.add_task(execute_scan, scan.id)
    return DomainScanStarted(id=scan.id, status=scan.status)


@router.get("/scans/{scan_id}", response_model=DomainScanOut)
def get_scan(scan_id: int, user: User = Depends(active_user), db: Session = Depends(get_db)):
    scan = db.get(DomainScan, scan_id)
    if not scan or (scan.user_id != user.id and user.role != "admin"):
        raise AppError(404, "SCAN_NOT_FOUND", "Результат анализа не найден.")
    return scan_to_schema(scan)
