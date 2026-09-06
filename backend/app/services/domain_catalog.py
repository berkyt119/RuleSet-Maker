import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_network
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.models import GlobalDomainSelection, GlobalRuleset, User, UserCustomCidr, UserCustomDomain, UserCustomService
from app.services.prefix_finder import DOMAIN_RE, normalize_hostname, validate_domain
from app.services.ruleset_generator import build_ruleset


@dataclass(frozen=True)
class CatalogService:
    key: str
    group_key: str
    group_name: str
    name: str
    display_name: str
    root_domain: str | None
    related_domains: list[str]
    is_custom: bool = False
    custom_service_id: int | None = None

    @property
    def domains(self) -> list[str]:
        values = []
        if self.root_domain:
            values.append(self.root_domain)
        values.extend(self.related_domains)
        return normalize_domain_list(values)


def validate_public_cidr(value: str) -> str:
    try:
        network = ip_network(value.strip(), strict=False)
    except Exception as exc:
        raise ValueError("CIDR должен быть указан в формате ip/netmask, например 8.8.8.8/32.") from exc
    if network.version != 4:
        raise ValueError("Поддерживаются только IPv4 CIDR.")
    if any([network.is_private, network.is_loopback, network.is_link_local, network.is_multicast, network.is_reserved, network.is_unspecified]):
        raise ValueError("CIDR не должен относиться к локальным или служебным адресам.")
    return str(network)


def write_json_atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temp, path)


def persist_ruleset_files(ruleset: dict, created_at: datetime) -> tuple[str, str]:
    settings = get_settings()
    output = Path(settings.ruleset_output_path)
    archive_dir = Path(settings.ruleset_archive_dir)
    dated = archive_dir / f"{created_at.strftime('%Y-%m-%d-%H-%M-%S')}-data.json"
    write_json_atomic(output, ruleset)
    write_json_atomic(dated, ruleset)
    return str(output), str(dated)


def normalize_domain_list(values: list[str]) -> list[str]:
    domains = set()
    for value in values:
        hostname = normalize_hostname(value)
        if DOMAIN_RE.match(hostname):
            domains.add(hostname)
    return sorted(domains)


def service_key(group_name: str, name: str, root_domain: str | None) -> str:
    root = normalize_hostname(root_domain) if root_domain else "no-root"
    return f"export::{group_name.strip()}::{name.strip()}::{root}"


def custom_service_key(service_id: int) -> str:
    return f"custom::{service_id}"


def display_group_name(value: str | None) -> str:
    name = str(value or "").strip()
    if not name or name.lower() == "ungrouped":
        return "Без категории"
    return name


def load_export_payload() -> tuple[dict | None, str | None, str | None]:
    path = Path(get_settings().domain_json_export_path)
    if not path.exists():
        return None, None, "Файл каталога доменов еще не получен."
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None, None, "Файл каталога доменов содержит некорректный JSON."
    if not isinstance(payload, dict) or not isinstance(payload.get("groups"), list):
        return None, None, "Файл каталога доменов имеет некорректную структуру."
    return payload, payload.get("generated_at"), None


def export_services() -> tuple[list[CatalogService], str | None, str | None]:
    payload, generated_at, error = load_export_payload()
    if error or not payload:
        return [], generated_at, error
    services = []
    for group in payload.get("groups", []):
        if not isinstance(group, dict):
            continue
        group_name = display_group_name(group.get("name"))
        for service in group.get("services", []) if isinstance(group.get("services"), list) else []:
            if not isinstance(service, dict):
                continue
            root = normalize_hostname(service.get("root_domain")) if service.get("root_domain") else None
            related = normalize_domain_list(service.get("related_domains") if isinstance(service.get("related_domains"), list) else [])
            name = str(service.get("name") or service.get("display_name") or root or "Service")
            display_name = str(service.get("display_name") or name)
            services.append(CatalogService(service_key(group_name, name, root), group_name, group_name, name, display_name, root, related))
    return services, generated_at, None


def user_custom_services(db: Session, user: User) -> list[CatalogService]:
    rows = db.query(UserCustomService).order_by(UserCustomService.id).all()
    return [
        CatalogService(
            key=custom_service_key(row.id),
            group_key="custom-user-services",
            group_name="Пользовательские сервисы",
            name=row.name,
            display_name=row.display_name,
            root_domain=row.root_domain,
            related_domains=[domain.domain for domain in row.domains],
            is_custom=True,
            custom_service_id=row.id,
        )
        for row in rows
    ]


def all_catalog_services(db: Session, user: User) -> tuple[list[CatalogService], str | None, str | None]:
    exported, generated_at, error = export_services()
    return exported + user_custom_services(db, user), generated_at, error


def selection_map(db: Session, user: User) -> dict[str, bool]:
    rows = db.query(GlobalDomainSelection).all()
    return {row.service_key: row.is_enabled for row in rows}


def catalog_response(db: Session, user: User) -> dict:
    services, generated_at, error = all_catalog_services(db, user)
    selected = selection_map(db, user)
    groups = {}
    groups["custom-user-services"] = {"key": "custom-user-services", "name": "Пользовательские сервисы", "services": []}
    for service in services:
        group = groups.setdefault(service.group_key, {"key": service.group_key, "name": service.group_name, "services": []})
        group["services"].append(
            {
                "key": service.key,
                "name": service.name,
                "display_name": service.display_name,
                "root_domain": service.root_domain,
                "related_domains": service.related_domains,
                "domains_count": len(service.domains),
                "enabled": selected.get(service.key, False),
                "is_custom": service.is_custom,
                "custom_service_id": service.custom_service_id,
                "custom_domains": [
                    {"id": domain.id, "domain": domain.domain}
                    for domain in db.query(UserCustomDomain).filter(UserCustomDomain.service_id == service.custom_service_id).order_by(UserCustomDomain.domain).all()
                ] if service.is_custom and service.custom_service_id else [],
                "custom_cidrs": [
                    {"id": cidr.id, "cidr": cidr.cidr}
                    for cidr in db.query(UserCustomCidr).filter(UserCustomCidr.service_id == service.custom_service_id).order_by(UserCustomCidr.cidr).all()
                ] if service.is_custom and service.custom_service_id else [],
            }
        )
    for group in groups.values():
        enabled = [item["enabled"] for item in group["services"]]
        group["enabled"] = bool(enabled) and all(enabled)
        group["partial"] = any(enabled) and not all(enabled)
    return {"generated_at": generated_at, "error": error, "groups": list(groups.values())}


def get_or_create_ruleset(db: Session, user: User | None = None) -> GlobalRuleset:
    row = db.query(GlobalRuleset).first()
    if row:
        return row
    row = GlobalRuleset(public_token=secrets.token_urlsafe(32))
    db.add(row)
    db.flush()
    return row


def save_selection_and_build_ruleset(db: Session, user: User, enabled_service_keys: list[str]) -> dict:
    enabled = set(enabled_service_keys)
    now = datetime.utcnow()
    existing = {row.service_key: row for row in db.query(GlobalDomainSelection).all()}
    for key in set(existing) | enabled:
        row = existing.get(key)
        if not row:
            row = GlobalDomainSelection(service_key=key)
            db.add(row)
        row.is_enabled = key in enabled
        row.updated_at = now

    services, _generated_at, _error = all_catalog_services(db, user)
    domains = []
    cidrs = []
    for service in services:
        if service.key in enabled:
            domains.extend(service.domains)
            if service.is_custom and service.custom_service_id:
                cidrs.extend(row.cidr for row in db.query(UserCustomCidr).filter(UserCustomCidr.service_id == service.custom_service_id).all())
    built_ruleset = build_ruleset(domains, cidrs)
    normalized_domains = built_ruleset["rules"][0].get("domain_suffix", [])
    normalized_cidrs = built_ruleset["rules"][0].get("ip_cidr", [])
    ruleset = get_or_create_ruleset(db, user)
    ruleset.domains_json = json.dumps(normalized_domains, ensure_ascii=False)
    ruleset.cidrs_json = json.dumps(normalized_cidrs, ensure_ascii=False)
    ruleset.domains_count = len(normalized_domains)
    ruleset.cidrs_count = len(normalized_cidrs)
    ruleset.updated_at = now
    output_path, archive_path = persist_ruleset_files(built_ruleset, now)
    db.flush()
    return {"domains_count": ruleset.domains_count, "cidrs_count": ruleset.cidrs_count, "public_token": ruleset.public_token, "updated_at": ruleset.updated_at, "output_path": output_path, "archive_path": archive_path}


def current_ruleset(db: Session, user: User) -> tuple[dict, GlobalRuleset]:
    ruleset = get_or_create_ruleset(db, user)
    try:
        domains = json.loads(ruleset.domains_json or "[]")
    except Exception:
        domains = []
    try:
        cidrs = json.loads(ruleset.cidrs_json or "[]")
    except Exception:
        cidrs = []
    return build_ruleset(domains if isinstance(domains, list) else [], cidrs if isinstance(cidrs, list) else []), ruleset


def public_ruleset(db: Session, token: str) -> dict | None:
    row = db.query(GlobalRuleset).filter(GlobalRuleset.public_token == token).first()
    if not row:
        return None
    try:
        domains = json.loads(row.domains_json or "[]")
    except Exception:
        domains = []
    try:
        cidrs = json.loads(row.cidrs_json or "[]")
    except Exception:
        cidrs = []
    return build_ruleset(domains if isinstance(domains, list) else [], cidrs if isinstance(cidrs, list) else [])


def create_custom_service(db: Session, user: User, name: str, root_domain: str | None) -> UserCustomService:
    root = validate_domain(root_domain) if root_domain else None
    display = name.strip()
    row = UserCustomService(user_id=user.id, name=display, display_name=display, root_domain=root)
    db.add(row)
    db.flush()
    return row


def add_custom_domain(db: Session, service: UserCustomService, domain: str) -> UserCustomDomain:
    row = UserCustomDomain(service_id=service.id, domain=validate_domain(domain))
    db.add(row)
    db.flush()
    return row


def add_custom_cidr(db: Session, service: UserCustomService, cidr: str) -> UserCustomCidr:
    row = UserCustomCidr(service_id=service.id, cidr=validate_public_cidr(cidr))
    db.add(row)
    db.flush()
    return row
