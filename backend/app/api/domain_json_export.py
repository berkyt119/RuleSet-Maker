import json
import os
from pathlib import Path

from fastapi import APIRouter, Request, Response

from app.core.config import get_settings
from app.core.errors import AppError


router = APIRouter(tags=["Domain JSON export"])


def bearer_token(request: Request) -> str:
    authorization = request.headers.get("Authorization", "")
    prefix = "Bearer "
    if not authorization.startswith(prefix):
        return ""
    return authorization[len(prefix):].strip()


def validate_export_payload(payload: object) -> dict:
    if not isinstance(payload, dict):
        raise AppError(400, "INVALID_EXPORT_JSON", "Тело запроса должно быть JSON-объектом.")
    if payload.get("schema_version") != 1:
        raise AppError(400, "INVALID_SCHEMA_VERSION", "schema_version должен быть равен 1.")
    if not isinstance(payload.get("groups"), list):
        raise AppError(400, "INVALID_GROUPS", "groups должен быть массивом.")
    return payload


@router.post("/domain-json-export", status_code=204)
async def domain_json_export(request: Request) -> Response:
    settings = get_settings()
    if not settings.domain_json_export_token or bearer_token(request) != settings.domain_json_export_token:
        raise AppError(401, "UNAUTHORIZED", "Необходим корректный Bearer token.")
    content_type = request.headers.get("Content-Type", "")
    if "application/json" not in content_type.lower():
        raise AppError(415, "UNSUPPORTED_MEDIA_TYPE", "Content-Type должен быть application/json.")
    try:
        payload = validate_export_payload(await request.json())
    except json.JSONDecodeError as exc:
        raise AppError(400, "INVALID_JSON", "Некорректный JSON.") from exc

    target = Path(settings.domain_json_export_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temp, target)
    return Response(status_code=204)
