from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.errors import AppError
from app.core.security import decode_access_token
from app.db.models import User
from app.db.session import get_db


bearer = HTTPBearer(auto_error=False)


def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer), db: Session = Depends(get_db)) -> User:
    if not credentials:
        raise AppError(401, "UNAUTHORIZED", "Необходима авторизация.")
    subject = decode_access_token(credentials.credentials)
    if not subject:
        raise AppError(401, "UNAUTHORIZED", "Необходима авторизация.")
    user = db.get(User, int(subject)) if subject.isdigit() else None
    if not user or not user.is_active:
        raise AppError(401, "UNAUTHORIZED", "Необходима авторизация.")
    return user


def active_user(user: User = Depends(current_user)) -> User:
    if user.must_change_password:
        raise AppError(403, "PASSWORD_CHANGE_REQUIRED", "Необходимо сменить пароль.")
    return user


def admin_user(user: User = Depends(active_user)) -> User:
    if user.role != "admin":
        raise AppError(403, "FORBIDDEN", "Недостаточно прав.")
    return user
