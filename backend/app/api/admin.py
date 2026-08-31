from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import admin_user
from app.core.errors import AppError
from app.core.security import hash_password
from app.db.models import PasswordPolicy, User
from app.db.session import get_db
from app.schemas import PasswordPolicyIn, PasswordPolicyOut, UserCreate, UserOut, UserPasswordSet, UserUpdate
from app.services.audit import audit
from app.services.password_policy import validate_password_policy


router = APIRouter(prefix="/admin", tags=["Administration"])


def valid_role(role: str) -> str:
    if role not in {"admin", "user"}:
        raise AppError(400, "INVALID_ROLE", "Некорректная роль пользователя.")
    return role


@router.get("/users", response_model=list[UserOut])
def list_users(_admin: User = Depends(admin_user), db: Session = Depends(get_db)):
    return db.query(User).order_by(User.id).all()


@router.post("/users", response_model=UserOut)
def create_user(payload: UserCreate, admin: User = Depends(admin_user), db: Session = Depends(get_db)):
    role = valid_role(payload.role)
    policy = db.query(PasswordPolicy).order_by(PasswordPolicy.id).first()
    errors = validate_password_policy(payload.password, policy)
    if errors:
        raise AppError(400, "PASSWORD_POLICY_VIOLATION", " ".join(errors))
    user = User(username=payload.username.strip(), password_hash=hash_password(payload.password), role=role, must_change_password=payload.must_change_password)
    db.add(user)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise AppError(409, "USERNAME_EXISTS", "Пользователь с таким логином уже существует.") from exc
    audit(db, admin, "create_user", "user", user.id)
    db.commit()
    db.refresh(user)
    return user


@router.get("/users/{user_id}", response_model=UserOut)
def get_user(user_id: int, _admin: User = Depends(admin_user), db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if not user:
        raise AppError(404, "USER_NOT_FOUND", "Пользователь не найден.")
    return user


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(user_id: int, payload: UserUpdate, admin: User = Depends(admin_user), db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if not user:
        raise AppError(404, "USER_NOT_FOUND", "Пользователь не найден.")
    if payload.username is not None:
        user.username = payload.username.strip()
    if payload.role is not None:
        user.role = valid_role(payload.role)
    if payload.is_active is not None:
        user.is_active = payload.is_active
    if payload.must_change_password is not None:
        user.must_change_password = payload.must_change_password
    user.updated_at = datetime.utcnow()
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise AppError(409, "USERNAME_EXISTS", "Пользователь с таким логином уже существует.") from exc
    audit(db, admin, "update_user", "user", user.id)
    db.commit()
    db.refresh(user)
    return user


@router.post("/users/{user_id}/password")
def set_user_password(user_id: int, payload: UserPasswordSet, admin: User = Depends(admin_user), db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if not user:
        raise AppError(404, "USER_NOT_FOUND", "Пользователь не найден.")
    policy = db.query(PasswordPolicy).order_by(PasswordPolicy.id).first()
    errors = validate_password_policy(payload.password, policy)
    if errors:
        raise AppError(400, "PASSWORD_POLICY_VIOLATION", " ".join(errors))
    user.password_hash = hash_password(payload.password)
    user.must_change_password = payload.must_change_password
    user.updated_at = datetime.utcnow()
    audit(db, admin, "set_user_password", "user", user.id)
    db.commit()
    return {"ok": True}


@router.get("/password-policy", response_model=PasswordPolicyOut)
def get_password_policy(_admin: User = Depends(admin_user), db: Session = Depends(get_db)):
    return db.query(PasswordPolicy).order_by(PasswordPolicy.id).first()


@router.put("/password-policy", response_model=PasswordPolicyOut)
def update_password_policy(payload: PasswordPolicyIn, admin: User = Depends(admin_user), db: Session = Depends(get_db)):
    policy = db.query(PasswordPolicy).order_by(PasswordPolicy.id).first()
    policy.min_length = payload.min_length
    policy.require_uppercase = payload.require_uppercase
    policy.require_lowercase = payload.require_lowercase
    policy.require_digit = payload.require_digit
    policy.require_special_char = payload.require_special_char
    policy.updated_at = datetime.utcnow()
    policy.updated_by = admin.id
    audit(db, admin, "update_password_policy", "password_policy", policy.id)
    db.commit()
    db.refresh(policy)
    return policy
