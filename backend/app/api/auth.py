from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import current_user
from app.core.errors import AppError
from app.core.security import create_access_token, hash_password, verify_password
from app.db.models import PasswordPolicy, User
from app.db.session import get_db
from app.schemas import ChangePasswordIn, LoginIn, TokenOut, UserOut
from app.services.audit import audit
from app.services.password_policy import validate_password_policy


router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=TokenOut)
def login(payload: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username.strip()).first()
    if not user or not user.is_active or not verify_password(payload.password, user.password_hash):
        audit(db, user, "login_failed", "auth", details=payload.username.strip())
        db.commit()
        raise AppError(401, "INVALID_CREDENTIALS", "Неверный логин или пароль.")
    user.last_login_at = datetime.utcnow()
    audit(db, user, "login_success", "auth")
    db.commit()
    return TokenOut(access_token=create_access_token(str(user.id)), must_change_password=user.must_change_password)


@router.post("/logout")
def logout(user: User = Depends(current_user), db: Session = Depends(get_db)):
    audit(db, user, "logout", "auth")
    db.commit()
    return {"ok": True}


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user


@router.post("/change-password")
def change_password(payload: ChangePasswordIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not verify_password(payload.current_password, user.password_hash):
        raise AppError(400, "INVALID_CURRENT_PASSWORD", "Текущий пароль указан неверно.")
    if payload.new_password != payload.confirm_password:
        raise AppError(400, "PASSWORD_CONFIRMATION_MISMATCH", "Новый пароль и подтверждение не совпадают.")
    policy = db.query(PasswordPolicy).order_by(PasswordPolicy.id).first()
    errors = validate_password_policy(payload.new_password, policy)
    if errors:
        raise AppError(400, "PASSWORD_POLICY_VIOLATION", " ".join(errors))
    user.password_hash = hash_password(payload.new_password)
    user.must_change_password = False
    user.updated_at = datetime.utcnow()
    audit(db, user, "change_password", "user", user.id)
    db.commit()
    return {"ok": True}
