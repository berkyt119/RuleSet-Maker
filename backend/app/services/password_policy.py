import re

from app.db.models import PasswordPolicy


SPECIAL_RE = re.compile(r"[^A-Za-z0-9]")


def validate_password_policy(password: str, policy: PasswordPolicy) -> list[str]:
    errors = []
    if len(password) < policy.min_length:
        errors.append(f"Пароль должен быть не короче {policy.min_length} символов.")
    if policy.require_uppercase and not any(char.isupper() for char in password):
        errors.append("Пароль должен содержать прописную букву.")
    if policy.require_lowercase and not any(char.islower() for char in password):
        errors.append("Пароль должен содержать строчную букву.")
    if policy.require_digit and not any(char.isdigit() for char in password):
        errors.append("Пароль должен содержать цифру.")
    if policy.require_special_char and not SPECIAL_RE.search(password):
        errors.append("Пароль должен содержать специальный символ.")
    return errors
