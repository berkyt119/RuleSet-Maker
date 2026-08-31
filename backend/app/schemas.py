from datetime import datetime

from pydantic import BaseModel, Field


class ApiError(BaseModel):
    code: str
    message: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    must_change_password: bool = False


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class UserOut(BaseModel):
    id: int
    username: str
    role: str
    is_active: bool
    must_change_password: bool
    created_at: datetime
    updated_at: datetime
    last_login_at: datetime | None = None

    class Config:
        from_attributes = True


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=1, max_length=128)
    role: str = "user"
    must_change_password: bool = True


class UserUpdate(BaseModel):
    username: str | None = Field(default=None, min_length=3, max_length=64)
    role: str | None = None
    is_active: bool | None = None
    must_change_password: bool | None = None


class UserPasswordSet(BaseModel):
    password: str = Field(min_length=1, max_length=128)
    must_change_password: bool = True


class ChangePasswordIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=1, max_length=128)
    confirm_password: str = Field(min_length=1, max_length=128)


class PasswordPolicyIn(BaseModel):
    min_length: int = Field(ge=6, le=128)
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digit: bool = True
    require_special_char: bool = True


class PasswordPolicyOut(PasswordPolicyIn):
    id: int
    updated_at: datetime
    updated_by: int | None = None

    class Config:
        from_attributes = True


class DomainScanIn(BaseModel):
    domain: str = Field(min_length=3, max_length=255)


class DomainResultOut(BaseModel):
    domain: str
    source: str

    class Config:
        from_attributes = True


class DomainScanOut(BaseModel):
    id: int
    input_domain: str
    normalized_domain: str
    status: str
    error_code: str | None = None
    error_message: str | None = None
    domains_count: int = 0
    domains: list[DomainResultOut] = []
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None

    class Config:
        from_attributes = True


class DomainScanStarted(BaseModel):
    id: int
    status: str


class RulesetOut(BaseModel):
    version: int
    rules: list[dict[str, list[str]]]


class SelectionIn(BaseModel):
    enabled_service_keys: list[str]


class CustomServiceIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    root_domain: str | None = Field(default=None, max_length=255)


class CustomDomainIn(BaseModel):
    domain: str = Field(min_length=3, max_length=255)
    value_type: str = "domain"
