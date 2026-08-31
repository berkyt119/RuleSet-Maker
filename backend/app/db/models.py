from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="user")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class PasswordPolicy(Base):
    __tablename__ = "password_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    min_length: Mapped[int] = mapped_column(Integer, default=10)
    require_uppercase: Mapped[bool] = mapped_column(Boolean, default=True)
    require_lowercase: Mapped[bool] = mapped_column(Boolean, default=True)
    require_digit: Mapped[bool] = mapped_column(Boolean, default=True)
    require_special_char: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)


class DomainScan(Base):
    __tablename__ = "domain_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    input_domain: Mapped[str] = mapped_column(String(255))
    normalized_domain: Mapped[str] = mapped_column(String(255), index=True)
    status: Mapped[str] = mapped_column(String(32), default="PROCESSING")
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    results: Mapped[list["DomainScanResult"]] = relationship(cascade="all, delete-orphan", order_by="DomainScanResult.domain")


class DomainScanResult(Base):
    __tablename__ = "domain_scan_results"
    __table_args__ = (UniqueConstraint("scan_id", "domain", name="uq_scan_domain"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("domain_scans.id", ondelete="CASCADE"), index=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    source: Mapped[str] = mapped_column(String(64), default="discovery")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(120))
    entity: Mapped[str] = mapped_column(String(120))
    entity_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class UserDomainSelection(Base):
    __tablename__ = "user_domain_selections"
    __table_args__ = (UniqueConstraint("user_id", "service_key", name="uq_user_service_selection"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    service_key: Mapped[str] = mapped_column(String(512), index=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class UserCustomService(Base):
    __tablename__ = "user_custom_services"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    display_name: Mapped[str] = mapped_column(String(160))
    root_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    domains: Mapped[list["UserCustomDomain"]] = relationship(cascade="all, delete-orphan", order_by="UserCustomDomain.domain")
    cidrs: Mapped[list["UserCustomCidr"]] = relationship(cascade="all, delete-orphan", order_by="UserCustomCidr.cidr")


class UserCustomDomain(Base):
    __tablename__ = "user_custom_domains"
    __table_args__ = (UniqueConstraint("service_id", "domain", name="uq_custom_service_domain"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("user_custom_services.id", ondelete="CASCADE"), index=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class UserCustomCidr(Base):
    __tablename__ = "user_custom_cidrs"
    __table_args__ = (UniqueConstraint("service_id", "cidr", name="uq_custom_service_cidr"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("user_custom_services.id", ondelete="CASCADE"), index=True)
    cidr: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class UserRuleset(Base):
    __tablename__ = "user_rulesets"
    __table_args__ = (UniqueConstraint("user_id", name="uq_user_ruleset"), UniqueConstraint("public_token", name="uq_ruleset_public_token"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    domains_json: Mapped[str] = mapped_column(Text, default="[]")
    cidrs_json: Mapped[str] = mapped_column(Text, default="[]")
    domains_count: Mapped[int] = mapped_column(Integer, default=0)
    cidrs_count: Mapped[int] = mapped_column(Integer, default=0)
    public_token: Mapped[str] = mapped_column(String(96), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
