from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.admin import delete_user, get_password_policy, update_password_policy, update_user
from app.core.errors import AppError
from app.db.models import GlobalDomainSelection, PasswordPolicy, User, UserCustomService
from app.db.session import Base
from app.schemas import PasswordPolicyIn, UserUpdate
from app.services.domain_catalog import all_catalog_services, selection_map
from app.services.password_policy import validate_password_policy
from app.services.domain_catalog import validate_public_cidr
from app.services.prefix_finder import normalize_discovery_result, validate_domain
from app.services.ruleset_generator import build_ruleset, safe_ruleset_filename


def test_domain_validation_accepts_valid_domain():
    assert validate_domain("YouTube.COM.") == "youtube.com"


def test_domain_validation_rejects_invalid_domain():
    try:
        validate_domain("not a domain")
    except ValueError:
        return
    raise AssertionError("invalid domain was accepted")


def test_discovery_result_is_deduplicated_sorted_and_filtered():
    result = normalize_discovery_result(
        "youtube.com",
        {
            "v2fly": {"googlevideo.com", "youtube.com", "doubleclick.net", "GOOGLEVIDEO.COM."},
            "browser": {"ytimg.com", "bad value"},
        },
    )
    assert result == [
        {"domain": "googlevideo.com", "source": "v2fly"},
        {"domain": "youtube.com", "source": "root+v2fly"},
        {"domain": "ytimg.com", "source": "browser"},
    ]


def test_ruleset_generator_deduplicates_and_sorts():
    assert build_ruleset(["youtube.com", "", "googlevideo.com", "youtube.com."]) == {
        "version": 3,
        "rules": [{"domain_suffix": ["googlevideo.com", "youtube.com"]}],
    }


def test_ruleset_generator_supports_ip_cidr():
    assert build_ruleset(["example.com"], ["8.8.8.8/32"]) == {
        "version": 3,
        "rules": [{"domain_suffix": ["example.com"], "ip_cidr": ["8.8.8.8/32"]}],
    }


def test_public_cidr_validation_rejects_private_ranges():
    assert validate_public_cidr("8.8.8.8/32") == "8.8.8.8/32"
    for value in ["127.0.0.1/32", "10.0.0.0/8", "192.168.1.1/32", "224.0.0.0/4"]:
        try:
            validate_public_cidr(value)
        except ValueError:
            continue
        raise AssertionError(f"private or special CIDR was accepted: {value}")


def test_safe_ruleset_filename():
    assert safe_ruleset_filename("youtube.com") == "youtube-com-ruleset.json"


def test_password_policy_validation():
    policy = PasswordPolicy(min_length=10, require_uppercase=True, require_lowercase=True, require_digit=True, require_special_char=True)
    assert validate_password_policy("Strong123!", policy) == []
    assert validate_password_policy("weak", policy)


def test_custom_services_are_global_between_users():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    db = sessionmaker(bind=engine)()
    admin = User(username="admin", password_hash="x", role="admin", is_active=True)
    user = User(username="user", password_hash="x", role="user", is_active=True)
    db.add_all([admin, user])
    db.flush()
    db.add(UserCustomService(user_id=admin.id, name="Shared", display_name="Shared", root_domain="shared.example"))
    db.commit()

    services, _generated_at, _error = all_catalog_services(db, user)

    assert any(service.display_name == "Shared" for service in services)


def test_domain_selection_is_global_between_users():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    db = sessionmaker(bind=engine)()
    first = User(username="first", password_hash="x", role="user", is_active=True)
    second = User(username="second", password_hash="x", role="user", is_active=True)
    db.add_all([first, second, GlobalDomainSelection(service_key="service::one", is_enabled=True)])
    db.commit()

    assert selection_map(db, first) == {"service::one": True}
    assert selection_map(db, second) == {"service::one": True}


def test_password_policy_update_is_persisted():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    db = sessionmaker(bind=engine)()
    admin = User(username="admin", password_hash="x", role="admin", is_active=True)
    db.add(admin)
    db.commit()
    db.refresh(admin)

    update_password_policy(
        PasswordPolicyIn(
            min_length=14,
            require_uppercase=False,
            require_lowercase=True,
            require_digit=False,
            require_special_char=True,
        ),
        admin,
        db,
    )
    saved = get_password_policy(admin, db)

    assert saved.min_length == 14
    assert saved.require_uppercase is False
    assert saved.require_lowercase is True
    assert saved.require_digit is False
    assert saved.require_special_char is True


def test_admin_can_disable_user_account():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    db = sessionmaker(bind=engine)()
    admin = User(username="admin", password_hash="x", role="admin", is_active=True)
    user = User(username="user", password_hash="x", role="user", is_active=True)
    db.add_all([admin, user])
    db.commit()
    db.refresh(admin)
    db.refresh(user)

    updated = update_user(user.id, UserUpdate(is_active=False), admin, db)

    assert updated.is_active is False


def test_admin_can_delete_user_account():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    db = sessionmaker(bind=engine)()
    admin = User(username="admin", password_hash="x", role="admin", is_active=True)
    user = User(username="user", password_hash="x", role="user", is_active=True)
    db.add_all([admin, user])
    db.commit()
    db.refresh(admin)
    user_id = user.id

    delete_user(user_id, admin, db)

    assert db.get(User, user_id) is None


def test_admin_cannot_delete_self():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    db = sessionmaker(bind=engine)()
    admin = User(username="admin", password_hash="x", role="admin", is_active=True)
    db.add(admin)
    db.commit()
    db.refresh(admin)

    try:
        delete_user(admin.id, admin, db)
    except AppError as exc:
        assert exc.detail["code"] == "CANNOT_DISABLE_SELF"
        return
    raise AssertionError("admin deleted own account")


def test_admin_cannot_disable_self():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    db = sessionmaker(bind=engine)()
    admin = User(username="admin", password_hash="x", role="admin", is_active=True)
    db.add(admin)
    db.commit()
    db.refresh(admin)

    try:
        update_user(admin.id, UserUpdate(is_active=False), admin, db)
    except AppError as exc:
        assert exc.detail["code"] == "CANNOT_DISABLE_SELF"
        return
    raise AssertionError("admin disabled own account")
