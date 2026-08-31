from app.db.models import PasswordPolicy
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
