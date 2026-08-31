import re


def build_ruleset(domains: list[str], cidrs: list[str] | None = None) -> dict:
    unique = sorted({domain.strip().lower().rstrip(".") for domain in domains if domain and domain.strip()})
    unique_cidrs = sorted({cidr.strip() for cidr in cidrs or [] if cidr and cidr.strip()})
    rule = {}
    if unique:
        rule["domain_suffix"] = unique
    if unique_cidrs:
        rule["ip_cidr"] = unique_cidrs
    return {"version": 3, "rules": [rule]}


def safe_ruleset_filename(domain: str) -> str:
    safe = re.sub(r"[^a-z0-9.-]+", "-", domain.lower()).strip("-.") or "ruleset"
    return f"{safe.replace('.', '-')}-ruleset.json"
