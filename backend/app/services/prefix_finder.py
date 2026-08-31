import asyncio
import json
import re
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

import tldextract

from app.core.config import get_settings
from app.services.domain_classifier import should_reject_domain


USER_AGENT = "dogma-vpn-prefix-finder/0.1"
V2FLY_RAW_BASE = "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data"
DOMAIN_RE = re.compile(r"^(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$")


class PrefixFinderError(RuntimeError):
    pass


def normalize_hostname(value: str | None) -> str:
    return (value or "").strip().lower().rstrip(".")


def normalize_domain(value: str | None) -> str:
    hostname = normalize_hostname(value)
    ext = tldextract.extract(hostname)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return hostname


def validate_domain(value: str | None) -> str:
    domain = normalize_hostname(value)
    if not DOMAIN_RE.match(domain):
        raise ValueError("Указано некорректное доменное имя.")
    return domain


def service_key(name: str) -> str:
    return re.sub(r"[^a-z0-9_-]+", "", name.lower().replace(" ", "-"))


def v2fly_auto_keys(name: str, root_domain: str | None = None) -> list[str]:
    keys = []
    root = normalize_hostname(root_domain)
    if root:
        keys.append(root)
        labels = [label for label in root.split(".") if label]
        if labels:
            keys.append(labels[0])
        if len(labels) > 2:
            keys.append(".".join(labels[:-1]))
    key_from_name = service_key(name)
    if key_from_name:
        keys.append(key_from_name)
    return list(dict.fromkeys(keys))


def http_text(url: str, timeout: int = 15) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def v2fly_domains(name: str, root_domain: str | None = None, v2fly_key: str | None = None) -> set[str]:
    candidates = set()
    keys = [v2fly_key.strip()] if v2fly_key and v2fly_key.strip() else v2fly_auto_keys(name, root_domain)
    for key in dict.fromkeys(item for item in keys if item):
        if key.startswith("https://github.com/") and "/blob/" in key:
            key = key.replace("https://github.com/", "https://raw.githubusercontent.com/").replace("/blob/", "/", 1)
        try:
            raw = http_text(key if key.startswith(("http://", "https://")) else f"{V2FLY_RAW_BASE}/{key}")
        except Exception:
            continue
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("include:"):
                continue
            line = line.split("@", 1)[0]
            for prefix in ["domain:", "full:", "regexp:"]:
                if line.startswith(prefix):
                    line = line[len(prefix):]
            hostname = normalize_hostname(line)
            if DOMAIN_RE.match(hostname):
                candidates.add(hostname)
    return candidates


async def browser_domains(root_domain: str, wait_seconds: int = 8) -> set[str]:
    settings = get_settings()
    if not settings.enable_browser_discovery:
        return set()
    try:
        from playwright.async_api import async_playwright
    except Exception:
        return set()

    found = set()
    url = root_domain if root_domain.startswith(("http://", "https://")) else f"https://{root_domain}"
    try:
        async with async_playwright() as p:
            executable_path = "/usr/bin/chromium" if Path("/usr/bin/chromium").exists() else None
            browser = await p.chromium.launch(headless=True, executable_path=executable_path, args=["--no-sandbox"])
            page = await browser.new_page()

            def capture(request):
                hostname = urlparse(request.url).hostname
                if hostname:
                    normalized = normalize_hostname(hostname)
                    if DOMAIN_RE.match(normalized):
                        found.add(normalized)

            page.on("request", capture)
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            await page.wait_for_timeout(wait_seconds * 1000)
            await browser.close()
    except Exception:
        pass
    return found


def normalize_discovery_result(root_domain: str, source_map: dict[str, set[str]]) -> list[dict[str, str]]:
    normalized_root = validate_domain(root_domain)
    merged: dict[str, list[str]] = {normalized_root: ["root"]}
    for source, domains in source_map.items():
        for domain in domains:
            hostname = normalize_hostname(domain)
            if not DOMAIN_RE.match(hostname):
                continue
            if should_reject_domain(hostname, normalized_root):
                continue
            merged.setdefault(hostname, [])
            if source not in merged[hostname]:
                merged[hostname].append(source)
    return [{"domain": domain, "source": "+".join(sources)} for domain, sources in sorted(merged.items())]


async def discover_related_domains(domain: str) -> list[dict[str, str]]:
    root = validate_domain(domain)
    try:
        browser, v2fly = await asyncio.wait_for(
            asyncio.gather(browser_domains(root), asyncio.to_thread(v2fly_domains, root, root)),
            timeout=get_settings().prefix_finder_timeout_seconds,
        )
    except asyncio.TimeoutError as exc:
        raise PrefixFinderError("Превышено время выполнения анализа.") from exc
    except Exception as exc:
        raise PrefixFinderError("Не удалось выполнить анализ домена.") from exc
    return normalize_discovery_result(root, {"browser": browser, "v2fly": v2fly})


def run_related_domains(domain: str) -> list[dict[str, str]]:
    return asyncio.run(discover_related_domains(domain))
