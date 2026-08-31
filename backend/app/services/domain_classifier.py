import tldextract


NEGATIVE_EXACT_DOMAINS = {
    "2mdn.net",
    "adform.net",
    "adnxs.com",
    "adsrvr.org",
    "advertising.com",
    "app-measurement.com",
    "appsflyer.com",
    "adjust.com",
    "bingads.microsoft.com",
    "criteo.com",
    "criteo.net",
    "demdex.net",
    "doubleclick.net",
    "facebook.net",
    "flurry.com",
    "google-analytics.com",
    "googleadservices.com",
    "googlesyndication.com",
    "googletagmanager.com",
    "hotjar.com",
    "mixpanel.com",
    "scorecardresearch.com",
    "segment.io",
    "sentry.io",
    "taboola.com",
    "yandexmetrica.com",
}

NEGATIVE_SUFFIX_DOMAINS = NEGATIVE_EXACT_DOMAINS
NEGATIVE_KEYWORDS = {"ads", "adserver", "adservice", "doubleclick", "remarketing", "retargeting", "tagmanager", "telemetry", "tracker", "tracking"}


def registrable_domain(hostname: str) -> str:
    ext = tldextract.extract(hostname)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return hostname


def same_or_subdomain(hostname: str, parent: str) -> bool:
    return hostname == parent or hostname.endswith(f".{parent}")


def should_reject_domain(domain: str, service_root_domain: str) -> bool:
    hostname = domain.strip().lower().rstrip(".")
    if same_or_subdomain(hostname, service_root_domain):
        return False
    root = registrable_domain(hostname)
    if hostname in NEGATIVE_EXACT_DOMAINS or root in NEGATIVE_EXACT_DOMAINS:
        return True
    for suffix in NEGATIVE_SUFFIX_DOMAINS:
        if same_or_subdomain(hostname, suffix) or same_or_subdomain(root, suffix):
            return True
    tokens = set(hostname.replace("_", "-").replace(".", "-").split("-"))
    return bool(tokens & NEGATIVE_KEYWORDS)
