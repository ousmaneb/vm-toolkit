"""One cached HTTP session for every outside website the toolkit talks to."""

from datetime import timedelta

import requests
import requests_cache

from . import __version__
from .config import Settings

# Hours each source is cached for, unless overridden in [cache] in config.toml.
DEFAULT_TTL_HOURS = {
    "kev": 12,
    "epss": 12,
    "nvd": 168,
    "exploits": 168,
    "osv": 24,
    "github": 6,
    # Anything not listed in SOURCE_URLS, such as news feeds and advisory pages.
    "default": 6,
}
SOURCE_URLS = {
    "kev": "www.cisa.gov",
    "epss": "api.first.org",
    "nvd": "services.nvd.nist.gov",
    "exploits": ["gitlab.com/exploit-database", "raw.githubusercontent.com/rapid7"],
    "osv": "api.osv.dev",
    "github": "api.github.com",
}
# Headers and parameters that carry API keys. requests-cache leaves them out of cache keys
# and redacts them from the cached copy of each request stored on disk.
SECRET_PARAMS = ["apiKey", "Authorization", "X-API-KEY", "api_key", "access_token"]


class WebError(Exception):
    pass


def web_session(settings: Settings) -> requests_cache.CachedSession:
    ttl = {**DEFAULT_TTL_HOURS, **settings.section("cache")}
    urls_expire_after = {}
    for source, patterns in SOURCE_URLS.items():
        for pattern in [patterns] if isinstance(patterns, str) else patterns:
            urls_expire_after[pattern] = timedelta(hours=float(ttl[source]))
    settings.cache_path.parent.mkdir(parents=True, exist_ok=True)
    session = requests_cache.CachedSession(
        str(settings.cache_path),
        backend="sqlite",
        urls_expire_after=urls_expire_after,
        allowable_methods=("GET", "POST"),
        allowable_codes=(200,),
        expire_after=timedelta(hours=float(ttl["default"])),
        stale_if_error=True,
        ignored_parameters=SECRET_PARAMS,
    )
    session.headers["User-Agent"] = f"vmtoolkit/{__version__}"
    if settings.offline:
        session.settings.only_if_cached = True
        session.settings.expire_after = requests_cache.NEVER_EXPIRE
        session.settings.urls_expire_after = {}
    return session


def fetch(session: requests.Session, method: str, url: str, **kwargs) -> requests.Response:
    try:
        resp = session.request(method, url, timeout=kwargs.pop("timeout", 60), **kwargs)
    except requests.exceptions.RequestException as e:
        raise WebError(f"Request to {url} failed: {type(e).__name__}") from None
    if resp.status_code == 504 and getattr(session, "settings", None) and session.settings.only_if_cached:
        raise WebError(f"Offline mode: {url} is not in the cache yet. Run once without --offline.")
    return resp
