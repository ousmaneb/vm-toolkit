import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

DEFAULTS = {
    "paths": {"data_dir": "data"},
    "nessus": {
        "url": "https://localhost:8834",
        "ca_cert": "",
        "verify_tls": True,
        "export_timeout": 300,
    },
    "import": {"include_info": False},
    "sla_days": {"critical": 15, "high": 30, "medium": 90, "low": 180},
}

# Every secret read through get_secret is remembered so log output can be scrubbed.
_secret_values: set[str] = set()


class ConfigError(Exception):
    pass


def _merge(base: dict, override: dict) -> dict:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = value
    return merged


@dataclass
class Settings:
    raw: dict
    base_dir: Path
    offline: bool = False
    db_override: Path | None = None

    def section(self, name: str) -> dict:
        return self.raw.get(name, {})

    def resolve(self, value: str | Path) -> Path:
        path = Path(value).expanduser()
        return path if path.is_absolute() else self.base_dir / path

    @property
    def data_dir(self) -> Path:
        return self.resolve(self.raw["paths"]["data_dir"])

    @property
    def db_path(self) -> Path:
        if self.db_override:
            return self.db_override
        return self.data_dir / "vmt.db"

    @property
    def cache_path(self) -> Path:
        return self.data_dir / "cache.sqlite"

    @property
    def raw_dir(self) -> Path:
        return self.data_dir / "raw"


def load_settings(config_path: Path | None = None, offline: bool = False, db: Path | None = None) -> Settings:
    if config_path is None and os.environ.get("VMT_CONFIG"):
        config_path = Path(os.environ["VMT_CONFIG"])
    if config_path is None:
        config_path = Path.cwd() / "config.toml"
    elif not config_path.exists():
        raise ConfigError(f"Config file not found: {config_path}")

    raw = DEFAULTS
    if config_path.exists():
        try:
            raw = _merge(DEFAULTS, tomllib.loads(config_path.read_text(encoding="utf-8")))
        except tomllib.TOMLDecodeError as e:
            raise ConfigError(f"{config_path} is not valid TOML: {e}") from None

    base_dir = config_path.resolve().parent
    load_dotenv(base_dir / ".env", override=False)
    return Settings(raw=raw, base_dir=base_dir, offline=offline, db_override=db)


def get_secret(name: str, required: bool = False) -> str | None:
    value = os.environ.get(name, "").strip()
    if value:
        _secret_values.add(value)
        return value
    if required:
        raise ConfigError(f"{name} is not set. Add it to your .env file.")
    return None


def redact(text: str) -> str:
    for value in _secret_values:
        text = text.replace(value, "***")
    return text


class RedactSecrets(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.getMessage())
        record.args = ()
        return True
