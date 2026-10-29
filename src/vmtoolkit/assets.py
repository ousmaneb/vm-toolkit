"""Per-machine settings from [assets] in config.toml."""

from dataclasses import dataclass, field
from fnmatch import fnmatch

from .config import ConfigError, Settings

CRITICALITY = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}
DEFAULT_CRITICALITY = "medium"


@dataclass
class AssetConfig:
    criticality: str = DEFAULT_CRITICALITY
    internet_facing: bool = False
    aliases: list[str] = field(default_factory=list)
    # The [assets."..."] key that matched, or None when the defaults were used.
    matched: str | None = None

    @property
    def weight(self) -> float:
        return CRITICALITY[self.criticality]


def entries(settings: Settings) -> dict[str, dict]:
    raw = settings.section("assets")
    for key, entry in raw.items():
        if not isinstance(entry, dict):
            raise ConfigError(f'[assets."{key}"] must be a table, e.g. [assets."{key}"] criticality = "high"')
        level = entry.get("criticality", DEFAULT_CRITICALITY)
        if level not in CRITICALITY:
            raise ConfigError(f'[assets."{key}"] criticality must be one of {", ".join(CRITICALITY)}, not "{level}"')
    return raw


def asset_config(settings: Settings, name: str, ip: str | None = None) -> AssetConfig:
    """Find the settings for a machine. Exact names and aliases win over wildcard patterns."""
    names = {n.lower() for n in (name, ip) if n}
    all_entries = entries(settings)
    exact = [k for k, e in all_entries.items()
             if k.lower() in names or names & {a.lower() for a in e.get("aliases", [])}]
    patterns = [k for k in all_entries if any(ch in k for ch in "*?[") and any(fnmatch(n, k.lower()) for n in names)]
    for key in exact + patterns:
        e = all_entries[key]
        return AssetConfig(
            criticality=e.get("criticality", DEFAULT_CRITICALITY),
            internet_facing=bool(e.get("internet_facing", False)),
            aliases=list(e.get("aliases", [])),
            matched=key,
        )
    return AssetConfig()
