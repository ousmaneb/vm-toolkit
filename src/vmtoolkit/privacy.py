"""Replace machine names, FQDNs and IP addresses with placeholders before text goes to an AI API."""

import ipaddress
import re
import sqlite3

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b", re.IGNORECASE)
PLACEHOLDER_RE = re.compile(r"\b(?:MACHINE|IP)_\d+\b")


class Redactor:
    """Consistent placeholders for one request: the same machine always becomes the same MACHINE_n."""

    def __init__(self, conn: sqlite3.Connection, enabled: bool = True):
        self.enabled = enabled
        self.forward: dict[str, str] = {}
        self.back: dict[str, str] = {}
        # Every name a machine goes by (name, FQDN, short host name) maps to that machine's row.
        self.aliases: dict[str, tuple[int, str]] = {}
        if enabled:
            for row in conn.execute("SELECT id, name, fqdn, ip FROM assets ORDER BY id"):
                for value in (row["name"], row["fqdn"]):
                    if not value or IPV4_RE.fullmatch(value):
                        continue
                    for alias in (value, value.split(".")[0]):
                        if len(alias) >= 3:
                            self.aliases.setdefault(alias.lower(), (row["id"], row["name"]))
        # Longest first, so "web-01.lab" is replaced before "web-01".
        self.names = sorted(self.aliases, key=len, reverse=True)

    def _token(self, key: str, kind: str, original: str) -> str:
        if key not in self.forward:
            count = sum(1 for t in self.back if t.startswith(kind)) + 1
            token = f"{kind}_{count}"
            self.forward[key], self.back[token] = token, original
        return self.forward[key]

    def redact(self, text: str | None) -> str:
        if not text or not self.enabled:
            return text or ""
        for name in self.names:
            asset_id, canonical = self.aliases[name]
            text = re.sub(rf"(?<![\w.-]){re.escape(name)}(?![\w-])",
                          lambda m: self._token(f"asset:{asset_id}", "MACHINE", canonical), text, flags=re.IGNORECASE)

        def ip(m: re.Match) -> str:
            try:
                ipaddress.ip_address(m.group(0))
            except ValueError:
                return m.group(0)  # something like a version number "1.2.3.4" that isn't a valid address
            return self._token(m.group(0), "IP", m.group(0))

        text = IPV4_RE.sub(ip, text)
        return IPV6_RE.sub(ip, text)

    def restore(self, text: str) -> str:
        return PLACEHOLDER_RE.sub(lambda m: self.back.get(m.group(0), m.group(0)), text)
