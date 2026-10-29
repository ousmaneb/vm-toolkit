"""Dashboard accounts: salted scrypt password hashes, and a lockout after repeated wrong passwords."""

import base64
import hashlib
import hmac
import os
import secrets
import sqlite3
from datetime import timedelta

from .config import ConfigError
from .db import parse_iso, to_iso, utcnow

MIN_LENGTH = 12
SESSION = timedelta(hours=8)
MAX_FAILURES = 5
LOCKOUT = timedelta(minutes=15)
SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1}
WRONG = "Wrong username or password."


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, **SCRYPT)
    return "scrypt${n}${r}${p}${salt}${digest}".format(
        **SCRYPT, salt=base64.b64encode(salt).decode(), digest=base64.b64encode(digest).decode())


def check_password(password: str, stored: str) -> bool:
    _, n, r, p, salt, digest = stored.split("$")
    actual = hashlib.scrypt(password.encode("utf-8"), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p))
    return hmac.compare_digest(actual, base64.b64decode(digest))


# Checked against when the username doesn't exist, so a wrong username takes as long as a wrong password.
_DUMMY = hash_password(secrets.token_hex(16))


def _check_new(username: str, password: str) -> None:
    if not username or not username.replace(".", "").replace("-", "").replace("_", "").replace("@", "").isalnum():
        raise ConfigError("Usernames may contain letters, digits, '.', '-', '_' and '@'.")
    if len(password) < MIN_LENGTH:
        raise ConfigError(f"Passwords must be at least {MIN_LENGTH} characters.")


def add_user(conn: sqlite3.Connection, username: str, password: str) -> None:
    username = username.strip().lower()
    _check_new(username, password)
    with conn:
        if conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
            raise ConfigError(f"User {username} already exists. Use `vmt users passwd` to change the password.")
        conn.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                     (username, hash_password(password), utcnow()))


def set_password(conn: sqlite3.Connection, username: str, password: str) -> None:
    username = username.strip().lower()
    _check_new(username, password)
    with conn:
        changed = conn.execute("UPDATE users SET password_hash = ?, failed_logins = 0, locked_until = NULL "
                               "WHERE username = ?", (hash_password(password), username)).rowcount
    if not changed:
        raise ConfigError(f"No user called {username}.")
    end_sessions(conn, username)


def remove_user(conn: sqlite3.Connection, username: str) -> bool:
    end_sessions(conn, username)
    with conn:
        return conn.execute("DELETE FROM users WHERE username = ?", (username.strip().lower(),)).rowcount > 0


def list_users(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT username, created_at, last_login_at, failed_logins, locked_until "
                        "FROM users ORDER BY username").fetchall()


def has_users(conn: sqlite3.Connection) -> bool:
    return conn.execute("SELECT EXISTS (SELECT 1 FROM users)").fetchone()[0] == 1


def authenticate(conn: sqlite3.Connection, username: str, password: str) -> tuple[bool, str]:
    """(signed in, message). The message never says whether the username exists."""
    username = username.strip().lower()
    now = parse_iso(utcnow())
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if row is None:
        check_password(password, _DUMMY)
        return False, WRONG
    if row["locked_until"] and parse_iso(row["locked_until"]) > now:
        return False, "Too many wrong passwords. Try again in 15 minutes."
    if not check_password(password, row["password_hash"]):
        failed = row["failed_logins"] + 1
        locked = to_iso(now + LOCKOUT) if failed >= MAX_FAILURES else None
        with conn:
            conn.execute("UPDATE users SET failed_logins = ?, locked_until = ? WHERE username = ?",
                         (0 if locked else failed, locked, username))
        return False, WRONG
    with conn:
        conn.execute("UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = ? WHERE username = ?",
                     (utcnow(), username))
    return True, ""


def bootstrap(conn: sqlite3.Connection) -> str | None:
    """Create the first account from VMT_ADMIN_USER / VMT_ADMIN_PASSWORD, only while there are no accounts."""
    username, password = os.environ.get("VMT_ADMIN_USER", ""), os.environ.get("VMT_ADMIN_PASSWORD", "")
    if not username or not password or has_users(conn):
        return None
    add_user(conn, username, password)
    return f"Created the first dashboard account, {username.strip().lower()}. You can remove VMT_ADMIN_PASSWORD now."


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def start_session(conn: sqlite3.Connection, username: str) -> str:
    """A new random session token. The browser keeps the token; the database keeps only its hash."""
    token = secrets.token_urlsafe(32)
    now = parse_iso(utcnow())
    with conn:
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (to_iso(now),))
        conn.execute("INSERT INTO sessions (token_hash, username, created_at, expires_at) VALUES (?, ?, ?, ?)",
                     (_token_hash(token), username, to_iso(now), to_iso(now + SESSION)))
    return token


def session_user(conn: sqlite3.Connection, token: str | None) -> str | None:
    if not token:
        return None
    row = conn.execute("SELECT username, expires_at FROM sessions WHERE token_hash = ?",
                       (_token_hash(token),)).fetchone()
    if row is None or parse_iso(row["expires_at"]) <= parse_iso(utcnow()):
        return None
    return row["username"]


def end_session(conn: sqlite3.Connection, token: str | None) -> None:
    if token:
        with conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(token),))


def end_sessions(conn: sqlite3.Connection, username: str) -> None:
    with conn:
        conn.execute("DELETE FROM sessions WHERE username = ?", (username.strip().lower(),))
