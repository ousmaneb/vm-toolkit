"""Sign-in for the dashboard. Accounts live in the main database, whichever database the sidebar shows."""

import logging
import os
import threading
import time

import streamlit as st

from vmtoolkit import db
from vmtoolkit.config import Settings, production
from vmtoolkit.users import authenticate, end_session, has_users, session_user, start_session

COOKIE = "vmt_session"
audit = logging.getLogger("vmtoolkit.audit")


class Throttle:
    """Failed sign-ins per client address. Limits guessing across many usernames, which the per-account
    lockout doesn't. Kept in memory: a restart clears it, which is also the way out of a false block."""

    def __init__(self, limit: int = 20, window: float = 15 * 60):
        self.limit, self.window = limit, window
        self.failures: dict[str, list[float]] = {}
        self.lock = threading.Lock()

    def _recent(self, address: str, now: float) -> list[float]:
        recent = [t for t in self.failures.get(address, []) if now - t < self.window]
        self.failures[address] = recent
        return recent

    def blocked(self, address: str, now: float | None = None) -> bool:
        with self.lock:
            return len(self._recent(address, now or time.time())) >= self.limit

    def failed(self, address: str, now: float | None = None) -> None:
        now = now or time.time()
        with self.lock:
            self._recent(address, now).append(now)


THROTTLE = Throttle()


def client_address(headers, direct: str | None) -> str:
    """The visitor's address. Behind a proxy (Railway, a load balancer) it is the entry the last trusted
    proxy appended to X-Forwarded-For; VMT_PROXY_HOPS says how many proxies sit in front of the app."""
    forwarded = [p.strip() for p in (headers.get("X-Forwarded-For") or "").split(",") if p.strip()]
    hops = max(int(os.environ.get("VMT_PROXY_HOPS", "1")), 1)
    if forwarded:
        return forwarded[-hops] if len(forwarded) >= hops else forwarded[0]
    return direct or "unknown"


def _cookie() -> str | None:
    value = st.context.cookies.get(COOKIE)
    return value if isinstance(value, str) else None  # the test harness has no real cookies


def required(settings: Settings) -> bool:
    if production():
        return True
    conn = db.connect(settings.data_dir / "vmt.db")
    try:
        return has_users(conn)
    finally:
        conn.close()


def _set_cookie(token: str, max_age: int):
    # Set from the page because Streamlit has no API for it. SameSite=Strict keeps it off cross-site
    # requests; Secure is added whenever the dashboard is served over HTTPS.
    st.html(f"""<script>document.cookie = "{COOKIE}={token}; Path=/; Max-Age={max_age}; SameSite=Strict"
        + (location.protocol === "https:" ? "; Secure" : "");</script>""", unsafe_allow_javascript=True)


def require_login(settings: Settings) -> str | None:
    """The signed-in username, None when sign-in isn't needed; otherwise shows the form and stops the page."""
    if not required(settings):
        return None
    # Cookies are written on the run after sign-in or sign-out, because st.rerun() would drop the script.
    if "pending_cookie" in st.session_state:
        token = st.session_state.pop("pending_cookie")
        _set_cookie(token, 8 * 3600 if token else 0)
    # This tab's own token first: st.context.cookies is read once, when the tab connects, so it can be stale.
    conn = db.connect(settings.data_dir / "vmt.db")
    try:
        user = session_user(conn, st.session_state.get("token")) or session_user(conn, _cookie())
    finally:
        conn.close()
    if user:
        st.session_state.user = user
        return user

    _, middle, _ = st.columns([1, 1.2, 1])
    with middle:
        st.title("Sign in")
        st.caption("Vulnerability management dashboard")
        with st.form("sign-in"):
            username = st.text_input("Username", autocomplete="username")
            password = st.text_input("Password", type="password", autocomplete="current-password")
            submitted = st.form_submit_button("Sign in", type="primary", width="stretch")
        if submitted:
            address = client_address(st.context.headers, st.context.ip_address)
            name = username.strip().lower()
            if THROTTLE.blocked(address):
                audit.warning("sign-in refused for %r from %s: too many failures from this address", name, address)
                st.error("Too many failed sign-ins from your network. Try again in 15 minutes.",
                         icon=":material/error:")
                st.stop()
            conn = db.connect(settings.data_dir / "vmt.db")
            try:
                ok, message = authenticate(conn, username, password)
                token = start_session(conn, name) if ok else None
            finally:
                conn.close()
            if ok:
                st.session_state.token = token
                st.session_state.pending_cookie = token
                audit.info("%s signed in from %s", name, address)
                st.rerun()
            THROTTLE.failed(address)
            audit.warning("failed sign-in for %r from %s", name, address)
            time.sleep(1)  # slows scripted guessing; a person won't notice
            st.error(message, icon=":material/error:")
    st.stop()


def sign_out_button(user: str, settings: Settings):
    with st.sidebar:
        st.caption(f"Signed in as **{user}**")
        if st.button("Sign out", icon=":material/logout:"):
            conn = db.connect(settings.data_dir / "vmt.db")
            try:
                end_session(conn, st.session_state.get("token"))
                end_session(conn, _cookie())
            finally:
                conn.close()
            audit.info("%s signed out", user)
            for key in ("token", "user"):
                st.session_state.pop(key, None)
            st.session_state.pending_cookie = ""
            st.rerun()
