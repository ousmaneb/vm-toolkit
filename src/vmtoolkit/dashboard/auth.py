"""Sign-in for the dashboard. Accounts live in the main database, whichever database the sidebar shows."""

import logging
import time

import streamlit as st

from vmtoolkit import db
from vmtoolkit.config import Settings, production
from vmtoolkit.users import authenticate, has_users

SESSION_HOURS = 8
audit = logging.getLogger("vmtoolkit.audit")


def required(settings: Settings) -> bool:
    if production():
        return True
    conn = db.connect(settings.data_dir / "vmt.db")
    try:
        return has_users(conn)
    finally:
        conn.close()


def current_user() -> str | None:
    started = st.session_state.get("signed_in_at", 0)
    if st.session_state.get("user") and time.time() - started < SESSION_HOURS * 3600:
        return st.session_state.user
    return None


def require_login(settings: Settings) -> str | None:
    """The signed-in username, None when sign-in isn't needed; otherwise shows the form and stops the page."""
    if not required(settings):
        return None
    user = current_user()
    if user:
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
            conn = db.connect(settings.data_dir / "vmt.db")
            try:
                ok, message = authenticate(conn, username, password)
            finally:
                conn.close()
            if ok:
                st.session_state.user = username.strip().lower()
                st.session_state.signed_in_at = time.time()
                audit.info("%s signed in", st.session_state.user)
                st.rerun()
            audit.warning("failed sign-in for %r", username.strip().lower())
            st.error(message, icon=":material/error:")
    st.stop()


def sign_out_button(user: str):
    with st.sidebar:
        st.caption(f"Signed in as **{user}**")
        if st.button("Sign out", icon=":material/logout:"):
            audit.info("%s signed out", user)
            for key in ("user", "signed_in_at"):
                st.session_state.pop(key, None)
            st.rerun()
