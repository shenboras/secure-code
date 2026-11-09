"""
demo_sessions.py -- Part B: cookies & sessions.

Shows weak vs strong session IDs, a cookie missing its flags vs a hardened
one, and a session-fixation attack defeated by rotating the ID on login.
Run:  python demo_sessions.py
"""
import secrets


# --- session IDs -----------------------------------------------------------
_weak_counter = 1000


def weak_session_id() -> str:
    """UNSAFE: sequential and predictable -- an attacker can guess the next."""
    global _weak_counter
    _weak_counter += 1
    return str(_weak_counter)


def strong_session_id() -> str:
    """SAFE: 256 bits of entropy, URL-safe."""
    return secrets.token_urlsafe(32)


# --- cookies ---------------------------------------------------------------
def weak_cookie(name: str, value: str) -> str:
    """UNSAFE: no Secure, HttpOnly or SameSite."""
    return f"{name}={value}; Path=/"


def strong_cookie(name: str, value: str) -> str:
    """SAFE: hardened session cookie."""
    return f"{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax"


# --- session fixation ------------------------------------------------------
class SessionStore:
    """A tiny in-memory session store: sid -> data dict."""

    def __init__(self):
        self.data = {}

    def new(self, sid=None):
        sid = sid or strong_session_id()
        self.data[sid] = {}
        return sid

    def valid(self, sid):
        return sid in self.data


def login_vulnerable(store, sid, user):
    """UNSAFE: keeps the same SID across the login boundary."""
    store.data[sid]["user"] = user
    return sid


def login_safe(store, sid, user):
    """SAFE: issue a fresh SID on login; the old one no longer works."""
    data = store.data.pop(sid, {})
    new_sid = store.new()
    data["user"] = user
    store.data[new_sid] = data
    return new_sid


if __name__ == "__main__":
    print("== session IDs ==")
    print("weak:  ", weak_session_id(), weak_session_id())
    print("strong:", strong_session_id())
    print()
    print("== cookies ==")
    print("weak:  ", weak_cookie("SID", "abc"))
    print("strong:", strong_cookie("SID", "abc"))
    print()
    print("== session fixation ==")
    for label, login in (("vulnerable", login_vulnerable), ("safe", login_safe)):
        store = SessionStore()
        planted = store.new("attacker-knows-this")        # attacker fixes the SID
        after = login(store, planted, "alice")            # victim logs in
        print(f"{label:>10}: attacker's SID still valid after login? "
              f"{store.valid('attacker-knows-this')}  (new sid: {after[:12]}...)")
