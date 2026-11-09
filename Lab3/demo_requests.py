"""
demo_requests.py -- Part C: CSRF tokens & open redirects.

Shows an HMAC CSRF token accepted when valid and rejected when tampered
(constant-time compare), and a set of redirect targets allowed or blocked.
Run:  python demo_requests.py
"""
import hashlib
import hmac
from urllib.parse import urlparse

SECRET = b"server-side-csrf-secret-key"


# --- CSRF tokens -----------------------------------------------------------
def make_token(session_id: str) -> str:
    return hmac.new(SECRET, session_id.encode(), hashlib.sha256).hexdigest()


def check_token(session_id: str, token: str) -> bool:
    expected = make_token(session_id)
    return hmac.compare_digest(expected, token)   # constant-time


# --- open redirects --------------------------------------------------------
def redirect_vulnerable(target: str) -> str:
    """UNSAFE: trusts whatever URL the parameter contains."""
    return target


def redirect_safe(target: str, allowed_hosts) -> str:
    """SAFE: allow relative paths, or http(s) to an allow-listed host."""
    t = target.strip().replace("\\", "/")
    if t.startswith("//"):                 # protocol-relative -> off-site
        return "/"
    u = urlparse(t)
    if not u.scheme and not u.netloc:      # relative path
        return t
    if u.scheme in ("http", "https") and u.hostname in allowed_hosts and not u.username:
        return t
    return "/"


if __name__ == "__main__":
    print("== CSRF tokens ==")
    sid = "session-abc123"
    tok = make_token(sid)
    print("valid token accepted:   ", check_token(sid, tok))
    print("tampered token accepted:", check_token(sid, tok[:-1] + ("0" if tok[-1] != "0" else "1")))
    print("other session accepted: ", check_token("other-session", tok))
    print()
    print("== open redirects ==")
    allowed = {"example.com", "help.example.com"}
    for t in ["/dashboard", "https://example.com/welcome", "https://evil.example",
              "//evil.example", "https://example.com@evil.example", "javascript:alert(1)"]:
        print(f"  {t:<40} -> {redirect_safe(t, allowed)}")
