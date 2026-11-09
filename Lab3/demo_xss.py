"""
demo_xss.py -- Part A: output encoding & XSS.

Untrusted input placed into a page without encoding is run by the browser.
The same idea is reproduced here with strings so it is easy to inspect.
Run:  python demo_xss.py
"""
import html
from urllib.parse import urlparse

PAYLOAD = "<script>alert('XSS')</script>"


def render_profile_vulnerable(name: str) -> str:
    """UNSAFE: untrusted name written into HTML verbatim."""
    return f"<div>Hello, {name}</div>"


def render_profile_safe(name: str) -> str:
    """SAFE: encode for the HTML text context before output."""
    return f"<div>Hello, {html.escape(name)}</div>"


def link_vulnerable(url: str) -> str:
    """UNSAFE: an attacker-controlled href can be a javascript: URL."""
    return f'<a href="{url}">profile</a>'


def _is_safe_url(url: str) -> bool:
    scheme = urlparse(url.strip()).scheme.lower()
    return scheme in ("", "http", "https")


def link_safe(url: str) -> str:
    """SAFE: only allow relative or http(s) links in an href."""
    if not _is_safe_url(url):
        return '<a href="#">link removed</a>'
    return f'<a href="{html.escape(url, quote=True)}">profile</a>'


if __name__ == "__main__":
    print("== HTML text context ==")
    print("payload:    ", PAYLOAD)
    print("vulnerable: ", render_profile_vulnerable(PAYLOAD))
    print("safe:       ", render_profile_safe(PAYLOAD))
    print()
    print("== href context ==")
    evil = "javascript:alert(document.cookie)"
    print("vulnerable: ", link_vulnerable(evil))
    print("safe:       ", link_safe(evil))
    print("safe (ok):  ", link_safe("/users/42"))
