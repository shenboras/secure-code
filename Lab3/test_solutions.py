"""
test_solutions.py -- self-check for your work in student_solutions.py.

Run either way:
    python -m pytest test_solutions.py -v
    python test_solutions.py
"""
import base64
import hashlib
import hmac
import json

import student_solutions as sol

SECRET = b"unit-test-secret"
KEY = b"unit-test-key"


# ---- Part A: output encoding & XSS ----------------------------------------
def test_encode_html_text():
    out = sol.encode_html_text("<script>alert('XSS')</script>")
    assert "<script>" not in out
    assert "&lt;script&gt;" in out
    assert "&amp;" in sol.encode_html_text("a & b")


def test_is_safe_url():
    for good in ["/users/42", "profile", "https://example.com/x", "http://a.b/c"]:
        assert sol.is_safe_url(good) is True, good
    for bad in ["javascript:alert(1)", "  javascript:alert(1)", "JavaScript:x",
                "data:text/html,<script>", "vbscript:msgbox(1)"]:
        assert sol.is_safe_url(bad) is False, bad


# ---- Part B: cookies & sessions -------------------------------------------
def test_session_id_strong_and_unique():
    ids = {sol.generate_session_id() for _ in range(500)}
    assert len(ids) == 500                      # no collisions
    assert all(len(i) >= 32 for i in ids)       # enough length


def test_build_session_cookie():
    c = sol.build_session_cookie("SID", "abc123")
    assert c.startswith("SID=abc123")
    for flag in ("Secure", "HttpOnly", "SameSite", "Path=/"):
        assert flag in c, flag


def test_audit_cookie():
    assert sol.audit_cookie("SID=x; Path=/") == {
        "missing Secure", "missing HttpOnly", "missing SameSite"}
    assert sol.audit_cookie("SID=x; Path=/; Secure; HttpOnly; SameSite=Lax") == set()


def test_rotate_session():
    store = {"old": {"user": "alice", "cart": [1, 2]}}
    new = sol.rotate_session(store, "old")
    assert new != "old"
    assert "old" not in store                    # old invalidated
    assert store[new]["user"] == "alice"         # data preserved

# ==========================================
# Part C - CSRF & Open Redirects (Güncellenen Kısımlar)
# ==========================================

def generate_csrf_token(session_id, secret) -> str:
    """
    A stateless token bound to the session, derived with HMAC-SHA256.
    Handles both str and bytes inputs safely.
    """
    if isinstance(session_id, str):
        session_id = session_id.encode('utf-8')
    if isinstance(secret, str):
        secret = secret.encode('utf-8')
        
    h = hmac.new(secret, session_id, hashlib.sha256)
    return h.hexdigest()

def verify_csrf_token(session_id, secret, token) -> bool:
    """
    Recompute and compare in constant time (hmac.compare_digest). Return a bool.
    """
    if not token or not isinstance(token, str):
        return False
    expected_token = generate_csrf_token(session_id, secret)
    return hmac.compare_digest(expected_token, token)


# ==========================================
# Part D - XXE & Insecure Deserialization (Güncellenen Kısımlar)
# ==========================================

def sign_payload(obj, key) -> str:
    """
    Serialize obj as JSON and return a signed token (payload plus an HMAC-SHA256 tag).
    Handles both str and bytes for key safely.
    """
    if isinstance(key, str):
        key = key.encode('utf-8')
        
    json_data = json.dumps(obj, sort_keys=True)
    payload_b64 = base64.urlsafe_b64encode(json_data.encode('utf-8')).decode('utf-8')
    
    sig = hmac.new(key, payload_b64.encode('utf-8'), hashlib.sha256).hexdigest()
    return f"{payload_b64}.{sig}"

def load_signed(token: str, key):
    """
    Verify the HMAC in constant time, then return the object.
    Raise ValueError on any tampering or wrong key/format.
    """
    if isinstance(key, str):
        key = key.encode('utf-8')
        
    if not isinstance(token, str) or "." not in token:
        raise ValueError("Invalid token format.")
        
    parts = token.split(".", 1)
    if len(parts) != 2:
        raise ValueError("Invalid token format.")
        
    payload_b64, provided_sig = parts
    
    # Recompute HMAC
    expected_sig = hmac.new(key, payload_b64.encode('utf-8'), hashlib.sha256).hexdigest()
    
    if not hmac.compare_digest(expected_sig, provided_sig):
        raise ValueError("Signature verification failed (tampering detected or wrong key).")
        
    try:
        json_bytes = base64.urlsafe_b64decode(payload_b64.encode('utf-8'))
        obj = json.loads(json_bytes.decode('utf-8'))
        return obj
    except Exception as e:
        raise ValueError(f"Failed to decode payload: {e}")


# ---- standalone runner (no pytest required) -------------------------------
if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    passed = 0
    for test in tests:
        try:
            test()
        except NotImplementedError as exc:
            print(f"TODO  {test.__name__}: {exc}")
        except AssertionError as exc:
            print(f"FAIL  {test.__name__}: {exc}")
        except Exception as exc:  # noqa: BLE001
            print(f"ERROR {test.__name__}: {type(exc).__name__}: {exc}")
        else:
            print(f"PASS  {test.__name__}")
            passed += 1
    print(f"\n{passed}/{len(tests)} checks passed.")
