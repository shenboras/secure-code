import html
import secrets
import hmac
import hashlib
import json
import base64
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

# ==========================================
# PART A - Cross-Site Scripting & Output Encoding
# ==========================================

def encode_html_text(s: str) -> str:
    """
    HTML-encode a string for the text context so markup cannot execute.
    (Converts <, >, &, and quotes to entities).
    """
    if not isinstance(s, str):
        s = str(s)
    return html.escape(s, quote=True)

def is_safe_url(url: str) -> bool:
    """
    Return True only for URLs safe to put in an href:
    - Relative URLs (e.g., /path, relative/path, but not protocol-relative //evil.com)
    - Absolute http/https URLs
    Reject javascript:, data:, vbscript: (case- and whitespace-insensitive).
    """
    if not isinstance(url, str):
        return False
    
    # Strip leading/trailing whitespaces and control characters that might bypass checks
    cleaned_url = url.strip()
    
    # Check for dangerous schemes case-insensitively
    lower_url = cleaned_url.lower()
    dangerous_schemes = ("javascript:", "data:", "vbscript:")
    for scheme in dangerous_schemes:
        if lower_url.startswith(scheme):
            return False
            
    # Also check if there are whitespace/tab injections before the scheme
    # e.g., "java\nscript:..."
    scheme_check = "".join(lower_url.split())
    for scheme in dangerous_schemes:
        if scheme_check.startswith(scheme):
            return False

    # Parse the URL using urllib.parse
    parsed = urlparse(cleaned_url)
    
    # If it has a scheme, it must be http or https
    if parsed.scheme:
        if parsed.scheme.lower() not in ("http", "https"):
            return False
            
    # If it's a network-path reference (protocol-relative like //evil.com), reject it
    if cleaned_url.startswith("//"):
        return False
        
    return True


# ==========================================
# Part B - Cookies & Sessions
# ==========================================

def generate_session_id() -> str:
    """
    Return a cryptographically strong, URL-safe session ID
    using the secrets module (at least 32 bytes of entropy).
    """
    return secrets.token_urlsafe(32)

def build_session_cookie(name: str, value: str) -> str:
    """
    Return a Set-Cookie header string carrying Secure, HttpOnly, SameSite=Lax and Path=/.
    Format: name=value; Secure; HttpOnly; SameSite=Lax; Path=/
    """
    return f"{name}={value}; Secure; HttpOnly; SameSite=Lax; Path=/"

def audit_cookie(header: str) -> set:
    """
    Given a Set-Cookie header, return the set of problems from:
    {"missing Secure", "missing HttpOnly", "missing SameSite"}
    """
    problems = set()
    # Normalize header for case-insensitive checks
    header_lower = header.lower()
    
    if "secure" not in header_lower:
        problems.add("missing Secure")
    if "httponly" not in header_lower:
        problems.add("missing HttpOnly")
    if "samesite" not in header_lower:
        problems.add("missing SameSite")
        
    return problems

def rotate_session(store: dict, old_sid: str) -> str:
    """
    Given a dict session store (sid -> data), create a new strong ID,
    move the data to it, delete the old entry, and return the new ID.
    """
    if old_sid in store:
        data = store.pop(old_sid)
    else:
        data = {}
        
    new_sid = generate_session_id()
    store[new_sid] = data
    return new_sid


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


   
