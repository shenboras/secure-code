"""
demo_keymgmt.py -- Part D: key management & damage reduction.

Shows a hard-coded secret found by a scan, per-tenant keys isolating a
compromise, and key rotation that keeps old data readable.
Run:  python demo_keymgmt.py  (standard library only)
"""
import hashlib
import hmac
import re
import secrets

SOURCE = '''
API_KEY = "sk_live_51H8xZ2eZvKYlo"
db_password = "hunter2"
def connect(): return open_db(db_password)
timeout = 30
'''


def scan_demo():
    pattern = re.compile(r'(?i)\b\w*(?:key|secret|password|passwd|token|credential)\w*\s*=\s*["\']')
    hits = [ln.strip() for ln in SOURCE.splitlines() if pattern.search(ln)]
    print("hard-coded secrets found:")
    for h in hits:
        print("  !", h)


def tenant_demo():
    master = secrets.token_bytes(32)
    def tenant_key(tid):
        return hmac.new(master, tid.encode(), hashlib.sha256).digest()
    print("tenant A:", tenant_key("tenant-A").hex()[:24], "...")
    print("tenant B:", tenant_key("tenant-B").hex()[:24], "...")
    print("A != B (one leak doesn't expose the other)?", tenant_key("tenant-A") != tenant_key("tenant-B"))


def rotation_demo():
    keyring = {"v1": secrets.token_bytes(32)}            # old data encrypted under v1
    new_id = f"v{len(keyring) + 1}"
    keyring[new_id] = secrets.token_bytes(32)            # new data uses v2
    print("current key id:", new_id)
    print("old key kept for decryption?", "v1" in keyring)


if __name__ == "__main__":
    print("== scan for hard-coded secrets =="); scan_demo()
    print("\n== per-tenant key separation =="); tenant_demo()
    print("\n== key rotation with versioning =="); rotation_demo()
