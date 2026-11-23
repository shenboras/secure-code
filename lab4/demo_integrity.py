"""
demo_integrity.py -- Part C: integrity, MACs & key derivation.

Shows an HMAC catching a one-bit change, a naive compare vs a constant-time
one, and HKDF turning one secret into two independent keys.
Run:  python demo_integrity.py  (standard library only)
"""
import hashlib
import hmac


def mac_demo():
    key = b"shared-mac-key"
    msg = b"balance=100"
    tag = hmac.new(key, msg, hashlib.sha256).hexdigest()
    forged = b"balance=999"
    tag2 = hmac.new(key, forged, hashlib.sha256).hexdigest()
    print("tag(original):", tag[:24], "...")
    print("tag(forged)  :", tag2[:24], "...   different -> tampering detected")


def compare_demo():
    a = "a3f1c0"; b = "a3f1c0"
    print("naive ==          :", a == b, "  (may exit early -> timing leak)")
    print("hmac.compare_digest:", hmac.compare_digest(a, b), "  (constant time)")


def hkdf(master, length, info):
    """Minimal HKDF-Expand (RFC 5869) using only hashlib/hmac."""
    out, t, counter = b"", b"", 1
    while len(out) < length:
        t = hmac.new(master, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t; counter += 1
    return out[:length]


def kdf_demo():
    master = b"one-shared-master-secret"
    enc_key = hkdf(master, 32, b"encryption")
    mac_key = hkdf(master, 32, b"mac")
    print("enc key:", enc_key.hex()[:24], "...")
    print("mac key:", mac_key.hex()[:24], "...")
    print("different purposes -> different keys ?", enc_key != mac_key)


if __name__ == "__main__":
    print("== HMAC detects tampering =="); mac_demo()
    print("\n== constant-time compare =="); compare_demo()
    print("\n== HKDF: one secret, many keys =="); kdf_demo()
