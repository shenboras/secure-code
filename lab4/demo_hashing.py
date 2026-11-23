"""
demo_hashing.py -- Part A: hashing, encoding & randomness.

Three tools people confuse: encoding (reversible, no key), hashing (one-way),
and randomness (must be unpredictable). Run:  python demo_hashing.py
"""
import base64
import hashlib
import random
import secrets


def encoding_is_not_encryption():
    data = b"secret-value"
    enc = base64.b64encode(data).decode()
    back = base64.b64decode(enc)
    print(f"base64:  {enc}  ->  {back!r}   (reversed with no key)")


def broken_vs_strong_hash():
    msg = b"transfer 100 EUR"
    print("md5    :", hashlib.md5(msg).hexdigest(), "  (collisions are practical -- avoid)")
    print("sha256 :", hashlib.sha256(msg).hexdigest())


def predictable_vs_unpredictable():
    random.seed(1234)                         # attacker can replay the seed
    print("random (seeded):", random.getrandbits(32), random.getrandbits(32))
    print("secrets        :", secrets.token_hex(8))


if __name__ == "__main__":
    print("== encoding is not encryption ==");  encoding_is_not_encryption()
    print("\n== broken vs strong hash ==");      broken_vs_strong_hash()
    print("\n== predictable vs unpredictable =="); predictable_vs_unpredictable()
