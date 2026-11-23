"""
demo_symmetric.py -- Part B: symmetric encryption done right.

Shows ECB leaking repeated blocks, AES-GCM detecting tampering, and why a
reused nonce is catastrophic. Needs the `cryptography` package.
Run:  python demo_symmetric.py
"""
import os


def ecb_demo():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key = os.urandom(32)
    block = b"YELLOW SUBMARINE"          # exactly one 16-byte AES block
    plaintext = block + block            # two identical blocks
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    print("ECB block 1 == block 2 ?", ct[:16] == ct[16:32], " <- identical input leaks")


def gcm_demo():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = AESGCM.generate_key(bit_length=256)
    aead = AESGCM(key)
    nonce = os.urandom(12)
    ct = aead.encrypt(nonce, b"transfer 100 EUR to alice", b"ctx=v1")
    print("decrypt ok  :", aead.decrypt(nonce, ct, b"ctx=v1"))
    tampered = bytearray(ct); tampered[0] ^= 1
    try:
        aead.decrypt(nonce, bytes(tampered), b"ctx=v1")
    except Exception as e:
        print("tamper caught:", type(e).__name__)


def nonce_reuse_demo():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = AESGCM.generate_key(bit_length=256)
    aead = AESGCM(key)
    nonce = os.urandom(12)                        # SAME nonce -- never do this
    p1 = b"attack at dawn!!"
    p2 = b"retreat at dusk!"
    c1 = aead.encrypt(nonce, p1, b"")[:len(p1)]   # ciphertext part only
    c2 = aead.encrypt(nonce, p2, b"")[:len(p2)]
    x_ct = bytes(a ^ b for a, b in zip(c1, c2))
    x_pt = bytes(a ^ b for a, b in zip(p1, p2))
    print("c1 XOR c2 == p1 XOR p2 ?", x_ct == x_pt, " <- the key cancels out")


if __name__ == "__main__":
    try:
        print("== ECB leaks structure =="); ecb_demo()
        print("\n== AES-GCM authenticates =="); gcm_demo()
        print("\n== nonce reuse is catastrophic =="); nonce_reuse_demo()
    except ImportError:
        print("This demo needs the 'cryptography' package:  pip install cryptography")
