import base64
import hashlib
import hmac
import os
import re
import secrets


# ==========================================================================
# Part A -- hashing, encoding & randomness
# ==========================================================================
def sha256_hex(data: bytes) -> str:
    """
    (A1): Return the SHA-256 digest of `data` as a hex string.
    """
    return hashlib.sha256(data).hexdigest()


def secure_token(n_bytes: int = 32) -> str:
    """
    (A2): Return a URL-safe random token with at least `n_bytes` of entropy.
    """
    return secrets.token_urlsafe(n_bytes)


def is_reversible_encoding(s: bytes) -> bool:
    """
    (A3): Base64 encode `s`, decode it back, and return True iff original bytes recovered.
    """
    encoded = base64.b64encode(s)
    decoded = base64.b64decode(encoded)
    return decoded == s


# ==========================================================================
# Part B -- symmetric encryption done right (AEAD)   [needs `cryptography`]
# ==========================================================================
def ecb_leaks(block: bytes) -> bool:
    """
    (B1): Encrypt `block + block` with AES-ECB and return True iff the two ciphertext blocks are identical.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(block + block) + encryptor.finalize()
    # ECB modunda aynı düz metin blokları aynı şifreli metin bloklarını üretir.
    return ciphertext[:16] == ciphertext[16:]


def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """
    (B2): Encrypt with AES-GCM using a FRESH random 96-bit (12-byte) nonce.
    Return nonce || ciphertext (ciphertext includes the GCM tag).
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ciphertext


def aead_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """
    (B3): Reverse `aead_encrypt`: split off the 12-byte nonce, decrypt and verify with AES-GCM.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = blob[:12]
    ciphertext = blob[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)


# ==========================================================================
# Part C -- integrity, MACs & key derivation
# ==========================================================================
def hmac_sha256(key: bytes, msg: bytes) -> str:
    """
    (C1): Return the HMAC-SHA-256 tag of `msg` under `key`, as hex.
    """
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def verify_mac(key: bytes, msg: bytes, tag: str) -> bool:
    """
    (C2): Recompute the tag and compare it with `tag` in CONSTANT TIME.
    """
    expected_tag = hmac_sha256(key, msg)
    return hmac.compare_digest(expected_tag, tag)


def derive_keys(master: bytes, labels=("enc", "mac"), length: int = 32) -> dict:
    """
    (C3): Derive one independent key per label from `master` using HMAC-SHA-256.
    """
    derived = {}
    for label in labels:
        label_bytes = label.encode('utf-8') if isinstance(label, str) else label
        key_bytes = hmac.new(master, label_bytes, hashlib.sha256).digest()[:length]
        derived[label] = key_bytes
    return derived


# ==========================================================================
# Part D -- key management & damage reduction
# ==========================================================================
def find_hardcoded_secrets(source: str) -> set:
    """
    (D1): Scan `source` and return the set of stripped lines assigning a string literal
    to a name containing key/secret/password/token/passwd/api_key (case-insensitive).
    """
    results = set()
    keywords = ['key', 'secret', 'password', 'token', 'passwd', 'api_key']
    
    for line in source.splitlines():
        stripped = line.strip()
        if '=' in stripped:
            parts = stripped.split('=', 1)
            var_name = parts[0].strip().lower()
            rhs = parts[1].strip()
            
            # Değişken adında anahtar kelimelerden biri geçiyor mu ve sağ taraf string literali mi?
            has_keyword = any(kw in var_name for kw in keywords)
            is_string = (rhs.startswith("'") and rhs.endswith("'")) or (rhs.startswith('"', 0)) # veya çift tırnak
            # Daha güvenli string kontrolü:
            if not is_string and (rhs.startswith('"') and rhs.endswith('"')):
                is_string = True

            if has_keyword and is_string:
                results.add(stripped)
    return results


def tenant_key(master: bytes, tenant_id: str) -> bytes:
    """
    (D2): Derive a distinct key per tenant from `master` (HMAC-SHA-256 over tenant_id).
    """
    return hmac.new(master, tenant_id.encode('utf-8'), hashlib.sha256).digest()


def rotate(keyring: dict) -> str:
    """
    (D3): Add a NEW current key under a new version id without removing old ones, return new id.
    """
    max_v = 0
    for k in keyring.keys():
        m = re.match(r'v(\d+)', k)
        if m:
            max_v = max(max_v, int(m.group(1)))
            
    new_id = f"v{max_v + 1}" if max_v > 0 else f"v{len(keyring) + 1}"
    keyring[new_id] = os.urandom(32)
    return new_id