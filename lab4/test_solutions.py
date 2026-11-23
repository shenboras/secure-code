"""
test_solutions.py -- self-check for your work in student_solutions.py.

Run either way:
    python -m pytest test_solutions.py -v
    python test_solutions.py

Part B needs the `cryptography` package; its tests report clearly if it is
missing, and the other parts still run.
"""
import hashlib
import os

import student_solutions as sol


# ---- Part A ---------------------------------------------------------------
def test_sha256_hex():
    assert sol.sha256_hex(b"abc") == hashlib.sha256(b"abc").hexdigest()
    assert len(sol.sha256_hex(b"")) == 64


def test_secure_token_strong_unique():
    toks = {sol.secure_token(32) for _ in range(500)}
    assert len(toks) == 500
    assert all(len(t) >= 32 for t in toks)


def test_is_reversible_encoding():
    assert sol.is_reversible_encoding(b"secret-value") is True


# ---- Part B (needs cryptography) ------------------------------------------
def test_ecb_leaks():
    assert sol.ecb_leaks(b"YELLOW SUBMARINE") is True


def test_aead_roundtrip_and_tamper():
    key = os.urandom(32)
    blob = sol.aead_encrypt(key, b"hello world", b"ctx=v1")
    assert sol.aead_decrypt(key, blob, b"ctx=v1") == b"hello world"
    # flipped byte must fail
    bad = bytearray(blob); bad[-1] ^= 1
    try:
        sol.aead_decrypt(key, bytes(bad), b"ctx=v1")
    except Exception:
        pass
    else:
        raise AssertionError("tampered ciphertext was accepted")
    # wrong AAD must fail
    try:
        sol.aead_decrypt(key, blob, b"ctx=v2")
    except Exception:
        pass
    else:
        raise AssertionError("wrong AAD was accepted")


def test_aead_nonce_is_fresh():
    key = os.urandom(32)
    a = sol.aead_encrypt(key, b"same message", b"")
    b = sol.aead_encrypt(key, b"same message", b"")
    assert a[:12] != b[:12], "nonce must be fresh each call"


# ---- Part C ---------------------------------------------------------------
def test_hmac_and_verify():
    k = b"key"
    tag = sol.hmac_sha256(k, b"msg")
    assert sol.verify_mac(k, b"msg", tag) is True
    assert sol.verify_mac(k, b"msg", tag[:-1] + ("0" if tag[-1] != "0" else "1")) is False
    assert sol.verify_mac(k, b"other", tag) is False


def test_derive_keys_distinct():
    keys = sol.derive_keys(b"master-secret", labels=("enc", "mac"), length=32)
    assert set(keys) == {"enc", "mac"}
    assert len(keys["enc"]) == 32
    assert keys["enc"] != keys["mac"]
    # deterministic for the same master + label
    again = sol.derive_keys(b"master-secret", labels=("enc", "mac"), length=32)
    assert again["enc"] == keys["enc"]


# ---- Part D ---------------------------------------------------------------
def test_find_hardcoded_secrets():
    src = ('API_KEY = "sk_live_123"\n'
           "db_password = 'hunter2'\n"
           "timeout = 30\n"
           'name = "alice"\n')
    hits = sol.find_hardcoded_secrets(src)
    assert any("API_KEY" in h for h in hits)
    assert any("db_password" in h for h in hits)
    assert not any("timeout" in h for h in hits)


def test_tenant_key_isolation():
    m = os.urandom(32)
    assert sol.tenant_key(m, "A") != sol.tenant_key(m, "B")
    assert sol.tenant_key(m, "A") == sol.tenant_key(m, "A")


def test_rotate_keeps_old():
    import secrets
    keyring = {"v1": secrets.token_bytes(32)}
    new_id = sol.rotate(keyring)
    assert new_id != "v1"
    assert "v1" in keyring                 # old key preserved
    assert new_id in keyring               # new key added
    assert len(keyring) == 2


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
        except ModuleNotFoundError as exc:
            print(f"SKIP  {test.__name__}: needs '{exc.name}' (pip install -r requirements.txt)")
        except AssertionError as exc:
            print(f"FAIL  {test.__name__}: {exc}")
        except Exception as exc:  # noqa: BLE001
            print(f"ERROR {test.__name__}: {type(exc).__name__}: {exc}")
        else:
            print(f"PASS  {test.__name__}")
            passed += 1
    print(f"\n{passed}/{len(tests)} checks passed.")
