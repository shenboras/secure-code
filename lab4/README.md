# Lab 4 - Cryptographic Protection

This lab turns the cryptography lecture into hands-on practice: you will
**see** common cryptographic mistakes fail, **fix** them with correct
primitives, and **verify** the fixes with automated tests. The topics follow
the lecture - foundations, pitfalls, and damage-reduction techniques.

Everything runs locally in Python, on strings and in-memory data - no
network, no real keys, no real targets.

> **One dependency:** this lab uses the `cryptography` package for AEAD.
> Install it with `pip install -r requirements.txt`. Everything else is the
> Python standard library (`hashlib`, `hmac`, `secrets`, `os`, `base64`).

---

## 1. How to use this lab

Each part has four sections:

| Section | What you do |
| --- | --- |
| **Theory** | A short recap from the lecture. |
| **Demonstration** | Run a provided script (or notebook cell) and watch weak-vs-safe behaviour. |
| **Implementation** | Fill in a function in `student_solutions.py`. |
| **Research** | A few written sentences for your report. |

Two ways to work:

- **Notebook** - open `lab4.ipynb`, run the example cells, write each
  function in its *Your code* cell, and run the check cell below it.
- **Files + tests** - edit `student_solutions.py` and run `test_solutions.py`.

### Setup

```bash
python --version                   # 3.10+
pip install -r requirements.txt    # cryptography (+ optional pytest, jupyter)
```

### Files

```
lab4-cryptography/
├── README.md                 ← this document
├── demo_hashing.py           ← Part A demos: hashing, encoding, randomness
├── demo_symmetric.py         ← Part B demos: ECB vs AEAD, nonce reuse
├── demo_integrity.py         ← Part C demos: MAC, timing-safe compare, KDF
├── demo_keymgmt.py           ← Part D demos: key handling & rotation
├── student_solutions.py      ← YOU implement the functions here (TODOs)
├── test_solutions.py         ← automated self-check
├── lab4.ipynb                ← interactive notebook
└── requirements.txt
```

### Running the tests

```bash
python -m pytest test_solutions.py -v      # pretty output
python test_solutions.py                   # no pytest needed
```

## 2. Recap: the one idea

> **The maths is strong. Systems break in the engineering - the mode, the
> nonce, the randomness and the keys.**

Each part maps to **OWASP Top 10:2025 → A04 Cryptographic Failures**.

---

## Part A - Hashing, Encoding & Randomness

### A.1 Theory

Three tools are constantly confused. **Encoding** (Base64) is reversible with
no key - it hides nothing. **Hashing** is a one-way fingerprint for integrity.
**Encryption** is reversible with a key. And every key, nonce, salt and token
must come from a **cryptographic RNG**, never `random`.

### A.2 Demonstration

```bash
python demo_hashing.py
```

See Base64 "un-encrypted" trivially, a broken hash (MD5) next to SHA-256, and
a predictable `random` value next to an unpredictable `secrets` one.

### A.3 Implementation

In `student_solutions.py`:

- **`sha256_hex(data: bytes)`** - return the SHA-256 digest as hex. (Do not
  use MD5 or SHA-1.)
- **`secure_token(n_bytes=32)`** - return a URL-safe random token from a
  cryptographic RNG with at least `n_bytes` of entropy.
- **`is_reversible_encoding(s)`** - return `True`: Base64 is reversible
  without a key. (A one-line reflection - implement the round-trip and prove
  it, returning the decoded bytes equal the input.)

### A.4 Research

- Explain the difference between encoding, hashing and encryption in one
  sentence each.
- Name two places a predictable "random" value would break a cryptosystem.

---

## Part B - Symmetric Encryption Done Right (AEAD)

### B.1 Theory

ECB mode encrypts each block independently, so identical plaintext blocks
produce identical ciphertext - structure leaks, and there is no integrity.
The fix is an **AEAD** mode (AES-GCM, ChaCha20-Poly1305): confidentiality and
authentication in one step, with a **unique nonce per message**. Nonce reuse
under the same key is catastrophic.

### B.2 Demonstration

```bash
python demo_symmetric.py
```

See ECB leak repeated blocks, AES-GCM detect a tampered ciphertext, and a
reused nonce produce a visible relationship between two ciphertexts.

### B.3 Implementation

In `student_solutions.py`:

- **`ecb_leaks(block)`** - demonstrate the ECB weakness: return `True` iff a
  two-identical-block plaintext yields two identical ciphertext blocks under
  AES-ECB. (This proves the weakness; you will not use ECB again.)
- **`aead_encrypt(key, plaintext, aad=b"")`** - encrypt with AES-GCM using a
  fresh random 96-bit nonce; return `nonce + ciphertext`.
- **`aead_decrypt(key, blob, aad=b"")`** - split the nonce, decrypt and verify;
  raise on any tampering (wrong tag, wrong AAD, flipped byte).

### B.4 Research

- Why is AES-GCM nonce reuse worse than just leaking one message?
- What does the "associated data" (AAD) protect, and why is it not encrypted?

---

## Part C - Integrity, MACs & Key Derivation

### C.1 Theory

Encryption alone gives confidentiality, not integrity. A **MAC**
(HMAC-SHA-256) detects tampering and proves authenticity with a shared key.
Comparing MACs (or any secret) must be **constant-time** or the compare leaks
via timing. And you should **derive** purpose-specific keys from one secret
with a KDF (HKDF) - never reuse one key for two jobs.

### C.2 Demonstration

```bash
python demo_integrity.py
```

See an HMAC detect a single flipped bit, a naive `==` compared with a
constant-time compare, and HKDF turn one secret into two independent keys.

### C.3 Implementation

In `student_solutions.py`:

- **`hmac_sha256(key, msg)`** - return the HMAC-SHA-256 tag (hex).
- **`verify_mac(key, msg, tag)`** - recompute and compare in **constant time**
  (`hmac.compare_digest`). Return a bool.
- **`derive_keys(master, n=2, length=32)`** - use HKDF (or an HMAC-based
  equivalent) to derive `n` independent keys from one master secret. Keys for
  different `info`/purpose labels must differ.

### C.4 Research

- Why must a MAC comparison be constant-time? What leaks otherwise?
- Why is reusing one key for both encryption and MAC a bad idea, and how does
  a KDF fix it?

---

## Part D - Key Management & Damage Reduction

### D.1 Theory

You cannot guarantee a key never leaks; you can guarantee the **blast radius**
is small. Never hard-code keys; store them apart from the data; **rotate**
them; and derive **separate keys per purpose/tenant** so one compromise does
not expose everything. Forward secrecy applies the same idea to sessions.

### D.2 Demonstration

```bash
python demo_keymgmt.py
```

See a hard-coded key found by a simple scan, a key rotation that keeps old
data readable via key versioning, and per-tenant keys that isolate a
compromise.

### D.3 Implementation

In `student_solutions.py`:

- **`find_hardcoded_secrets(source)`** - scan a source string and return the
  set of lines that look like a hard-coded key/secret/password assignment.
- **`tenant_key(master, tenant_id)`** - derive a distinct key per tenant from
  the master secret (different tenants → different keys; same tenant →
  stable).
- **`rotate(keyring)`** - given a `dict` of `key_id -> key`, add a new current
  key (a new version) and return its id, keeping old keys so existing
  ciphertext still decrypts.

### D.4 Research

- Why does per-tenant (or per-purpose) key separation reduce the damage of a
  single key compromise?
- What is "harvest now, decrypt later", and which two steps (crypto-agility,
  post-quantum migration) address it?

---

## 3. Self-assessment checklist

- [ ] `sha256_hex` and `secure_token` use strong primitives; no MD5/SHA-1/`random`.
- [ ] `aead_encrypt`/`aead_decrypt` round-trip and reject tampering.
- [ ] `verify_mac` is constant-time; `derive_keys` yields distinct keys.
- [ ] `tenant_key` isolates tenants; `rotate` keeps old data readable.
- [ ] `find_hardcoded_secrets` flags the planted secrets.
- [ ] My report contains the research answers (A.4, B.4, C.4, D.4).

## 4. What to submit

1. Your completed **`student_solutions.py`**.
2. A short **report** with the research answers.
3. The **passing test output**.

---

## Appendix - References

- OWASP Top 10:2025 - A04 Cryptographic Failures - <https://owasp.org/Top10/2025/>
- OWASP Cryptographic Storage Cheat Sheet - <https://cheatsheetseries.owasp.org/>
- Python `cryptography` (AEAD, HKDF) - <https://cryptography.io/>
- Python `hmac`, `hashlib`, `secrets` - standard library docs
- NIST FIPS 203/204/205 (post-quantum, 2024); NIST SP 800-57 (key management)
- CWE-327 (broken algorithm), CWE-330 (weak randomness), CWE-311 (missing encryption)

*Built from the Cryptographic Protection lecture; examples extended into a
self-contained, self-checking lab.*
