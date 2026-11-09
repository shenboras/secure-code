# Lab 3 - Web Application Security

This lab turns the second web-security lecture into hands-on practice:
**cross-site scripting and output encoding, cookies and sessions,
cross-site request forgery and redirects, and the server-side parsing
attacks XXE and insecure deserialization.**

Everything runs locally in Python, against strings and in-memory data - no
web server, no network, no real targets. You *see* each weakness, *fix* it,
and *verify* the fix with automated tests.

---

## 1. How to use this lab

Each part has four sections:

| Section | What you do |
| --- | --- |
| **Theory** | A short recap from the lecture. |
| **Demonstration** | Run a provided script (or notebook cell) and watch the weak-vs-safe behaviour. |
| **Implementation** | Fill in a function in `student_solutions.py`. |
| **Research** | A few written sentences for your report. |

Two ways to work:

- **Notebook** - open `lab3.ipynb`, run the example cells, write each
  function in its *Your code* cell, and run the check cell below it.
- **Files + tests** - edit `student_solutions.py` and run `test_solutions.py`.

### Setup

```bash
python --version          # 3.10+
# optional tooling:
pip install -r requirements.txt   # pytest, jupyterlab
```

The lab uses only the Python standard library: `html`, `secrets`, `hmac`,
`hashlib`, `json`, `base64`, `urllib.parse`, `xml.etree.ElementTree`.

### Files

```
lab2-web-app-security/
├── README.md                 ← this document
├── demo_xss.py               ← Part A demos: output encoding / XSS
├── demo_sessions.py          ← Part B demos: cookies & sessions
├── demo_requests.py          ← Part C demos: CSRF & open redirects
├── demo_parsers.py           ← Part D demos: XXE & deserialization
├── student_solutions.py      ← YOU implement the functions here (TODOs)
├── test_solutions.py         ← automated self-check
├── lab3.ipynb                ← interactive notebook
└── requirements.txt          ← optional tooling
```

### Running the tests

```bash
python -m pytest test_solutions.py -v      # pretty output
python test_solutions.py                   # no pytest needed
```

---

## 2. Recap: the one idea

> **The client, the URL, the document and the serialized object are all
> attacker-controlled until proven otherwise.**

Part I of the lecture series showed the server cannot trust the client.
Part II adds a second victim - *other users* of your app - and the server's
own parsers. Each part below maps to the **OWASP Top 10:2025**.

---

## Part A - Cross-Site Scripting & Output Encoding

**OWASP Top 10:2025 → A05 Injection (CWE-79)**

### A.1 Theory

XSS is injection into the **browser**. If untrusted input is written into a
page without encoding, the browser runs it as markup or script, with the
full authority of your site. The reliable fix is **context-aware output
encoding**: encode data for the exact place it lands (HTML text, attribute,
URL, JavaScript). A second, related trap is putting untrusted input into an
`href` - a `javascript:` URL is XSS even without a `<script>` tag.

### A.2 Demonstration

```bash
python demo_xss.py
```

Watch the payload `<script>alert('XSS')</script>` appear **raw** in the
vulnerable renderer and **escaped** (`&lt;script&gt;…`) in the safe one, and
see a `javascript:` link rejected.

### A.3 Implementation

In `student_solutions.py`:

- **`encode_html_text(s)`** - HTML-encode a string for the text context so
  markup cannot execute (`<`, `>`, `&`, and quotes become entities).
- **`is_safe_url(url)`** - return `True` only for URLs safe to put in an
  `href`: relative URLs, or absolute `http`/`https`. Reject `javascript:`,
  `data:`, `vbscript:` (case- and whitespace-insensitive).

### A.4 Research

- Name **two output contexts** besides HTML text and the encoding each
  needs.
- What does a **Content-Security-Policy** add on top of encoding, and why
  is it defence in depth rather than a replacement?

---

## Part B - Cookies & Sessions

**OWASP Top 10:2025 → A07 Authentication Failures (CWE-384, CWE-613)**

### B.1 Theory

A session ID is a credential: steal or fixate it and you are logged in. The
defences are concrete: strong random IDs, the right cookie attributes
(`Secure`, `HttpOnly`, `SameSite`), expiry, and **rotating the ID on login**
to defeat session fixation.

### B.2 Demonstration

```bash
python demo_sessions.py
```

See a weak, guessable ID next to a strong one; a cookie missing its flags
next to a hardened one; and a fixation attack defeated by rotation.

### B.3 Implementation

In `student_solutions.py`:

- **`generate_session_id()`** - return a cryptographically strong, URL-safe
  session ID (use the `secrets` module; at least 32 bytes of entropy).
- **`build_session_cookie(name, value)`** - return a `Set-Cookie` header
  string carrying `Secure`, `HttpOnly`, `SameSite=Lax` and `Path=/`.
- **`audit_cookie(header)`** - given a `Set-Cookie` header, return the set of
  problems from `{"missing Secure", "missing HttpOnly", "missing SameSite"}`.
- **`rotate_session(store, old_sid)`** - given a `dict` session store
  (`sid -> data`), create a new strong ID, move the data to it, delete the
  old entry, and return the new ID. (This is how you stop fixation at login.)

### B.4 Research

- Explain **session fixation** and how rotating the ID on login stops it.
- What do the `Secure`, `HttpOnly` and `SameSite` attributes each defend
  against? Why is binding a session to an IP address a weak control?

---

## Part C - CSRF & Open Redirects

**OWASP Top 10:2025 → A01 Broken Access Control (CWE-352, CWE-601)**

### C.1 Theory

CSRF abuses the browser's **ambient authority**: cookies are sent
automatically, so a page the victim visits can make their browser act on a
site they are logged into. The server needs proof a request came from its
own page - a **CSRF token** the attacker cannot predict - plus `SameSite`
cookies and `Origin` checks. An **open redirect** lends your domain's
reputation to a phishing link; validate the destination against an
allow-list.

### C.2 Demonstration

```bash
python demo_requests.py
```

See a valid CSRF token accepted and a tampered one rejected (using a
constant-time compare), and a battery of redirect targets allowed or
blocked.

### C.3 Implementation

In `student_solutions.py`:

- **`generate_csrf_token(session_id, secret)`** - a stateless token bound to
  the session, derived with HMAC-SHA256.
- **`verify_csrf_token(session_id, secret, token)`** - recompute and compare
  in **constant time** (`hmac.compare_digest`). Return a bool.
- **`safe_redirect_target(target, allowed_hosts)`** - return `target` if it
  is safe to redirect to, else `None`. Allow relative paths and absolute
  `http`/`https` URLs whose host is in `allowed_hosts`. Reject
  protocol-relative `//evil.com`, userinfo tricks
  (`https://example.com@evil.com`), `javascript:` and backslash tricks.

### C.4 Research

- In one or two sentences each: how do a **synchronizer token**, a
  **double-submit cookie**, and **`SameSite`** each stop CSRF?
- Why must token comparison be constant-time?

---

## Part D - XXE & Insecure Deserialization

**OWASP Top 10:2025 → A02 Security Misconfiguration (XXE, CWE-611) and
A08 Software or Data Integrity Failures (deserialization, CWE-502)**

### D.1 Theory

An XML parser that honours a document's **DTD** can be made to read local
files, reach internal servers (SSRF), or explode a tiny input into gigabytes
(the *billion laughs* bomb). The simplest robust defence: **refuse documents
that declare a DTD**, then parse. For deserialization, never rebuild native
objects from untrusted bytes (`pickle`, Java serialization): prefer a
**data-only format (JSON)** and verify an **integrity signature** before
loading.

### D.2 Demonstration

```bash
python demo_parsers.py
```

See a billion-laughs document and an external-entity document **rejected**
before any parsing (so nothing expands), a normal document parsed, and a
JSON payload that is accepted only when its HMAC signature checks out.

### D.3 Implementation

In `student_solutions.py`:

- **`parse_xml_safely(xml_str)`** - raise `ValueError` if the document
  declares a DTD (`<!DOCTYPE`); otherwise parse it with
  `xml.etree.ElementTree` and return the root element.
- **`sign_payload(obj, key)`** - serialize `obj` as JSON and return a signed
  token (payload plus an HMAC-SHA256 tag).
- **`load_signed(token, key)`** - verify the HMAC in constant time, then
  return the object. Raise `ValueError` on any tampering or wrong key.

### D.4 Research

- Why is `pickle.loads` on untrusted data dangerous? What can an attacker
  achieve?
- The *billion laughs* attack uses no external entities at all. How does it
  work, and which parser setting stops it?

---

## 3. Self-assessment checklist

- [ ] `encode_html_text` and `is_safe_url` neutralize the XSS payloads.
- [ ] Session IDs are strong and unique; cookies carry Secure/HttpOnly/SameSite.
- [ ] `rotate_session` issues a new ID and invalidates the old one.
- [ ] CSRF tokens verify in constant time; tampered tokens fail.
- [ ] `safe_redirect_target` blocks every evil target in the tests.
- [ ] `parse_xml_safely` refuses DTDs; `load_signed` detects tampering.

## Appendix - References

- OWASP Top 10:2025 - <https://owasp.org/Top10/2025/>
- OWASP Cheat Sheets - XSS Prevention, CSRF Prevention, Session Management,
  XML External Entity Prevention, Deserialization -
  <https://cheatsheetseries.owasp.org/>
- Python `secrets`, `hmac`, `html`, `xml.etree.ElementTree`, `defusedxml`
- CWE-79, CWE-352, CWE-601, CWE-384, CWE-611, CWE-502 -
  <https://cwe.mitre.org/>

*Built from the Web Application Security II lecture; examples extended into a
self-contained, self-checking lab.*
