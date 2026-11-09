"""
demo_parsers.py -- Part D: XXE & insecure deserialization.

Shows an XML parser that refuses documents declaring a DTD (so the
billion-laughs bomb and external entities never expand), and a safe,
signed JSON payload format that detects tampering.
Run:  python demo_parsers.py

NOTE: the billion-laughs string below is NEVER expanded -- the safe parser
rejects it on sight, before any parsing happens.
"""
import base64
import hashlib
import hmac
import json
import xml.etree.ElementTree as ET

KEY = b"payload-signing-key"

NORMAL_XML = "<user><name>Alice</name><role>student</role></user>"

EXTERNAL_ENTITY = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>'
    "<foo>&xxe;</foo>"
)

BILLION_LAUGHS = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE lolz [ <!ENTITY lol "lol">'
    '  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"> ]>'
    "<lolz>&lol2;</lolz>"
)


def parse_vulnerable(xml_str):
    """UNSAFE in general: a parser that honours the DTD. (Not called on the
    bombs here -- shown only to name the risky pattern.)"""
    return ET.fromstring(xml_str)


def parse_safe(xml_str):
    """SAFE: refuse any document that declares a DTD, then parse."""
    if "<!doctype" in xml_str.lower():
        raise ValueError("DTD declarations are not allowed")
    return ET.fromstring(xml_str)


def sign(obj):
    payload = base64.urlsafe_b64encode(json.dumps(obj).encode()).decode()
    tag = hmac.new(KEY, payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{tag}"


def load(token):
    payload, _, tag = token.partition(".")
    expected = hmac.new(KEY, payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, tag):
        raise ValueError("signature mismatch -- payload tampered")
    return json.loads(base64.urlsafe_b64decode(payload))


if __name__ == "__main__":
    print("== XML parsing ==")
    print("normal doc root tag:", parse_safe(NORMAL_XML).tag)
    for name, doc in (("external entity", EXTERNAL_ENTITY), ("billion laughs", BILLION_LAUGHS)):
        try:
            parse_safe(doc)
        except ValueError as e:
            print(f"rejected ({name}): {e}")
    print()
    print("== signed payload ==")
    token = sign({"user": "alice", "role": "student"})
    print("round-trip:", load(token))
    tampered = token[:-1] + ("0" if token[-1] != "0" else "1")
    try:
        load(tampered)
    except ValueError as e:
        print("tampered rejected:", e)
