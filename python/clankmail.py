"""ClankMail token verification and signing (SPEC.md §2–§4, §6–§7).

Written from SPEC.md, independently of the Go reference, so that shared
conformance can catch places where the spec is accidentally Go-shaped.
"""

import base64
import hashlib
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

MAX_TOKEN = 98304
DOMAIN = b"clankmail/v1\n"
MAX_SAFE_INT = 2**53 - 1
MAX_DEPTH = 16


class ClankMailError(Exception):
    def __init__(self, code, detail=""):
        super().__init__(f"{code}: {detail}")
        self.code = code


def b32(b: bytes) -> str:
    return base64.b32encode(b).decode().rstrip("=").lower()


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _canon(s, decode, encode):
    """§2: decode, re-encode, compare. None on any mismatch."""
    try:
        b = decode(s)
    except Exception:
        return None
    return b if encode(b) == s else None


def dec_b32(s: str):
    return _canon(s, lambda x: base64.b32decode(x.upper() + "=" * (-len(x) % 8)), b32)


def dec_b64(s: str):
    if not re.fullmatch(r"[A-Za-z0-9_-]*", s):
        return None
    return _canon(s, lambda x: base64.urlsafe_b64decode(x + "=" * (-len(x) % 4)), b64)


FIELD_P = 2**255 - 19
# §2 key validity rule: the y-coordinates of every point of order dividing 8.
SMALL_ORDER_Y = {
    0, 1, FIELD_P - 1,
    0x05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826,
    0x7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7,
}


def valid_key(pub: bytes) -> bool:
    y = int.from_bytes(pub, "little") & ((1 << 255) - 1)
    return y < FIELD_P and y not in SMALL_ORDER_Y


def object_id(payload: bytes) -> str:
    return "m_" + b32(hashlib.sha256(payload).digest())


def channel_id(genesis_payload: bytes) -> str:
    return "c_" + object_id(genesis_payload)[2:]


def sign(seed: bytes, payload: bytes) -> str:
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key().public_bytes_raw()
    return f"v1.{b32(pub)}.{b64(payload)}.{b64(priv.sign(DOMAIN + payload))}"


# ---------------------------------------------------------------- strict JSON

def _no_dups(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate key {k!r}")
        out[k] = v
    return out


def _int(s):
    if s.startswith("-"):
        raise ValueError("negative integer")
    n = int(s)
    if n > MAX_SAFE_INT:
        raise ValueError("integer out of range")
    return n


def _reject(s):
    raise ValueError(f"non-integer number {s}")


def _walk(v, depth):
    if isinstance(v, (dict, list)):
        depth += 1
        if depth > MAX_DEPTH:
            raise ValueError("nesting deeper than 16")
        for x in (v.values() if isinstance(v, dict) else v):
            _walk(x, depth)
    elif isinstance(v, str):
        # Python's json keeps a lone \ud800 as a surrogate code point; reject it.
        if any(0xD800 <= ord(c) <= 0xDFFF for c in v):
            raise ValueError("lone surrogate")
    if isinstance(v, dict):
        for k in v:
            _walk(k, depth)


def parse_strict(payload: bytes) -> dict:
    text = payload.decode("utf-8")  # strict: raises on invalid UTF-8
    if text.startswith("﻿"):
        raise ValueError("byte-order mark")
    v = json.loads(text, object_pairs_hook=_no_dups, parse_int=_int,
                   parse_float=_reject, parse_constant=_reject)
    if not isinstance(v, dict):
        raise ValueError("payload is not an object")
    _walk(v, 0)
    return v


# ---------------------------------------------------------------- schema

def _id(prefix):
    def check(v):
        return isinstance(v, str) and v.startswith(prefix) and \
            (b := dec_b32(v[len(prefix):])) is not None and len(b) == 32
    return check


def _str(lo, hi):
    return lambda v: isinstance(v, str) and lo <= len(v.encode()) <= hi


def _re(pat):
    return lambda v: isinstance(v, str) and re.fullmatch(pat, v) is not None


def _enum(*opts):
    return lambda v: isinstance(v, str) and v in opts


def _isint(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _hub(v):
    if not isinstance(v, str) or len(v) > 253 or "." not in v:
        return False
    return all(re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", p) for p in v.split("."))


def _list(lo, hi, each):
    return lambda v: isinstance(v, list) and lo <= len(v) <= hi and \
        all(each(x) for x in v) and len(set(v)) == len(v)


KEY, CHAN, OBJ = _id("k_"), _id("c_"), _id("m_")


def _to(v):
    return (isinstance(v, list) and len(v) == 1 and CHAN(v[0])) or _list(1, 32, KEY)(v)


R, O = True, False  # required / optional
SCHEMAS = {
    "handle": {"name": (R, _re(r"[a-z0-9][a-z0-9-]{1,30}")), "hub": (R, _hub)},
    "grant": {"agent": (R, KEY), "name": (R, _re(r"[a-z0-9][a-z0-9-]{0,31}")),
              "hub": (R, _hub), "exp": (O, _isint)},
    "enroll": {"grant": (R, OBJ)},
    "revoke": {"target": (R, OBJ)},
    "auth": {"hub": (R, _hub), "method": (R, _re(r"[A-Z]{1,16}")),
             "path": (R, lambda v: isinstance(v, str) and v.startswith("/") and len(v.encode()) <= 2048),
             "body": (R, _re(r"[0-9a-f]{64}")), "n": (O, _str(1, 64))},
    "channel": {"channel": (O, CHAN), "slug": (R, _re(r"[a-z0-9][a-z0-9-]{1,31}")),
                "title": (R, _str(1, 80)), "about": (O, _str(0, 1000)),
                "tags": (O, _list(0, 8, _re(r"[a-z0-9][a-z0-9-]{0,23}"))),
                "read": (R, _enum("public", "members")),
                "post": (R, _enum("owner", "mods", "members", "anyone")),
                "join": (R, _enum("open", "approval")),
                "mods": (O, _list(0, 16, KEY))},
    "msg": {"to": (R, _to), "body": (R, _str(1, 32768)), "subject": (O, _str(1, 200)),
            "re": (O, OBJ)},
    "join": {"channel": (R, CHAN)},
    "leave": {"channel": (R, CHAN)},
    "admit": {"channel": (R, CHAN), "member": (R, KEY)},
    "ban": {"channel": (R, CHAN), "member": (R, KEY), "until": (O, _isint)},
    "remove": {"channel": (R, CHAN), "target": (R, OBJ)},
    "sub": {"channel": (R, CHAN)},
}


def validate_schema(m: dict):
    if m.get("v") != 1 or not _isint(m.get("v")):
        raise ValueError("v must be 1")
    t = m.get("t")
    if not isinstance(t, str) or t not in SCHEMAS:
        raise ValueError(f"unknown type {t!r}")
    rules = {"from": (R, KEY), "ts": (R, _isint), **SCHEMAS[t]}
    for name, (required, check) in rules.items():
        if name not in m:
            if required:
                raise ValueError(f"missing {name}")
        elif not check(m[name]):
            raise ValueError(f"invalid {name}")


# ---------------------------------------------------------------- digest

def rank_digest(posts, limit, per_channel):
    """SPEC.md §8.1 counting, ranking and caps over hub-filtered posts.

    posts: dicts with id, channel, from, ts, optional re, and window (bool).
    Returns (items, omitted); items are {id, repliers, replies} in rank order.
    """
    window = [p for p in posts if p["window"]]
    by_id = {p["id"]: p for p in window}
    repliers = {p["id"]: set() for p in window}
    replies = {p["id"]: 0 for p in window}
    for r in posts:
        parent = by_id.get(r.get("re", ""))
        if parent and r["channel"] == parent["channel"] and r["from"] != parent["from"]:
            repliers[parent["id"]].add(r["from"])
            replies[parent["id"]] += 1
    # Byte-string id order: ids are ASCII, so str order is byte order. Sort by id
    # ascending first, then stably by the descending keys.
    window.sort(key=lambda p: p["id"].encode())
    window.sort(key=lambda p: (len(repliers[p["id"]]), replies[p["id"]], p["ts"]), reverse=True)
    items, per = [], {}
    for p in window:
        if len(items) == limit:
            break
        if per.get(p["channel"], 0) >= per_channel:
            continue
        per[p["channel"]] = per.get(p["channel"], 0) + 1
        items.append({"id": p["id"], "repliers": len(repliers[p["id"]]), "replies": replies[p["id"]]})
    return items, len(window) - len(items)


# ---------------------------------------------------------------- pipeline

def verify(token: str) -> dict:
    """Run the §4 pipeline; return {'id','t','from','fields'} or raise ClankMailError."""
    if len(token.encode()) > MAX_TOKEN:
        raise ClankMailError("E_SIZE")
    parts = token.split(".")
    if len(parts) != 4 or parts[0] != "v1":
        raise ClankMailError("E_FORMAT")
    pub, payload, sig = dec_b32(parts[1]), dec_b64(parts[2]), dec_b64(parts[3])
    if pub is None or len(pub) != 32 or not valid_key(pub) or payload is None or sig is None or len(sig) != 64:
        raise ClankMailError("E_ENCODING")
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, DOMAIN + payload)
    except (InvalidSignature, ValueError) as e:
        raise ClankMailError("E_SIGNATURE", str(e))
    try:
        fields = parse_strict(payload)
    except (ValueError, UnicodeDecodeError, RecursionError) as e:
        raise ClankMailError("E_JSON", str(e))
    try:
        validate_schema(fields)
    except ValueError as e:
        raise ClankMailError("E_SCHEMA", str(e))
    if fields["from"] != "k_" + parts[1]:
        raise ClankMailError("E_SIGNER")
    return {"id": object_id(payload), "t": fields["t"], "from": fields["from"], "fields": fields}
