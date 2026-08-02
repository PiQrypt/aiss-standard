# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
#
# Part of the AISS protocol specification.
# Free to use, modify, and redistribute -- see root LICENSE for details.

"""
RFC 8785 - JSON Canonicalization Scheme (JCS)

Pure stdlib implementation of RFC 8785 — zero external dependencies.
AISS Section 3: Canonicalization is MANDATORY for all signed/hashed structures.

RFC 8785 guarantees:
  - Lexicographic key ordering (recursive)
  - No insignificant whitespace
  - UTF-8 encoding (no BOM)
  - Deterministic number representation
  - Unicode normalization (NFC implied by JSON spec)

WARNING: Standard json.dumps(sort_keys=True) is NOT RFC 8785 compliant.
"""

import json
import hashlib
import math
from typing import Any

from aiss.exceptions import InvalidCanonicalJSONError


# ─── RFC 8785 implementation ──────────────────────────────────────────────────

def _round_trips_as_double(n: int) -> bool:
    """True when ``n`` survives int -> double -> int unchanged.

    Deliberately a property test rather than a ``2**53 - 1`` bound: 2**53 itself
    IS exactly representable and RFC 8785 Table 1 lists it ("Max pos int"), so a
    constant cutoff would reject a value the RFC expects.
    """
    try:
        return int(float(n)) == n
    except (OverflowError, ValueError):
        return False


def _es_number_to_string(x: float) -> str:
    """ECMAScript ``Number::toString``, which RFC 8785 3.2.2.3 defers to.

    ``repr()`` is NOT this algorithm. It agrees on many values and diverges on
    three whole classes: integral-valued doubles keep a ``.0``; Python switches
    to exponential notation at 1e16 where ECMAScript stays positional to 1e21;
    and Python zero-pads the exponent (``1e-07``) where ECMAScript does not.

    Verified against all 24 rows of RFC 8785 Table 1.
    """
    if x == 0:
        return "0"  # ECMAScript renders both +0 and -0 as "0"
    if x < 0:
        return "-" + _es_number_to_string(-x)

    # repr() gives the shortest round-tripping decimal, which is exactly the
    # digit string ECMAScript calls `s`. Recover (s, n) with value = 0.s * 10**n.
    r = repr(x)
    if "e" in r or "E" in r:
        mant, _, exp_s = r.partition("e")
        exp = int(exp_s)
    else:
        mant, exp = r, 0
    intpart, _, frac = mant.partition(".")
    raw = intpart + frac
    digits = raw.lstrip("0")
    n = len(intpart) + exp - (len(raw) - len(digits))
    digits = digits.rstrip("0") or "0"
    k = len(digits)

    if k <= n <= 21:
        return digits + "0" * (n - k)
    if 0 < n <= 21:
        return digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + digits
    e = n - 1
    return f"{digits if k == 1 else digits[0] + '.' + digits[1:]}e{'+' if e >= 0 else '-'}{abs(e)}"


def _serialize_value(value: Any) -> str:
    """Serialize a JSON value in RFC 8785 canonical form."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        # RFC 8785 numbers are ECMAScript numbers, i.e. IEEE-754 doubles. Python
        # ints are arbitrary precision, so a value above 2**53-1 canonicalizes
        # exactly here and is read back rounded by any JS implementation —
        # different bytes, different hash, failed signature. Refuse rather than
        # emit something only this implementation can reproduce.
        if not _round_trips_as_double(value):
            raise InvalidCanonicalJSONError(
                f"integer {value} does not round-trip through an IEEE-754 double, "
                f"so an ECMAScript implementation would read back a different "
                f"value and compute a different hash; RFC 8785 output would not "
                f"be portable"
            )
        return str(value)
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise InvalidCanonicalJSONError(f"NaN/Infinity not allowed in RFC 8785: {value}")
        return _es_number_to_string(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        items = ",".join(_serialize_value(item) for item in value)
        return f"[{items}]"
    if isinstance(value, dict):
        # RFC 8785 3.2.3 sorts by UTF-16 code units, NOT code points. They agree
        # across the BMP and diverge above it: a supplementary character's leading
        # surrogate (0xD800-0xDBFF) sorts BELOW 0xE000-0xFFFF, so plain Python
        # string comparison puts non-BMP keys in the wrong place.
        sorted_pairs = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        pairs = ",".join(
            f"{json.dumps(k, ensure_ascii=False)}:{_serialize_value(v)}"
            for k, v in sorted_pairs
        )
        return "{" + pairs + "}"
    raise InvalidCanonicalJSONError(f"Cannot canonicalize type: {type(value)}")


def canonicalize(obj: Any) -> bytes:
    """
    Serialize object to RFC 8785 canonical JSON bytes.

    AISS Section 3: MANDATORY for all structures that are hashed or signed.

    Args:
        obj: Python dict/list/primitive to canonicalize

    Returns:
        RFC 8785 canonical JSON as UTF-8 bytes (no BOM)

    Example:
        >>> canonicalize({"b": 2, "a": 1})
        b'{"a":1,"b":2}'
    """
    try:
        return _serialize_value(obj).encode("utf-8")
    except InvalidCanonicalJSONError:
        raise
    except Exception as e:
        raise InvalidCanonicalJSONError(f"Failed to canonicalize: {e}")


def hash_canonical(obj: Any) -> str:
    """
    Compute SHA-256 hash of RFC 8785 canonicalized object.

    Returns:
        Lowercase hex SHA-256 string (64 chars)
    """
    return hashlib.sha256(canonicalize(obj)).hexdigest()


def hash_bytes(data: bytes) -> str:
    """Compute SHA-256 hash of raw bytes. Returns lowercase hex string."""
    return hashlib.sha256(data).hexdigest()


def verify_canonical(data: bytes) -> bool:
    """Verify that bytes are valid RFC 8785 canonical JSON."""
    try:
        obj = json.loads(data.decode("utf-8"))
        return canonicalize(obj) == data
    except Exception:
        return False


__all__ = ["canonicalize", "hash_canonical", "hash_bytes", "verify_canonical"]
