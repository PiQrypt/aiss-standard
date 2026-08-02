"""RFC 8785 conformance vectors that the existing suite cannot fail on.

`tests/test_vectors/canonical.json` has five vectors and they all pass — but
between them they contain no float, no non-ASCII character, no non-BMP character
and no escape-requiring character. The vector named `unicode` is
`{"emoji": "ok", "name": "test"}`. So an implementation can be green there and
still emit different bytes from a conformant JCS implementation, which for a
signature standard means two conformant implementations disagreeing on a hash.

These vectors come from RFC 8785 Table 1 rather than from anyone's judgement
about what is worth testing.
"""
import json
import struct
from pathlib import Path

import pytest

from aiss.canonical import canonicalize
from aiss.exceptions import InvalidCanonicalJSONError

VECTORS = Path(__file__).parent / "test_vectors"
NUMBERS = json.loads((VECTORS / "canonical_numbers.json").read_text())
ORDERING = json.loads((VECTORS / "canonical_ordering.json").read_text())


def _double(hex16: str) -> float:
    return struct.unpack(">d", bytes.fromhex(hex16))[0]


@pytest.mark.parametrize("vec", NUMBERS["tests"], ids=lambda v: v["name"])
def test_rfc8785_table1_numbers(vec):
    """Every row of RFC 8785 Table 1, byte for byte."""
    value = _double(vec["ieee754_hex"])
    assert canonicalize(value).decode() == vec["expected_number"]


def test_the_number_vectors_actually_exercise_the_divergent_cases():
    """A control on the vectors themselves.

    The whole reason this file exists is that a suite can be green because it
    never asks the hard question. So assert the hard questions are present:
    an integral-valued double, a value in the 1e16..1e21 band where Python and
    ECMAScript disagree about positional notation, and a small negative
    exponent.
    """
    expected = [v["expected_number"] for v in NUMBERS["tests"]]
    assert "9007199254740992" in expected, "no integral-valued double"
    assert any(e.startswith("2951479") for e in expected), "nothing in the 1e16-1e21 band"
    assert "0.000001" in expected, "no small-exponent positional case"
    assert len(NUMBERS["tests"]) == 24


@pytest.mark.parametrize("vec", [v for v in ORDERING["tests"] if v["kind"] == "key_order"], ids=lambda v: v["name"])
def test_rfc8785_key_ordering_is_utf16(vec):
    """RFC 8785 3.2.3 sorts by UTF-16 code units, not code points."""
    assert canonicalize(vec["input"]).decode() == vec["expected_canonical"]


@pytest.mark.parametrize("vec", [v for v in ORDERING["tests"] if v["kind"] == "integer_range"], ids=lambda v: v["name"])
def test_integers_outside_the_double_range_are_refused(vec):
    """Python ints are arbitrary precision; ECMAScript numbers are doubles."""
    if vec["expect"] == "accepted":
        assert canonicalize(vec["input"]).decode() == str(vec["input"])
    else:
        with pytest.raises(InvalidCanonicalJSONError):
            canonicalize(vec["input"])


def test_the_original_five_vectors_still_pass():
    """No regression on the pre-existing suite."""
    original = json.loads((VECTORS / "canonical.json").read_text())
    for t in original["tests"]:
        assert canonicalize(t["input"]).decode() == t["expected_canonical"], t["name"]
