# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt
# e-Soleau: DSO2026006483 (19/02/2026) — DSO2026009143 (12/03/2026)
#
# AISS — Agent Identity and Signature Standard
# https://aiss-standard.org

"""
AISS-2 Hybrid Signatures — RFC §7.3, §4.2

Post-quantum + classical dual signatures.

Cryptographic algorithms:
  Ed25519    — classical (RFC 8032, 128-bit security)
  ML-DSA-65  — post-quantum (NIST FIPS 204, Dilithium3, 256-bit PQ security)

Requires: pip install aiss[post-quantum]   (liboqs-python)

RFC 3161 trusted timestamps and certified exports are available
in the full PiQrypt implementation: https://piqrypt.com
"""

import time
import base64
from typing import Dict, Any, Optional, List

from aiss.crypto import ed25519, dilithium
from aiss.canonical import canonicalize
from aiss.stamp import generate_nonce
from aiss.exceptions import CryptoBackendError, AISSError
from aiss.logger import get_logger

logger = get_logger(__name__)


def _require_dilithium() -> None:
    """Raise CryptoBackendError if Dilithium backend is not available."""
    if not dilithium or not dilithium.is_available():
        raise CryptoBackendError(
            "Dilithium3",
            "AISS-2 hybrid signatures require the Dilithium3 backend.\n"
            "Install: pip install aiss[post-quantum]\n"
            "Requires: liboqs-python"
        )


def stamp_event_aiss2_hybrid(
    private_key_ed25519: bytes,
    private_key_dilithium: bytes,
    agent_id: str,
    payload: Dict[str, Any],
    previous_hash: Optional[str] = None,
    nonce: Optional[str] = None,
    timestamp: Optional[int] = None,
    authority_chain: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Create an AISS-2.0 event with hybrid Ed25519 + ML-DSA-65 signatures.

    AISS-2 events carry dual signatures for forward secrecy against
    quantum attacks, while remaining backward-verifiable with Ed25519.

    Args:
        private_key_ed25519:   Ed25519 private key (32 bytes)
        private_key_dilithium: ML-DSA-65 / Dilithium3 private key
        agent_id:              Agent ID (from derive_agent_id)
        payload:               Event data dict
        previous_hash:         Hash of previous event (None → genesis)
        nonce:                 UUID v4 nonce (auto-generated if None)
        timestamp:             Unix UTC timestamp (auto-generated if None)
        authority_chain:       Optional delegation chain (RFC §17)

    Returns:
        AISS-2.0 signed event dict

    Raises:
        CryptoBackendError: If liboqs-python is not installed

    Example:
        from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid, verify_aiss2_hybrid

        event = stamp_event_aiss2_hybrid(
            priv_ed25519, priv_dilithium, agent_id,
            {"event_type": "decision", "action": "approve"}
        )
        assert event["version"] == "AISS-2.0"
        assert "signatures" in event
    """
    _require_dilithium()

    if nonce is None:
        nonce = generate_nonce()
    if timestamp is None:
        timestamp = int(time.time())

    # Build event structure (without signatures)
    event: Dict[str, Any] = {
        "version":       "AISS-2.0",
        "agent_id":      agent_id,
        "timestamp":     timestamp,
        "nonce":         nonce,
        "payload":       payload,
        "previous_hash": previous_hash,
    }

    if authority_chain:
        event["authority_chain"] = authority_chain

    # Canonicalize for signing
    canonical = canonicalize(event)

    # Sign with Ed25519 (classical)
    sig_ed25519 = ed25519.sign(private_key_ed25519, canonical)

    # Sign with ML-DSA-65 / Dilithium3 (post-quantum)
    sig_dilithium = dilithium.sign(private_key_dilithium, canonical)

    event["signatures"] = {
        "classical": {
            "algorithm": "Ed25519",
            "signature": ed25519.encode_base58(sig_ed25519),
        },
        "post_quantum": {
            "algorithm": "ML-DSA-65",
            "signature": base64.b64encode(sig_dilithium).decode("utf-8"),
        },
    }

    logger.debug("[AISS] AISS-2 hybrid event signed (Ed25519 + ML-DSA-65)")
    return event


def stamp_genesis_event_aiss2_hybrid(
    private_key_ed25519: bytes,
    private_key_dilithium: bytes,
    public_key_ed25519: bytes,
    agent_id: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Create an AISS-2.0 genesis event with hybrid signatures.

    Genesis previous_hash = SHA256(Ed25519 public key),
    maintaining compatibility with AISS-1 chain anchoring.

    Args:
        private_key_ed25519:   Ed25519 private key
        private_key_dilithium: ML-DSA-65 private key
        public_key_ed25519:    Ed25519 public key (for genesis hash)
        agent_id:              Agent ID
        payload:               Genesis event data

    Returns:
        AISS-2.0 genesis event
    """
    from aiss.canonical import hash_bytes
    genesis_hash = hash_bytes(public_key_ed25519)
    return stamp_event_aiss2_hybrid(
        private_key_ed25519,
        private_key_dilithium,
        agent_id,
        payload,
        previous_hash=genesis_hash,
    )


def verify_aiss2_hybrid(
    event: Dict[str, Any],
    public_key_ed25519: bytes,
    public_key_dilithium: bytes,
) -> bool:
    """
    Verify an AISS-2.0 hybrid event's dual signatures.

    Both Ed25519 and ML-DSA-65 signatures must be valid.

    Args:
        event:                  AISS-2.0 event dict
        public_key_ed25519:     Ed25519 public key
        public_key_dilithium:   ML-DSA-65 / Dilithium3 public key

    Returns:
        True if both signatures are valid

    Raises:
        InvalidSignatureError: If either signature is invalid
        CryptoBackendError:    If liboqs-python is not installed
    """
    from aiss.exceptions import InvalidSignatureError
    _require_dilithium()

    signatures = event.get("signatures")
    if not signatures:
        raise InvalidSignatureError("AISS-2 event missing 'signatures' field")

    classical   = signatures.get("classical")
    post_quantum = signatures.get("post_quantum")

    if not classical or not post_quantum:
        raise InvalidSignatureError(
            "AISS-2 event missing 'classical' or 'post_quantum' signature block"
        )

    # Reconstruct canonical form (without signatures)
    event_copy = {k: v for k, v in event.items() if k != "signatures"}
    canonical  = canonicalize(event_copy)

    # Verify Ed25519
    try:
        sig_bytes = ed25519.decode_base58(classical["signature"])
        ed25519.verify(public_key_ed25519, canonical, sig_bytes)
    except Exception as e:
        raise InvalidSignatureError(f"Ed25519 signature invalid: {e}")

    # Verify ML-DSA-65 / Dilithium3
    try:
        sig_bytes = base64.b64decode(post_quantum["signature"])
        if not dilithium.verify(public_key_dilithium, canonical, sig_bytes):
            raise InvalidSignatureError("ML-DSA-65 signature invalid")
    except InvalidSignatureError:
        raise
    except Exception as e:
        raise InvalidSignatureError(f"ML-DSA-65 signature verification failed: {e}")

    logger.debug("[AISS] AISS-2 hybrid signatures verified")
    return True


__all__ = [
    "stamp_event_aiss2_hybrid",
    "stamp_genesis_event_aiss2_hybrid",
    "verify_aiss2_hybrid",
]
