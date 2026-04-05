# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt
# e-Soleau: DSO2026006483 (19/02/2026) — DSO2026009143 (12/03/2026)
#
# AISS — Agent Identity and Signature Standard
# Open standard. Free to use, modify, and redistribute under MIT License.
# https://aiss-standard.org · https://github.com/piqrypt/aiss-spec

"""
AISS v2.0 — Agent Identity and Signature Standard
Proof of Continuity Protocol (PCP) — reference implementation

RFC Compliance:
  RFC 8785  — JSON Canonicalization Scheme (MANDATORY)
  RFC 8032  — Ed25519 signatures
  RFC 4122  — UUID v4 nonces
  NIST FIPS 204 — ML-DSA-65 / Dilithium3 (optional, pip install aiss[post-quantum])

Profiles:
  AISS-1  — Ed25519 + SHA-256, general interoperability
  AISS-2  — Ed25519 + ML-DSA-65 hybrid, regulated environments

Quick start:
    >>> from aiss import generate_keypair, derive_agent_id, stamp_event
    >>> from aiss.memory import store_event, load_events, search_events
    >>> priv, pub = generate_keypair()
    >>> agent_id = derive_agent_id(pub)
    >>> event = stamp_event(priv, agent_id, {"action": "trade_executed"})
    >>> store_event(event)

A2A handshake:
    >>> from aiss.a2a import create_identity_proposal, perform_handshake
    >>> proposal = create_identity_proposal(priv, pub, agent_id)

Post-quantum (requires pip install aiss[post-quantum]):
    >>> from aiss.stamp_aiss2 import stamp_event_aiss2_hybrid

Reference implementation (full stack):
    pip install piqrypt   # Vigil Pro + TrustGate + Bridges + Doorkeeper
    https://piqrypt.com
"""

__version__ = "2.0.0"
__author__  = "PiQrypt"
__email__   = "contact@piqrypt.com"
__license__ = "MIT"
__url__     = "https://aiss-standard.org"
__spec__    = "AISS RFC v2.0"

# ── Core AISS-1 : Identity ────────────────────────────────────────────────────
from aiss.identity import (
    generate_keypair,
    derive_agent_id,
    export_identity,
    create_agent_identity,
    load_agent_identity,
    list_agent_identities,
    secure_agent_key,
    create_rotation_attestation,
    create_rotation_pcp_event,
)

# ── Core AISS-1 : Event stamping ──────────────────────────────────────────────
from aiss.stamp import stamp_event, stamp_genesis_event

# ── Core AISS-1 : Verification ────────────────────────────────────────────────
from aiss.verify import verify_signature, verify_chain, verify_event

# ── Core AISS-1 : Hash chain ──────────────────────────────────────────────────
from aiss.chain import compute_event_hash, compute_chain_hash, append_event

# ── Core AISS-1 : Fork detection & resolution ─────────────────────────────────
from aiss.fork import (
    ForkDetector,
    find_forks,
    resolve_fork_by_timestamp,
    resolve_fork_by_first_seen,
    get_fork_resolution_info,
    select_canonical_chain,
    detect_fork_after_finalization,
    classify_fork,
    resolve_fork_canonical,
    ForkAfterFinalizationError,
    STATUS_FORK_DETECTED,
    STATUS_FORK_AFTER_FINALIZATION,
    STATUS_NON_CANONICAL,
    STATUS_CANONICAL,
)

# ── Core AISS-1 : Exports ────────────────────────────────────────────────────
from aiss.exports import (
    export_audit_chain,
    export_audit_chain_to_file,
    validate_audit_export,
    export_subset,
    export_by_timerange,
    get_audit_summary,
)

# ── Core AISS-1 : Exceptions ─────────────────────────────────────────────────
from aiss.exceptions import (
    AISSError,
    InvalidSignatureError,
    ForkDetected,
    ReplayAttackDetected,
    InvalidChainError,
    CryptoBackendError,
)

# ── AISS-2 : Authority binding ────────────────────────────────────────────────
from aiss.authority import (
    create_authority_statement,
    verify_authority_statement,
    build_authority_chain,
    validate_authority_chain,
    get_accountable_authority,
    annotate_event_with_authority,
    extract_authority_chain,
    RESULT_VALID_AUTHORIZED,
    RESULT_VALID_UNAUTHORIZED,
    RESULT_INVALID,
    AuthorityError,
    AuthorityExpiredError,
    AuthorityScopeError,
    AuthorityChainBrokenError,
)

# ── AISS-2 : Post-quantum hybrid signatures (optional) ────────────────────────
# Requires: pip install aiss[post-quantum]
try:
    from aiss.stamp_aiss2 import (
        stamp_event_aiss2_hybrid,
        stamp_genesis_event_aiss2_hybrid,
        verify_aiss2_hybrid,
    )
    _PQ_AVAILABLE = True
except ImportError:
    _PQ_AVAILABLE = False

# ── Agent context (LLM system prompt generation) ─────────────────────────────
from aiss.agent_context import (
    get_system_prompt,
    get_agent_metadata,
    build_agent_context,
)

# ── History (full rotation chain) ────────────────────────────────────────────
from aiss.history import (
    load_full_history,
    get_history_summary,
)

# ── Logger (no PiQrypt-specific levels) ──────────────────────────────────────
from aiss.logger import (
    get_logger,
    log_identity_created,
    log_chain_verified,
)


# ── AgentIdentity — developer-friendly API ───────────────────────────────────
from aiss.agent_identity import AgentIdentity, SignedEvent


def is_post_quantum_available() -> bool:
    """Returns True if liboqs is installed and AISS-2 hybrid signatures are available."""
    return _PQ_AVAILABLE


__all__ = [
    # AgentIdentity — developer-friendly API
    "AgentIdentity", "SignedEvent",
    # Version
    "__version__", "__spec__",
    # Identity
    "generate_keypair", "derive_agent_id", "export_identity",
    "create_agent_identity", "load_agent_identity", "list_agent_identities",
    "secure_agent_key", "create_rotation_attestation", "create_rotation_pcp_event",
    # Stamping
    "stamp_event", "stamp_genesis_event",
    # Verification
    "verify_signature", "verify_chain", "verify_event",
    # Hash chain
    "compute_event_hash", "compute_chain_hash", "append_event",
    # Fork
    "ForkDetector", "find_forks", "resolve_fork_by_timestamp",
    "resolve_fork_by_first_seen", "get_fork_resolution_info",
    "select_canonical_chain", "detect_fork_after_finalization",
    "classify_fork", "resolve_fork_canonical", "ForkAfterFinalizationError",
    "STATUS_FORK_DETECTED", "STATUS_FORK_AFTER_FINALIZATION",
    "STATUS_NON_CANONICAL", "STATUS_CANONICAL",
    # Exports
    "export_audit_chain", "export_audit_chain_to_file", "validate_audit_export",
    "export_subset", "export_by_timerange", "get_audit_summary",
    # Exceptions
    "AISSError", "InvalidSignatureError", "ForkDetected",
    "ReplayAttackDetected", "InvalidChainError", "CryptoBackendError",
    # Authority
    "create_authority_statement", "verify_authority_statement",
    "build_authority_chain", "validate_authority_chain",
    "get_accountable_authority", "annotate_event_with_authority",
    "extract_authority_chain",
    "RESULT_VALID_AUTHORIZED", "RESULT_VALID_UNAUTHORIZED", "RESULT_INVALID",
    "AuthorityError", "AuthorityExpiredError", "AuthorityScopeError",
    "AuthorityChainBrokenError",
    # Post-quantum
    "is_post_quantum_available",
    # Agent context
    "get_system_prompt", "get_agent_metadata", "build_agent_context",
    # History
    "load_full_history", "get_history_summary",
    # Logger
    "get_logger", "log_identity_created", "log_chain_verified",
]
