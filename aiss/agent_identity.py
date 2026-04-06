# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt
# e-Soleau: DSO2026006483 (19/02/2026) — DSO2026009143 (12/03/2026)
#
# AISS — Agent Identity and Signature Standard
# https://aiss-standard.org

"""
AgentIdentity — developer-friendly API for AISS.

Thin wrapper over the low-level AISS primitives.
The underlying protocol (identity, stamp, verify, chain) is unchanged.

Quick start:
    from aiss import AgentIdentity

    agent = AgentIdentity.create()
    event = agent.stamp("user_prompted", {"input": "hello"})
    assert agent.verify(event)
    print(event)

This class is the recommended entry point for new users.
For full protocol access use the low-level API directly:
    from aiss import generate_keypair, derive_agent_id, stamp_event, verify_event
"""

import json
from typing import Any, Dict, List, Optional

from aiss.identity import generate_keypair, derive_agent_id, export_identity
from aiss.stamp import stamp_event, stamp_genesis_event
from aiss.verify import verify_event, verify_chain
from aiss.chain import compute_event_hash, compute_chain_hash
from aiss.exports import export_audit_chain
from aiss.exceptions import InvalidSignatureError


class SignedEvent:
    """
    A signed AISS event.

    Thin wrapper around the raw event dict that provides
    convenient accessors and a clean repr.
    """

    def __init__(self, raw: Dict[str, Any]):
        self._raw = raw

    # ── Accessors ─────────────────────────────────────────────────────────────

    @property
    def agent_id(self) -> str:
        return self._raw["agent_id"]

    @property
    def event_type(self) -> str:
        return self._raw.get("payload", {}).get("event_type", "")

    @property
    def payload(self) -> Dict[str, Any]:
        return self._raw.get("payload", {})

    @property
    def signature(self) -> str:
        return self._raw["signature"]

    @property
    def hash(self) -> str:
        return compute_event_hash(self._raw)

    @property
    def timestamp(self) -> int:
        return self._raw["timestamp"]

    @property
    def previous_hash(self) -> Optional[str]:
        return self._raw.get("previous_hash")

    @property
    def raw(self) -> Dict[str, Any]:
        """Access the underlying raw event dict (full AISS protocol structure)."""
        return self._raw

    def to_dict(self) -> Dict[str, Any]:
        """Return the full raw event dict."""
        return self._raw

    def __repr__(self) -> str:
        return json.dumps(
            {
                "agent_id":   self.agent_id,
                "event_type": self.event_type,
                "payload":    self.payload,
                "signature":  self.signature[:24] + "...",
                "hash":       self.hash[:16] + "...",
                "timestamp":  self.timestamp,
            },
            indent=2,
        )

    def __str__(self) -> str:
        return self.__repr__()


class AgentIdentity:
    """
    AISS agent identity with event chain management.

    Creates a cryptographic identity for an autonomous agent
    and provides methods to stamp and verify events.

    Quick start:
        agent = AgentIdentity.create()
        event = agent.stamp("decision_made", {"action": "buy", "symbol": "BTC"})
        assert agent.verify(event)

    The identity holds:
    - A private/public Ed25519 keypair
    - A deterministic agent_id derived from the public key
    - An in-memory event chain (use store() to persist)

    For persistence across sessions, use the low-level API:
        from aiss.identity import create_agent_identity, load_agent_identity
    """

    def __init__(
        self,
        private_key: bytes,
        public_key: bytes,
        agent_id: str,
        name: Optional[str] = None,
    ):
        self._private_key = private_key
        self._public_key  = public_key
        self._agent_id    = agent_id
        self._name        = name
        self._chain: List[Dict[str, Any]] = []
        self._genesis_created = False

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def create(cls, name: Optional[str] = None) -> "AgentIdentity":
        """
        Create a new AISS agent identity.

        Generates a fresh Ed25519 keypair and derives the agent_id.
        Each call produces a unique identity.

        Args:
            name: Optional human-readable label (not part of the protocol)

        Returns:
            AgentIdentity instance ready to stamp events

        Example:
            agent = AgentIdentity.create()
            print(agent.agent_id)   # "3gFw2S1NT6dzo9v..."
        """
        private_key, public_key = generate_keypair()
        agent_id = derive_agent_id(public_key)
        return cls(private_key, public_key, agent_id, name=name)

    @classmethod
    def from_keys(
        cls,
        private_key: bytes,
        public_key: bytes,
        name: Optional[str] = None,
    ) -> "AgentIdentity":
        """
        Reconstruct an AgentIdentity from existing keypair bytes.

        Useful when loading a persisted identity.

        Args:
            private_key: Ed25519 private key bytes (32 bytes)
            public_key:  Ed25519 public key bytes (32 bytes)
            name:        Optional human-readable label

        Returns:
            AgentIdentity instance
        """
        agent_id = derive_agent_id(public_key)
        return cls(private_key, public_key, agent_id, name=name)

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def agent_id(self) -> str:
        """Deterministic 32-char agent ID derived from the public key."""
        return self._agent_id

    @property
    def public_key(self) -> bytes:
        """Ed25519 public key bytes."""
        return self._public_key

    @property
    def name(self) -> Optional[str]:
        """Human-readable label (not part of the protocol)."""
        return self._name

    @property
    def identity_doc(self) -> Dict[str, Any]:
        """AISS-1.0 identity document (RFC §6)."""
        return export_identity(self._agent_id, self._public_key)

    @property
    def chain(self) -> List[Dict[str, Any]]:
        """Current in-memory event chain (raw dicts)."""
        return list(self._chain)

    @property
    def chain_length(self) -> int:
        """Number of events in the current chain."""
        return len(self._chain)

    # ── Core operations ───────────────────────────────────────────────────────

    def stamp(
        self,
        event_type: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> SignedEvent:
        """
        Stamp and sign an event, appending it to the chain.

        On the first call, creates the genesis event.
        Subsequent calls chain automatically from the previous event hash.

        Args:
            event_type: Machine-readable action label (e.g. "user_prompted")
            payload:    Optional event data dict

        Returns:
            SignedEvent — signed, hash-chained event

        Example:
            event = agent.stamp("trade_executed", {"symbol": "BTC", "qty": 0.5})
            print(event.hash)
            print(event.signature)
        """
        full_payload = {"event_type": event_type}
        if payload:
            full_payload.update(payload)

        if not self._genesis_created:
            # First event — genesis
            raw = stamp_genesis_event(
                self._private_key,
                self._public_key,
                self._agent_id,
                full_payload,
            )
            self._genesis_created = True
        else:
            # Chained event
            previous_hash = compute_event_hash(self._chain[-1])
            raw = stamp_event(
                self._private_key,
                self._agent_id,
                full_payload,
                previous_hash=previous_hash,
            )

        self._chain.append(raw)
        return SignedEvent(raw)

    def verify(self, event: "SignedEvent | Dict[str, Any]") -> bool:
        """
        Verify the cryptographic signature of a single event.

        Args:
            event: SignedEvent instance or raw event dict

        Returns:
            True if signature is valid

        Raises:
            InvalidSignatureError: If signature verification fails

        Example:
            event = agent.stamp("decision", {"action": "buy"})
            assert agent.verify(event)   # True
        """
        raw = event.raw if isinstance(event, SignedEvent) else event
        return verify_event(raw, self._public_key)

    def verify_chain(self) -> bool:
        """
        Verify the integrity of the entire event chain.

        Checks:
        - All signatures are valid
        - Hash chain is unbroken
        - No forks or replays

        Returns:
            True if chain is intact

        Raises:
            InvalidChainError: If chain integrity fails

        Example:
            agent.stamp("step_1", {})
            agent.stamp("step_2", {})
            assert agent.verify_chain()
        """
        if not self._chain:
            return True
        return verify_chain(self._chain, self.identity_doc)

    # ── Storage & export ──────────────────────────────────────────────────────

    def store(self, event: "SignedEvent | Dict[str, Any]") -> None:
        """
        Persist a signed event to local AISS memory (~/.aiss/).

        Args:
            event: SignedEvent instance or raw event dict

        Example:
            event = agent.stamp("trade_executed", {"symbol": "BTC"})
            agent.store(event)
        """
        from aiss.memory import store_event as _store
        raw = event.raw if isinstance(event, SignedEvent) else event
        _store(raw)

    def export(self) -> Dict[str, Any]:
        """
        Export the current chain as an AISS-1.0-AUDIT document.

        Returns:
            Audit export dict with chain_integrity_hash

        Example:
            audit = agent.export()
            print(audit["chain_integrity_hash"])
        """
        return export_audit_chain(self.identity_doc, self._chain)

    def chain_hash(self) -> str:
        """
        Compute the integrity hash of the current chain.

        Returns:
            SHA-256 hex string over the full chain
        """
        return compute_chain_hash(self._chain)

    # ── Repr ──────────────────────────────────────────────────────────────────

    def __repr__(self) -> str:
        label = f" ({self._name})" if self._name else ""
        return (
            f"AgentIdentity{label}\n"
            f"  agent_id : {self._agent_id}\n"
            f"  chain    : {self.chain_length} event(s)\n"
            f"  profile  : AISS-1"
        )

    def __str__(self) -> str:
        return self.__repr__()
