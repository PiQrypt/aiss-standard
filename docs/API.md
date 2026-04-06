# AISS API Reference

Complete reference for the `aiss` Python package.

```bash
pip install aiss
```

---

## AgentIdentity — high-level API

The recommended entry point for new users.

```python
from aiss import AgentIdentity
```

### `AgentIdentity.create(name=None)`

Create a new agent identity with a fresh Ed25519 keypair.

```python
agent = AgentIdentity.create()
agent = AgentIdentity.create(name="trading_bot")

print(agent.agent_id)    # "3gFw2S1NT6dzo9vTPQ6JNWEwYFysZn8F"
print(agent.name)        # "trading_bot"
```

### `AgentIdentity.from_keys(private_key, public_key, name=None)`

Reconstruct an identity from existing keypair bytes.

```python
agent = AgentIdentity.from_keys(priv_bytes, pub_bytes)
```

### `agent.stamp(event_type, payload=None) → SignedEvent`

Stamp and sign an event. First call creates the genesis event automatically.
Subsequent calls chain from the previous event hash.

```python
e1 = agent.stamp("init",             {"version": "1.0"})
e2 = agent.stamp("trade_executed",   {"symbol": "BTC", "qty": 0.5})
e3 = agent.stamp("user_prompted",    {"data": "hello"})
```

### `agent.verify(event) → bool`

Verify the cryptographic signature of a single event.

```python
assert agent.verify(e1)          # True
assert agent.verify(e1.raw)      # also accepts raw dict
```

Raises `InvalidSignatureError` if signature is invalid.

### `agent.verify_chain() → bool`

Verify the entire event chain — signatures, hash links, no forks.

```python
assert agent.verify_chain()
```

### `agent.store(event)`

Persist a signed event to local AISS memory (`~/.aiss/`).

```python
agent.store(e2)
```

### `agent.export() → dict`

Export the chain as an AISS-1.0-AUDIT document.

```python
audit = agent.export()
# {
#   "spec": "AISS-1.0-AUDIT",
#   "agent_identity": {...},
#   "events": [...],
#   "chain_integrity_hash": "a3f7...",
#   "exported_at": 1771845244
# }
```

### `agent.chain_hash() → str`

SHA-256 hash over the full event chain.

### Properties

| Property | Type | Description |
|---|---|---|
| `agent_id` | `str` | 32-char deterministic ID |
| `public_key` | `bytes` | Ed25519 public key (32 bytes) |
| `name` | `str \| None` | Human-readable label |
| `identity_doc` | `dict` | AISS-1.0 identity document |
| `chain` | `list` | Current in-memory event chain |
| `chain_length` | `int` | Number of events |

---

## SignedEvent

Returned by `agent.stamp()`.

```python
event = agent.stamp("action", {"data": "hello"})

print(event.agent_id)     # "3gFw2S1NT6..."
print(event.event_type)   # "action"
print(event.payload)      # {"event_type": "action", "data": "hello"}
print(event.signature)    # "eA3oT793bV/hJnDX..."
print(event.hash)         # "8b1cfab333041b26..."  (SHA-256, 64 hex chars)
print(event.timestamp)    # 1771845244
print(event.previous_hash)

print(event)              # pretty JSON repr
event.to_dict()           # raw dict
event.raw                 # alias for to_dict()
```

---

## Low-level API

### Identity

```python
from aiss import generate_keypair, derive_agent_id, export_identity

priv, pub = generate_keypair()
agent_id  = derive_agent_id(pub)          # BASE58(SHA256(pub))[0:32]
identity  = export_identity(agent_id, pub)
# {
#   "version": "AISS-1.0",
#   "agent_id": "...",
#   "public_key": "...",   # base64
#   "algorithm": "Ed25519",
#   "created_at": 1771845244
# }
```

### Stamping

```python
from aiss import stamp_event, stamp_genesis_event
from aiss.chain import compute_event_hash

# Genesis — previous_hash = SHA256(public_key)
genesis = stamp_genesis_event(priv, pub, agent_id, {"event_type": "init"})

# Chained event
prev    = compute_event_hash(genesis)
event   = stamp_event(priv, agent_id, {"event_type": "action"}, previous_hash=prev)
```

### Verification

```python
from aiss import verify_event, verify_chain, verify_signature

verify_event(event, pub)          # raises InvalidSignatureError if invalid
verify_chain([genesis, event], identity)
verify_signature(event, pub)      # low-level, same as verify_event
```

### Hash chain

```python
from aiss.chain import compute_event_hash, compute_chain_hash, append_event

h     = compute_event_hash(event)    # SHA-256 hex string (64 chars)
chain_hash = compute_chain_hash(events)
events = append_event(events, new_event)
```

### Fork detection

```python
from aiss.fork import find_forks, resolve_fork_canonical

forks    = find_forks(events)
canonical = resolve_fork_canonical(fork_group)
```

### Anti-replay

```python
from aiss.replay import detect_replay_attacks

attacks = detect_replay_attacks(events)   # list of ReplayAttackDetected
```

---

## Memory

```python
from aiss.memory import (
    store_event, load_events, search_events,
    init_memory_dirs, get_memory_stats
)

# Store
store_event(event)
store_event(event, agent_name="trading_bot")

# Load
events = load_events(agent_id=agent_id)
events = load_events(month="2026-04", agent_name="trading_bot")

# Search
results = search_events(
    participant=agent_id,
    event_type="trade_executed",
    after=1700000000,
    before=1800000000,
    limit=50,
    follow_rotation=True,    # follow key rotation chain
    session_id="sess_a3f9",  # multi-agent session filter
)

# Stats
stats = get_memory_stats()
# {"total_events": 42, "months": [...], "storage_path": "~/.aiss/..."}
```

Storage location: `~/.aiss/agents/<name>/events/plain/YYYY-MM.json`

Encrypted storage (AES-256-GCM) is available in [PiQrypt](https://piqrypt.com).

---

## Exports

```python
from aiss.exports import (
    export_audit_chain,
    export_audit_chain_to_file,
    validate_audit_export,
    export_subset,
    export_by_timerange,
    get_audit_summary,
)

# Export full chain
audit = export_audit_chain(identity, events)
export_audit_chain_to_file(events, identity, "audit.json")

# Validate
validate_audit_export(audit)   # raises ValueError if invalid

# Selective
subset = export_subset(audit, start_index=10, end_index=20)
ranged = export_by_timerange(audit, start_timestamp=1700000000, end_timestamp=1800000000)

# Summary
summary = get_audit_summary(audit)
# {"agent_id": "...", "event_count": 42, "chain_hash": "...", ...}
```

---

## A2A — Agent-to-Agent Trust

```python
from aiss.a2a import (
    create_identity_proposal,
    verify_identity_proposal,
    perform_handshake,
    record_external_interaction,
    register_peer, list_peers, update_peer_trust_score,
)

# Propose identity to another agent
proposal = create_identity_proposal(priv, pub, agent_id)

# Full mutual handshake (both agents must participate)
session = perform_handshake(
    priv_a, pub_a, agent_id_a,
    pub_b, agent_id_b
)

# Record interaction with a non-AISS system (unilateral)
event = record_external_interaction(
    priv, agent_id,
    peer_id="external_llm_api",
    payload={"model": "gpt-4", "tokens": 1200}
)

# Peer registry
register_peer(agent_id_b, pub_b)
peers = list_peers()
update_peer_trust_score(agent_id_b, score=0.95)
```

---

## Post-quantum (AISS-2)

Requires: `pip install aiss[post-quantum]`

```python
from aiss.stamp_aiss2 import (
    stamp_event_aiss2_hybrid,
    stamp_genesis_event_aiss2_hybrid,
    verify_aiss2_hybrid,
)
from aiss import is_post_quantum_available

if is_post_quantum_available():
    event = stamp_event_aiss2_hybrid(
        ed25519_priv, dilithium_priv,
        agent_id, payload
    )
    verify_aiss2_hybrid(ed25519_pub, dilithium_pub, event)
```

AISS-2 events carry dual signatures:
```json
{
  "signatures": {
    "classical":    { "algorithm": "Ed25519",   "signature": "..." },
    "post_quantum": { "algorithm": "ML-DSA-65", "signature": "..." }
  }
}
```

---

## Exceptions

```python
from aiss.exceptions import (
    AISSError,               # base class
    InvalidSignatureError,   # signature verification failed
    InvalidChainError,       # hash chain broken
    ForkDetected,            # fork in event chain
    ReplayAttackDetected,    # duplicate nonce
    CryptoBackendError,      # missing crypto dependency
)
```

---

## Vigil

```bash
aiss start    # → http://localhost:8421
```

```python
from vigil import start_vigil, stop_vigil
start_vigil(port=8421)
```

---

## Spec

Full protocol specification: [RFC_AISS_v2.0.md](RFC_AISS_v2.0.md)
