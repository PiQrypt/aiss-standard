# AISS v1.1 — Agent Identity & Signature Standard

**Status:** Draft  
**Version:** 1.1  
**Date:** 2026-02-20  
**License:** MIT  
**e-Soleau:** DSO2026006483 (INPI, 19/02/2026)

---

## Abstract

AISS (Agent Identity & Signature Standard) defines a cryptographic protocol for creating verifiable audit trails of autonomous agent decisions. The protocol ensures:

- **Non-repudiation:** Agents cannot deny actions
- **Integrity:** Tamper-proof event chains
- **Auditability:** Human-verifiable proofs
- **Post-quantum security:** Resistance to quantum attacks

---

## 1. Introduction

### 1.1 Motivation

Autonomous AI agents make critical decisions (trading, medical diagnosis, autonomous driving) without direct human oversight. Traditional logging is insufficient because:

- Logs can be modified retroactively
- No cryptographic proof of authorship
- No protection against quantum computers
- No standardized format for audit

AISS provides a **cryptographically verifiable audit trail** using digital signatures and hash chains.

### 1.2 Scope

This specification defines:
- Agent identity derivation
- Event structure and signing
- Hash chain construction
- Fork detection and resolution
- Post-quantum signature schemes

This specification does NOT define:
- Storage mechanisms (filesystem, database, blockchain)
- Network protocols (transport, discovery)
- Authorization policies
- User interfaces

---

## 2. Agent Identity

### 2.1 Public Key Cryptography

An agent identity is derived from a public/private key pair.

**AISS-1.0 (Classical):**
- Algorithm: Ed25519 (RFC 8032)
- Private key: 32 bytes
- Public key: 32 bytes
- Security: 128-bit

**AISS-2.0 (Post-Quantum):**
- Classical: Ed25519
- Post-quantum: ML-DSA-65 (NIST FIPS 204, Dilithium3)
- Security: 256-bit (PQ)

### 2.2 Agent ID Derivation

The agent identifier is derived from the public key:

```
agent_id = base58(SHA-256(public_key)[0:24])
```

**Properties:**
- Length: 32 characters (base58)
- Collision resistance: 2^192
- Human-readable (no ambiguous characters)

**Example:**
```
Public key:  a3f7e8c9b1d5...
SHA-256:     4a2b1c9f7e3d...
Agent ID:    5Z8nY7KpL9mN3qR4sT6uV8wX
```

---

## 3. Event Structure

### 3.1 AISS-1.0 Event (Classical)

```json
{
  "version": "AISS-1.0",
  "agent_id": "5Z8nY7KpL9mN3qR4sT6uV8wX",
  "timestamp": 1739395200,
  "nonce": "uuid-v4-string",
  "payload": {
    "event_type": "decision",
    "data": {}
  },
  "previous_hash": "sha256:abc123...",
  "signature": "base64:ed25519_signature"
}
```

**Field Definitions:**

| Field | Type | Description | Required |
|-------|------|-------------|----------|
| `version` | string | Protocol version ("AISS-1.0") | Yes |
| `agent_id` | string | Agent identifier (32 chars) | Yes |
| `timestamp` | integer | Unix UTC seconds | Yes |
| `nonce` | string | UUID v4 (anti-replay) | Yes |
| `payload` | object | Event data (JSON) | Yes |
| `previous_hash` | string | Hash of previous event | Yes* |
| `signature` | string | Ed25519 signature (base64) | Yes |

*For first event, use `"genesis"`

### 3.2 AISS-2.0 Event (Hybrid PQ)

```json
{
  "version": "AISS-2.0",
  "agent_id": "5Z8nY7KpL9mN3qR4sT6uV8wX",
  "timestamp": 1739395200,
  "nonce": "uuid-v4-string",
  "payload": {
    "event_type": "decision",
    "data": {}
  },
  "previous_hash": "sha256:abc123...",
  "signatures": {
    "classical": {
      "algorithm": "Ed25519",
      "signature": "base64:..."
    },
    "post_quantum": {
      "algorithm": "ML-DSA-65",
      "signature": "base64:..."
    }
  }
}
```

**Hybrid Approach:**
- Both Ed25519 AND Dilithium3 signatures
- Event valid if BOTH verify
- Backward compatible (AISS-1.0 tools can verify classical)
- Future-proof (quantum resistance)

---

## 4. Canonical JSON (RFC 8785)

### 4.1 Requirement

Events MUST be serialized using RFC 8785 canonical JSON before hashing or signing.

**Why:** Ensures identical byte representation across implementations.

### 4.2 Canonicalization Rules

1. **Whitespace:** Removed (no spaces, newlines)
2. **Key order:** Lexicographic (UTF-8 byte order)
3. **Numbers:** No leading zeros, no trailing zeros after decimal
4. **Unicode:** \uXXXX escapes for control characters

**Example:**
```json
// Original
{
  "b": 2,
  "a": 1
}

// Canonical
{"a":1,"b":2}
```

### 4.3 Implementation

Libraries:
- Python: `canonicaljson`
- JavaScript: `json-canonicalize`
- Go: `github.com/gibson042/canonicaljson`

---

## 5. Hash Chain

### 5.1 Chain Construction

Events are linked via cryptographic hashing:

```
Event 1: previous_hash = "genesis"
Event 2: previous_hash = SHA-256(canonical(Event 1))
Event 3: previous_hash = SHA-256(canonical(Event 2))
...
```

### 5.2 Event Hash Computation

```python
def compute_event_hash(event):
    # 1. Remove signature field
    unsigned_event = {k: v for k, v in event.items() if k != 'signature'}
    
    # 2. Canonicalize
    canonical = canonicalize_json(unsigned_event)
    
    # 3. Hash
    return "sha256:" + hashlib.sha256(canonical).hexdigest()
```

### 5.3 Chain Integrity

**Property:** Any modification to any event invalidates all subsequent events.

**Verification:**
```python
def verify_chain(events):
    for i in range(1, len(events)):
        expected_hash = compute_event_hash(events[i-1])
        actual_hash = events[i]["previous_hash"]
        
        if expected_hash != actual_hash:
            return False  # Chain broken
    
    return True
```

---

## 6. Signature Generation & Verification

### 6.1 Signing (AISS-1.0)

```python
def sign_event(private_key, event):
    # 1. Remove signature field (if exists)
    unsigned = {k: v for k, v in event.items() if k != 'signature'}
    
    # 2. Canonicalize
    canonical = canonicalize_json(unsigned)
    
    # 3. Sign with Ed25519
    signature = ed25519.sign(private_key, canonical)
    
    # 4. Encode base64
    event["signature"] = "base64:" + base64.b64encode(signature).decode()
    
    return event
```

### 6.2 Verification (AISS-1.0)

```python
def verify_event(public_key, event):
    # 1. Extract signature
    signature_b64 = event["signature"].removeprefix("base64:")
    signature = base64.b64decode(signature_b64)
    
    # 2. Remove signature from event
    unsigned = {k: v for k, v in event.items() if k != 'signature'}
    
    # 3. Canonicalize
    canonical = canonicalize_json(unsigned)
    
    # 4. Verify with Ed25519
    try:
        ed25519.verify(public_key, canonical, signature)
        return True
    except:
        return False
```

### 6.3 Hybrid Signing (AISS-2.0)

```python
def sign_event_hybrid(ed25519_key, dilithium_key, event):
    # Remove signatures
    unsigned = {k: v for k, v in event.items() if k != 'signatures'}
    canonical = canonicalize_json(unsigned)
    
    # Sign with both algorithms
    ed25519_sig = ed25519.sign(ed25519_key, canonical)
    dilithium_sig = dilithium.sign(dilithium_key, canonical)
    
    event["signatures"] = {
        "classical": {
            "algorithm": "Ed25519",
            "signature": "base64:" + base64.b64encode(ed25519_sig).decode()
        },
        "post_quantum": {
            "algorithm": "ML-DSA-65",
            "signature": "base64:" + base64.b64encode(dilithium_sig).decode()
        }
    }
    
    return event
```

---

## 7. Fork Detection

### 7.1 Fork Definition

A **fork** occurs when an agent creates two events with the same `previous_hash`:

```
         Event 2A
        /
Event 1 
        \
         Event 2B
```

Both Event 2A and 2B reference Event 1 → **fork detected**.

### 7.2 Detection Algorithm

```python
def detect_forks(events):
    previous_hashes = {}
    forks = []
    
    for event in events:
        prev_hash = event["previous_hash"]
        
        if prev_hash in previous_hashes:
            # Fork detected
            fork = {
                "fork_point": prev_hash,
                "branches": [previous_hashes[prev_hash], event]
            }
            forks.append(fork)
        else:
            previous_hashes[prev_hash] = event
    
    return forks
```

### 7.3 Fork Resolution (Canonical History Rule)

When multiple branches exist, select ONE canonical chain:

**Step 1:** Count events with external timestamps (TSA RFC 3161)
- Branch with most TSA-stamped events wins

**Step 2:** If tie, select branch with earliest TSA timestamp

**Step 3:** If tie, select longest branch (most events)

**Step 4:** If still tie, lexicographically lowest chain hash

**Property:** Deterministic (all verifiers select same chain)

---

## 8. Nonce Management

### 8.1 Purpose

Nonces prevent replay attacks:
- Attacker cannot re-submit old event
- Each nonce used exactly once

### 8.2 Format

**Requirement:** UUID v4 (RFC 4122)

```python
import uuid
nonce = str(uuid.uuid4())  # "550e8400-e29b-41d4-a716-446655440000"
```

### 8.3 Verification

Implementations SHOULD maintain a nonce registry:

```python
used_nonces = set()

def verify_nonce(nonce):
    if nonce in used_nonces:
        raise ReplayAttackError("Nonce already used")
    
    used_nonces.add(nonce)
```

---

## 9. Timestamp Requirements

### 9.1 Local Timestamp

**Field:** `timestamp` (integer, Unix UTC seconds)

```python
import time
timestamp = int(time.time())  # 1739395200
```

### 9.2 External Timestamp (Optional)

For legal compliance, events MAY include RFC 3161 timestamp:

```json
{
  "version": "AISS-1.0",
  ...
  "trusted_timestamp": {
    "status": "verified",
    "authority": "freetsa.org",
    "timestamp": 1739395201,
    "rfc3161_token": "base64:..."
  }
}
```

**Benefits:**
- Independent time proof
- Anti-backdating
- Legal standing

---

## 10. Security Considerations

### 10.1 Private Key Protection

- MUST be stored with 0600 permissions (Unix)
- SHOULD be encrypted at rest
- MUST NOT be transmitted over network
- SHOULD be backed up securely (encrypted)

### 10.2 Quantum Resistance

- Ed25519 vulnerable to Shor's algorithm (quantum computers)
- Migrate to AISS-2.0 (Dilithium3) before quantum threat
- Timeline: NIST recommends migration by 2030

### 10.3 Hash Collision

- SHA-256 collision resistance: 2^128
- Estimated safe until 2040+ (current computing)
- Monitor NIST recommendations

### 10.4 Replay Protection

- Nonce MUST be unique per event
- Implementations SHOULD track used nonces
- Network-wide nonce registry recommended (future)

---

## 11. Compliance & Legal

### 11.1 Standards Conformance

AISS builds on:
- **RFC 8032** (Ed25519)
- **RFC 8785** (Canonical JSON)
- **RFC 3161** (Time-Stamp Protocol)
- **NIST FIPS 204** (ML-DSA / Dilithium)

### 11.2 Regulatory Frameworks

AISS helps meet requirements for:
- SOC2 Type 2 (audit controls)
- ISO 27001 (event logging)
- HIPAA (audit trail, encryption)
- GDPR (transparency, integrity)
- SEC/FINRA (trading audit trail)
- NIST PQC (post-quantum readiness)

---

## 12. Implementation Guidance

### 12.1 Reference Implementation

**PiQrypt** (Python): https://github.com/piqrypt/piqrypt

### 12.2 Minimum Viable Implementation

A conformant AISS-1.0 implementation MUST:
1. Generate Ed25519 keypairs
2. Derive agent IDs (base58 + SHA-256)
3. Serialize events using RFC 8785
4. Sign events with Ed25519
5. Verify signatures
6. Maintain hash chains
7. Detect forks

### 12.3 Test Vectors

See: `vectors/` directory

---

## 13. Versioning

### 13.1 Version History

- **AISS-1.0** (2026-02): Classical Ed25519
- **AISS-1.1** (2026-02): Adds fork resolution, nonce management
- **AISS-2.0** (2026-02): Post-quantum hybrid signatures

### 13.2 Backward Compatibility

- AISS-2.0 implementations MUST support AISS-1.0 events
- Forward compatibility NOT guaranteed

---

## 14. References

- [RFC 8032] Ed25519 Digital Signature Algorithm
- [RFC 8785] JSON Canonicalization Scheme
- [RFC 3161] Time-Stamp Protocol
- [NIST FIPS 204] Module-Lattice-Based Digital Signature Standard
- [RFC 4122] UUID Version 4

---

## 15. Contributors

- PiQrypt Inc.
- Community contributors welcome

**Contact:** piqrypt@gmail.com  
**Repository:** https://github.com/piqrypt/aiss-spec

---

## License

MIT License

Copyright (c) 2026 PiQrypt Inc.  
e-Soleau: DSO2026006483 (INPI, 19/02/2026)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
