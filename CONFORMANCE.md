# AISS Conformance

Implementation conformance matrix for the Agent Identity and Signature Standard v2.0.

---

## Conformance Levels

| Level | Description | Requirements |
|---|---|---|
| **Level 1 — Basic** | Minimal conformant implementation | Ed25519, SHA-256, RFC 8785, all Level 1 test vectors, fork detection |
| **Level 2 — Production** | Production-ready implementation | Level 1 + key rotation, key encryption at rest, key zeroization, CLI or equivalent |
| **Level 3 — Regulated** | AISS-2 regulated environments | Level 2 + ML-DSA-65 hybrid, RFC 3161 timestamps, HSM support, compliance documentation |

---

## Test Vectors

All AISS implementations MUST pass the normative test vectors.

### Available (v2.0.0)

| File | Description | Vectors | Level |
|---|---|---|---|
| `test_vectors/canonical.json` | RFC 8785 JSON Canonicalization | 5 | 1 |
| `test_vectors/identity.json` | Agent ID derivation determinism | 8 | 1 |
| `test_vectors/events.json` | Event hashing and structure | 3 | 1 |
| `test_vectors/fork.json` | Fork detection and resolution | 6 | 1 |
| `test_vectors/replay.json` | Anti-replay nonce protection | 5 | 1 |

### Planned (v2.1)

| File | Description | Status |
|---|---|---|
| `test_vectors/chain.json` | Full hash chain verification | planned |
| `test_vectors/rotation.json` | Key rotation and continuity | planned |
| `test_vectors/a2a.json` | A2A handshake verification | planned |
| `test_vectors/external.json` | External peer observation | planned |

---

## Running the test suite

```bash
pip install aiss[dev]
pytest tests/test_vectors.py -v
```

All Level 1 vectors must pass for a conformant AISS-1 implementation.

---

## Reference Implementation

| Implementation | Language | Level | Tests | Repository |
|---|---|---|---|---|
| **PiQrypt** | Python | Level 2 | 501 passing | [github.com/piqrypt/piqrypt](https://github.com/piqrypt/piqrypt) |

---

## Community Implementations

Open — submit a PR to list your implementation.

**Requirements to be listed:**
- Pass all normative test vectors in `test_vectors/`
- Conform to `docs/RFC_AISS_v2.0.md`
- Open source (any license)
- Provide a link to your repository

---

## Minimum Viable Implementation (Level 1)

A conformant AISS-1 implementation MUST:

1. Generate Ed25519 keypairs (RFC 8032)
2. Derive agent IDs: `BASE58(SHA256(public_key_bytes))[0:32]`
3. Serialize events using RFC 8785 (JSON Canonicalization Scheme)
4. Sign events with Ed25519
5. Verify signatures
6. Maintain SHA-256 hash chains
7. Detect forks (two events with the same `previous_hash`)
8. Implement UUID v4 nonce anti-replay

A conformant AISS-1 implementation MUST NOT:
- Use a different canonicalization scheme
- Truncate agent IDs to fewer than 32 characters
- Omit the `previous_hash` field (use SHA256 of public key for genesis)
- Accept events with duplicate nonces

---

## AISS-2 Requirements (Level 3)

In addition to Level 1:

- Hybrid signatures: Ed25519 + ML-DSA-65 (NIST FIPS 204)
- AISS-2 events use `signatures.classical` + `signatures.post_quantum`
- AISS-2 implementations MUST verify both signatures
- AISS-2 implementations MUST accept AISS-1 events
- Forward compatibility: AISS-1 implementations MAY ignore AISS-2 fields

---

## Spec Reference

Full protocol specification: [docs/RFC_AISS_v2.0.md](docs/RFC_AISS_v2.0.md)
