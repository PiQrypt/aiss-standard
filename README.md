# AISS — Agent Identity & Signature Standard

AISS defines the structural identity model for autonomous agents.

The Proof of Continuity Protocol (PCP) is the embedded enforcement mechanism
that guarantees identity persistence through deterministic continuity validation.

**Open standard for cryptographic audit trails of autonomous AI agents.**

[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.1-green)](SPEC.md)
[![Status](https://img.shields.io/badge/status-draft-yellow)](SPEC.md)

---

## 🎯 What is AISS?

AISS defines a **cryptographic protocol** for creating tamper-proof audit trails of AI agent decisions.

**Problem:** Agents make critical decisions (trading, medical, autonomous driving) but:
- Logs can be modified
- No proof of authorship
- Vulnerable to quantum attacks

**Solution:** AISS provides:
- ✅ Cryptographic signatures (Ed25519, Dilithium3)
- ✅ Hash-linked event chains (tamper-proof)
- ✅ Fork detection & resolution
- ✅ Post-quantum security (NIST FIPS 204)

PCP (Proof of Continuity Protocol) implements the continuity enforcement rules defined by AISS.
It ensures canonical history selection, fork determinism, and replay protection across distributed agents.

---

## 📚 Specification

**Main document:** [SPEC.md](SPEC.md)

**Contents:**
1. Agent Identity (Ed25519, Dilithium3)
2. Event Structure (AISS-1.0, AISS-2.0)
3. Canonical JSON (RFC 8785)
4. Hash Chains (SHA-256)
5. Signature Generation & Verification
6. Fork Detection & Resolution
7. Nonce Management (anti-replay)
8. Timestamp Requirements (RFC 3161)
9. Security Considerations
10. Implementation Guidance

---

## 🔧 Implementation

### Reference Implementation

**PiQrypt** (Python): https://github.com/piqrypt/piqrypt

```bash
pip install piqrypt
```

### Minimal Example

```python
import aiss

# Generate identity
private_key, public_key = aiss.generate_keypair()
agent_id = aiss.derive_agent_id(public_key)

# Sign event
event = aiss.stamp_event(
    private_key,
    agent_id,
    payload={"action": "decision", "confidence": 0.95}
)

# Verify
is_valid = aiss.verify_event(public_key, event)
```

---

## 📋 Compliance

AISS helps meet requirements for:
- **SOC2 Type 2** (audit controls)
- **ISO 27001** (event logging)
- **HIPAA** (audit trail, encryption)
- **GDPR** (transparency, integrity)
- **SEC/FINRA** (trading audit)
- **NIST PQC** (post-quantum readiness)

---

## 📂 Repository Structure

```
aiss-spec/
├── SPEC.md                  # Main specification
├── schemas/
│   ├── aiss-1.0.json        # JSON schema (classical)
│   ├── aiss-2.0.json        # JSON schema (post-quantum)
│   ├── aiss1_event.schema.json
│   └── aiss1_identity.schema.json
├── examples/
│   ├── event-simple.json
│   ├── event-chain.json
│   └── event-hybrid-pq.json
├── vectors/
│   ├── ed25519-test.json
│   └── dilithium-test.json
├── README.md
└── LICENSE
```

---

## 🚀 Quick Start

### 1. Read the Spec

Start with [SPEC.md](SPEC.md) — covers all protocol details.

### 2. Explore Examples

See `examples/` for:
- Simple events
- Event chains
- Hybrid post-quantum signatures

### 3. Implement

Use test vectors in `vectors/` to validate your implementation.

### 4. Contribute

Open an issue or PR if you:
- Find a bug in the spec
- Want to propose an improvement
- Have implementation feedback

---

## 🔒 Security

### Cryptographic Algorithms

| Version | Classical | Post-Quantum | Security |
|---------|-----------|--------------|----------|
| **AISS-1.0** | Ed25519 (RFC 8032) | - | 128-bit |
| **AISS-2.0** | Ed25519 | ML-DSA-65 (NIST FIPS 204) | 256-bit PQ |

### Quantum Timeline

- **2026-2030:** AISS-1.0 safe (Ed25519)
- **2030+:** Migrate to AISS-2.0 (Dilithium3)
- **2035+:** Ed25519 considered obsolete

**Recommendation:** Start with AISS-1.0, plan AISS-2.0 migration.

---

## 🤝 Implementations

**Official:**
- **PiQrypt** (Python): https://github.com/piqrypt/piqrypt

**Community:**
- Add yours! Submit a PR to list your implementation.

**Requirements:**
- Conformant to SPEC.md
- Pass test vectors
- Open-source (any license)

---

## 📖 Use Cases

### Trading Bots
```python
# Every trade decision = signed event
event = aiss.stamp_event(priv_key, agent_id, {
    "event_type": "trade_executed",
    "symbol": "AAPL",
    "action": "buy",
    "quantity": 100
})
# → SEC/FINRA audit trail
```

### Healthcare AI
```python
# Medical diagnosis = signed event
event = aiss.stamp_event(priv_key, agent_id, {
    "event_type": "diagnosis",
    "condition": "pneumonia",
    "confidence": 0.94,
    "patient_id_hash": "sha256:..."  # HIPAA compliant
})
# → HIPAA audit trail
```

### Autonomous Vehicles
```python
# Driving decision = signed event
event = aiss.stamp_event(priv_key, agent_id, {
    "event_type": "driving_decision",
    "action": "brake",
    "speed_kmh": 60,
    "obstacle_detected": true
})
# → Black box for accidents
```

---

## 📝 Versioning

- **v1.0** (2026-02): Initial release (Ed25519, hash chains)
- **v1.1** (2026-02): Fork resolution, nonce management
- **v2.0** (2026-02): Post-quantum hybrid signatures

**Backward compatibility:** AISS-2.0 implementations MUST support AISS-1.0 events.

---

## 🌐 Community

- **Discussions:** [GitHub Discussions](https://github.com/piqrypt/aiss-spec/discussions)
- **Issues:** [GitHub Issues](https://github.com/piqrypt/aiss-spec/issues)
- **Email:** piqrypt@gmail.com

---

## 📄 License

MIT License — see [LICENSE](LICENSE)

**e-Soleau:** DSO2026006483 (INPI, 19/02/2026)

---

## 🏆 Citation

If you use AISS in research or production, please cite:

```bibtex
@techreport{aiss2026,
  title = {AISS: Agent Identity \& Signature Standard},
  author = {PiQrypt Inc.},
  year = {2026},
  version = {1.1},
  url = {https://github.com/piqrypt/aiss-spec},
  note = {e-Soleau: DSO2026006483}
}
```

---

**Making AI Agents Accountable** ✨
