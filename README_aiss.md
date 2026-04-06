# AISS — Agent Identity and Signature Standard

Cryptographic trust primitive for autonomous AI agents.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/aiss)](https://pypi.org/project/aiss/)
[![Python](https://img.shields.io/badge/python-3.9+-blue)](https://www.python.org/)
[![NIST FIPS 204](https://img.shields.io/badge/NIST%20FIPS%20204-ML--DSA--65-purple)](https://csrc.nist.gov/pubs/fips/204/final)
[![RFC 8785](https://img.shields.io/badge/RFC%208785-JCS-green)](https://datatracker.ietf.org/doc/html/rfc8785)

---

## Quickstart

```python
from aiss import AgentIdentity

agent = AgentIdentity.create()
event = agent.stamp("user_prompted", {"data": "hello"})
assert agent.verify(event)
print(event["hash"])   # tamper-evident proof
```

```json
{
  "agent_id":   "3gFw2S1NT6dzo9vTPQ6JNWEwYFysZn8F",
  "event_type": "user_prompted",
  "payload":    { "data": "hello" },
  "signature":  "eA3oT793bV/hJnDX...",
  "hash":       "8b1cfab333041b26...",
  "timestamp":  1771845244
}
```

```bash
pip install aiss
```

---

## Why AISS

AISS makes agent actions:

- **verifiable** — cryptographic proof of authorship
- **portable** — no infrastructure dependency
- **tamper-evident** — hash-chained, any modification is detectable
- **post-quantum ready** — Ed25519 + ML-DSA-65 hybrid (NIST FIPS 204)

---

## Core concepts

| Primitive | Description | RFC |
|---|---|---|
| **Identity** | Deterministic agent ID derived from public key | §5–6 |
| **Event chain** | Signed, hash-linked, append-only history | §7–9 |
| **Fork resolution** | Deterministic canonical chain selection | §10 |
| **A2A trust** | Agent-to-agent handshake and co-signed events | §16 |

---

## Profiles

| Profile | Cryptography | Use case |
|---|---|---|
| **AISS-1** | Ed25519 · SHA-256 · RFC 8785 | General interoperability |
| **AISS-2** | Ed25519 + ML-DSA-65 hybrid | Regulated environments · forward secrecy |

---

## Low-level API

Full control over keys, events, chain, memory, and exports.

```python
from aiss import generate_keypair, derive_agent_id, stamp_event, verify_event
from aiss.memory import store_event, search_events
from aiss.exports import export_audit_chain

priv, pub  = generate_keypair()
agent_id   = derive_agent_id(pub)
event      = stamp_event(priv, agent_id, {"event_type": "action"})
verify_event(event, pub)
```

See [docs/API.md](docs/API.md) for the full reference.

---

## PCP stack

```
AISS      — identity · event chain · fork resolution · A2A   ← this package
```

Foundation layer for verifiable agent systems.

AISS defines the standard.
Additional features may be available in specific implementations.

Reference implementation: [PiQrypt](https://github.com/piqrypt/piqrypt) (Python)

---

## Compliance (indicative)

| Framework | Control | AISS mechanism |
|---|---|---|
| EU AI Act Art. 12 | Inviolable logging | Hash-chained signed events |
| SOC 2 CC6.6 | Audit trail | AISS-1.0-AUDIT export |
| NIST AI RMF MEASURE 2.5 | Traceability | Tamper-evident event history |
| GDPR Art. 5.1.f | Integrity | Fork detection + signatures |
| HIPAA §164.312 | Audit controls | Immutable event chain |

AISS provides the cryptographic mechanisms. Compliance depends on implementation.
Non-normative mapping.

---

## Tooling

**Vigil** — optional local monitoring interface.

```bash
aiss start    # → http://localhost:8421
```

Provides a local dashboard for agent activity, chain health, and VRS scoring.

---

## Implementations

**Reference:** [PiQrypt](https://github.com/piqrypt/piqrypt) (Python)

**Community:** open — submit a PR to list yours.
Requirements: pass all normative test vectors in `vectors/`, conform to SPEC.md.

---

## Spec

- [RFC v2.0](docs/RFC_AISS_v2.0.md) — full protocol specification
- [CONFORMANCE.md](CONFORMANCE.md) — implementation matrix
- [aiss-standard.org](https://aiss-standard.org) — landing page & playground
- [GitHub](https://github.com/piqrypt/aiss-standard)

---

## Contributing

Contributions welcome — spec improvements, test vectors, bug reports.
See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT — see [LICENSE](LICENSE).

## IP Notice

Protocol concepts deposited via e-Soleau (INPI France):
DSO2026006483 — 19 Feb 2026 · DSO2026009143 — 12 Mar 2026
