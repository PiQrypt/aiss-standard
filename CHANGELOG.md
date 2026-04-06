# Changelog — AISS

All notable changes to the AISS package are documented here.  
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

---

## [2.0.0] — 2026-04

### Overview

AISS v2.0.0 is the first release of the AISS package as a **standalone standard**.

Previously, the AISS implementation was bundled inside `pip install piqrypt`.
It is now published independently as `pip install aiss` — MIT licensed,
no quotas, no accounts, no telemetry.

PiQrypt remains the full-stack reference implementation (Vigil Pro, TrustGate,
Bridges, Doorkeeper, certified exports).

### Added

**Identity**
- `create_agent_identity` — persistent identity with encrypted key option
- `load_agent_identity` — reload identity from disk
- `list_agent_identities` — enumerate local identities
- `secure_agent_key` — optional key encryption at rest
- Key rotation with full chain continuity (`create_rotation_attestation`, `create_rotation_pcp_event`)

**Cryptography**
- AISS-1 profile: Ed25519 + SHA-256, RFC 8785 canonicalization
- AISS-2 profile: Ed25519 + ML-DSA-65 hybrid (NIST FIPS 204)
- Post-quantum support via optional extra: `pip install aiss[post-quantum]`

**Event chain**
- `stamp_event`, `stamp_genesis_event` — Ed25519 signed events
- `verify_event`, `verify_chain`, `verify_signature`
- `compute_event_hash`, `compute_chain_hash`, `append_event`
- Fork detection + deterministic canonical resolution
- Anti-replay protection (UUID v4 nonces)

**Authority binding**
- Delegation chains (`build_authority_chain`)
- Revocation support
- Event annotation with accountable authority

**Memory**
- `store_event`, `load_events` — local plain JSON storage
- `search_events` — query by agent_id, event_type, session_id, time range, follow_rotation
- `MemoryIndex` — fast indexed lookup by hash, nonce, agent, type
- `get_memory_stats`

**Exports**
- `export_audit_chain` — AISS-1.0-AUDIT format with `chain_integrity_hash`
- `export_audit_chain_to_file` — write to disk
- `validate_audit_export` — integrity check
- `export_subset`, `export_by_timerange` — selective exports
- JSON schemas: `aiss-1.0.json`, `aiss-2.0.json`, `audit.schema.json`

**A2A Protocol**
- Full Agent-to-Agent handshake (`perform_handshake`)
- Co-signed events (`build_cosigned_handshake_event`)
- External peer observation (`record_external_interaction`)
- Peer registry (`register_peer`, `list_peers`, `update_peer_trust_score`)

**Agent context**
- `get_system_prompt` — inject AISS identity into LLM system prompt
- `build_agent_context` — structured context for any agent framework

**Vigil (standard)**
- Local HTTP dashboard on port 8421
- VRS (Verifiable Risk Score) — 7-day history
- CRITICAL alerts
- Up to 2 bridge types
- Chain health monitoring
- Footer: "Powered by PiQrypt"

### Removed from this package (available in `pip install piqrypt`)

- License system, tiers, quotas
- Telemetry, badges
- Memory encryption (AES-256-GCM, KeyStore)
- RFC 3161 trusted timestamps
- Portable archives (.pqz)
- Certified exports (PiQrypt CA)
- TSI Engine, A2C Detector, VRS extended
- Vigil Pro (unlimited VRS, all alerts, unlimited bridges)
- TrustGate
- Framework bridges (LangChain, CrewAI, AutoGen, MCP, Ollama, ROS2, RPi, Session, OpenClaw)
- Doorkeeper state machine

### IP Notice

Protocol concepts deposited via e-Soleau (INPI France):
- DSO2026006483 — 19 February 2026
- DSO2026009143 — 12 March 2026

---

## Previous history

Before v2.0.0, AISS was developed and shipped as part of PiQrypt.  
See https://github.com/piqrypt/piqrypt/blob/main/CHANGELOG.md for full history.
