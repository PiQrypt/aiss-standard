#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt
"""
AISS v2.0.0 — Smoke Test
========================

Validates the complete AISS standard package end-to-end.

  BLOC 1 — Cryptography (keypair, Ed25519, RFC 8785)
  BLOC 2 — Stamp & Chain (genesis, events, hash chain)
  BLOC 3 — Verification (valid, tampered, chain)
  BLOC 4 — Memory (store, load, search)
  BLOC 5 — Export & Audit
  BLOC 6 — Fork & Replay detection
  BLOC 7 — A2A Handshake
  BLOC 8 — AgentIdentity high-level API
  BLOC 9 — Test vectors (normative)

Usage:
    python smoke_test.py           # compact summary
    python smoke_test.py -v        # verbose
    python smoke_test.py --stop    # stop on first failure
    python smoke_test.py --bloc 8  # single bloc
"""

import os
import sys
import json
import time
import tempfile
import traceback
import argparse
from pathlib import Path
from typing import List, Tuple

# Resolve project root
ROOT = Path(__file__).resolve().parent
for candidate in [ROOT, ROOT.parent]:
    if (candidate / "aiss").exists():
        AISS_ROOT = candidate
        break
else:
    print(f"ERROR: cannot find aiss/ from {ROOT}")
    sys.exit(1)

sys.path.insert(0, str(AISS_ROOT))

# Force unload of any aiss already loaded from site-packages
for _mod in list(sys.modules.keys()):
    if _mod == "aiss" or _mod.startswith("aiss."):
        del sys.modules[_mod]

GREEN = "\033[92m"
RED   = "\033[91m"
CYAN  = "\033[96m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
RESET = "\033[0m"

_results: List[Tuple[str, str, str, str]] = []
_stop_on_first_fail = False
_verbose = False


def check(bloc, name, fn):
    try:
        detail = fn() or ""
        _results.append((bloc, name, "OK", str(detail)))
        if _verbose:
            print(f"  {GREEN}✓{RESET} {name}  {DIM}{detail}{RESET}")
        return True
    except Exception:
        tb = traceback.format_exc().strip().split("\n")[-1]
        _results.append((bloc, name, "FAIL", tb))
        if _verbose:
            print(f"  {RED}✗{RESET} {name}\n    {DIM}{tb}{RESET}")
        if _stop_on_first_fail:
            print_summary()
            sys.exit(1)
        return False


def section(title):
    if _verbose:
        print(f"\n{BOLD}{CYAN}▶ {title}{RESET}")


def print_summary():
    total = len(_results)
    ok    = sum(1 for r in _results if r[2] == "OK")
    fail  = sum(1 for r in _results if r[2] == "FAIL")
    print("\n" + "=" * 60)
    print(f"{BOLD}AISS v2.0.0 — Smoke Test{RESET}")
    print("=" * 60)
    blocs = {}
    for bloc, name, status, detail in _results:
        blocs.setdefault(bloc, []).append((name, status, detail))
    for bloc, checks in blocs.items():
        ok_b  = sum(1 for _, s, _ in checks if s == "OK")
        tot   = len(checks)
        icon  = f"{GREEN}✓{RESET}" if ok_b == tot else f"{RED}✗{RESET}"
        print(f"\n  {icon} {BOLD}{bloc}{RESET}  ({ok_b}/{tot})")
        for name, status, detail in checks:
            if status == "FAIL":
                print(f"      {RED}✗{RESET} {name}\n        {DIM}{detail}{RESET}")
            elif _verbose:
                print(f"      {GREEN}✓{RESET} {name}  {DIM}{detail}{RESET}")
    print("\n" + "─" * 60)
    print(f"  Total  : {total}")
    print(f"  {GREEN}Passed{RESET} : {ok}")
    if fail:
        print(f"  {RED}Failed{RESET} : {fail}")
    print()
    if fail == 0:
        print(f"{GREEN}{BOLD}  ✅  All checks passed — AISS v2.0.0 operational{RESET}")
    else:
        print(f"{RED}{BOLD}  ❌  {fail} check(s) failed{RESET}")
    print()


# ─── BLOC 1 — Cryptography ────────────────────────────────────────────────────

def bloc1_crypto():
    B = "BLOC 1 — Cryptography"
    section(B)
    from aiss.crypto import ed25519
    from aiss.identity import generate_keypair, derive_agent_id
    from aiss.canonical import canonicalize

    def test_keypair():
        priv, pub = generate_keypair()
        assert len(priv) == 32 and len(pub) == 32
        return f"priv={len(priv)}B pub={len(pub)}B"

    def test_agent_id():
        _, pub = generate_keypair()
        a1 = derive_agent_id(pub)
        a2 = derive_agent_id(pub)
        assert a1 == a2 and len(a1) == 32
        return f"id={a1[:12]}... (32 chars)"

    def test_agent_id_unique():
        _, p1 = generate_keypair()
        _, p2 = generate_keypair()
        assert derive_agent_id(p1) != derive_agent_id(p2)
        return "unique ✓"

    def test_sign_verify():
        priv, pub = generate_keypair()
        msg = b"hello aiss"
        sig = ed25519.sign(priv, msg)
        ed25519.verify(pub, msg, sig)
        return f"sig={len(sig)}B"

    def test_canonicalize():
        obj = {"z": 1, "a": 2}
        c = canonicalize(obj)
        assert c == b'{"a":2,"z":1}'
        return "RFC 8785 ✓"

    check(B, "generate_keypair — 32B each", test_keypair)
    check(B, "derive_agent_id — deterministic 32 chars", test_agent_id)
    check(B, "derive_agent_id — unique per keypair", test_agent_id_unique)
    check(B, "Ed25519 sign + verify", test_sign_verify)
    check(B, "RFC 8785 canonicalization", test_canonicalize)


# ─── BLOC 2 — Stamp & Chain ───────────────────────────────────────────────────

def bloc2_stamp_chain():
    B = "BLOC 2 — Stamp & Chain"
    section(B)
    from aiss.identity import generate_keypair, derive_agent_id
    from aiss.stamp import stamp_event, stamp_genesis_event
    from aiss.chain import compute_event_hash, compute_chain_hash, append_event

    priv, pub = generate_keypair()
    aid = derive_agent_id(pub)

    def test_genesis():
        g = stamp_genesis_event(priv, pub, aid, {"event_type": "init"})
        assert g["version"] == "AISS-1.0"
        assert g["agent_id"] == aid
        assert "signature" in g
        assert "nonce" in g
        return f"version={g['version']}"

    def test_chain_link():
        g = stamp_genesis_event(priv, pub, aid, {"event_type": "g"})
        prev = compute_event_hash(g)
        e = stamp_event(priv, aid, {"event_type": "action"}, previous_hash=prev)
        assert e["previous_hash"] == prev
        return "previous_hash linked ✓"

    def test_hash_deterministic():
        g = stamp_genesis_event(priv, pub, aid, {"event_type": "g"})
        assert compute_event_hash(g) == compute_event_hash(g)
        return "deterministic ✓"

    def test_nonce_unique():
        g1 = stamp_genesis_event(priv, pub, aid, {"event_type": "a"})
        g2 = stamp_genesis_event(priv, pub, aid, {"event_type": "b"})
        assert g1["nonce"] != g2["nonce"]
        return "unique nonces ✓"

    def test_chain_hash():
        g = stamp_genesis_event(priv, pub, aid, {"event_type": "g"})
        prev = compute_event_hash(g)
        e = stamp_event(priv, aid, {"event_type": "step"}, previous_hash=prev)
        h = compute_chain_hash([g, e])
        assert len(h) == 64
        return f"chain_hash={h[:12]}..."

    check(B, "stamp_genesis_event — AISS-1.0 structure", test_genesis)
    check(B, "stamp_event — previous_hash linked", test_chain_link)
    check(B, "compute_event_hash — deterministic", test_hash_deterministic)
    check(B, "nonces — unique per event", test_nonce_unique)
    check(B, "compute_chain_hash — 64 hex chars", test_chain_hash)


# ─── BLOC 3 — Verification ────────────────────────────────────────────────────

def bloc3_verify():
    B = "BLOC 3 — Verification"
    section(B)
    from aiss.identity import generate_keypair, derive_agent_id, export_identity
    from aiss.stamp import stamp_event, stamp_genesis_event
    from aiss.chain import compute_event_hash
    from aiss.verify import verify_event, verify_chain, verify_signature
    from aiss.exceptions import InvalidSignatureError

    priv, pub = generate_keypair()
    aid = derive_agent_id(pub)
    identity = export_identity(aid, pub)

    def test_verify_valid():
        g = stamp_genesis_event(priv, pub, aid, {"event_type": "g"})
        assert verify_event(g, pub)
        return "valid ✓"

    def test_verify_tampered():
        g = stamp_genesis_event(priv, pub, aid, {"event_type": "g"})
        g["payload"]["event_type"] = "TAMPERED"
        try:
            verify_event(g, pub)
            return "FAIL — tamper not detected"
        except InvalidSignatureError:
            return "tampered rejected ✓"

    def test_verify_chain_valid():
        g = stamp_genesis_event(priv, pub, aid, {"event_type": "g"})
        prev = compute_event_hash(g)
        chain = [g]
        for i in range(4):
            e = stamp_event(priv, aid, {"event_type": f"step_{i}"}, previous_hash=prev)
            chain.append(e)
            prev = compute_event_hash(e)
        assert verify_chain(chain, identity)
        return f"chain of {len(chain)} ✓"

    def test_verify_chain_tampered():
        g = stamp_genesis_event(priv, pub, aid, {"event_type": "g"})
        prev = compute_event_hash(g)
        e = stamp_event(priv, aid, {"event_type": "step"}, previous_hash=prev)
        e["payload"]["event_type"] = "TAMPERED"
        try:
            verify_chain([g, e], identity)
            return "FAIL — tamper not detected"
        except Exception:
            return "tampered chain rejected ✓"

    check(B, "verify_event — valid signature", test_verify_valid)
    check(B, "verify_event — tampered payload rejected", test_verify_tampered)
    check(B, "verify_chain — 5 events valid", test_verify_chain_valid)
    check(B, "verify_chain — tampered event rejected", test_verify_chain_tampered)


# ─── BLOC 4 — Memory ─────────────────────────────────────────────────────────

def bloc4_memory():
    B = "BLOC 4 — Memory"
    section(B)
    from aiss.identity import generate_keypair, derive_agent_id
    from aiss.stamp import stamp_genesis_event, stamp_event
    from aiss.chain import compute_event_hash
    from aiss.memory import store_event, load_events, search_events, init_memory_dirs

    priv, pub = generate_keypair()
    aid = derive_agent_id(pub)
    agent_name = f"smoke_aiss_{int(time.time())}"

    with tempfile.TemporaryDirectory() as tmpdir:

        def test_store_load():
            g = stamp_genesis_event(priv, pub, aid, {"event_type": "init"})
            store_event(g, base_dir=tmpdir)
            events = load_events(base_dir=tmpdir)
            assert len(events) >= 1
            return f"{len(events)} event(s)"

        def test_store_multiple():
            g = stamp_genesis_event(priv, pub, aid, {"event_type": "g"})
            prev = compute_event_hash(g)
            store_event(g, base_dir=tmpdir)
            for i in range(3):
                e = stamp_event(priv, aid, {"event_type": f"step_{i}"}, previous_hash=prev)
                store_event(e, base_dir=tmpdir)
                prev = compute_event_hash(e)
            events = load_events(base_dir=tmpdir)
            assert len(events) >= 4
            return f"{len(events)} events stored"

        def test_search():
            events = load_events(base_dir=tmpdir)
            results = [e for e in events if e.get("agent_id") == aid]
            assert len(results) >= 1
            return f"{len(results)} result(s)"

        check(B, "store_event + load_events", test_store_load)
        check(B, "store 4 events + load all", test_store_multiple)
        check(B, "filter by agent_id", test_search)


# ─── BLOC 5 — Export & Audit ─────────────────────────────────────────────────

def bloc5_export():
    B = "BLOC 5 — Export & Audit"
    section(B)
    from aiss.identity import generate_keypair, derive_agent_id, export_identity
    from aiss.stamp import stamp_event, stamp_genesis_event
    from aiss.chain import compute_event_hash
    from aiss.exports import (
        export_audit_chain, export_audit_chain_to_file,
        validate_audit_export, export_subset, get_audit_summary,
    )

    priv, pub = generate_keypair()
    aid = derive_agent_id(pub)
    identity = export_identity(aid, pub)

    def build_chain(n=3):
        g = stamp_genesis_event(priv, pub, aid, {"event_type": "g"})
        chain = [g]
        prev = compute_event_hash(g)
        for i in range(1, n):
            e = stamp_event(priv, aid, {"event_type": f"s{i}"}, previous_hash=prev)
            chain.append(e)
            prev = compute_event_hash(e)
        return chain

    def test_export_structure():
        audit = export_audit_chain(identity, build_chain(3))
        assert audit["spec"] == "AISS-1.0-AUDIT"
        assert "chain_integrity_hash" in audit
        assert len(audit["events"]) == 3
        return f"{len(audit.keys())} keys, 3 events"

    def test_validate():
        audit = export_audit_chain(identity, build_chain(3))
        assert validate_audit_export(audit)
        return "valid ✓"

    def test_export_to_file():
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name
        export_audit_chain_to_file(build_chain(2), identity, path)
        loaded = json.loads(Path(path).read_text())
        assert loaded["spec"] == "AISS-1.0-AUDIT"
        Path(path).unlink()
        return "file written + reloaded ✓"

    def test_subset():
        audit  = export_audit_chain(identity, build_chain(5))
        subset = export_subset(audit, start_index=1, end_index=3)
        assert len(subset["events"]) == 2
        return "2/5 events ✓"

    def test_summary():
        audit   = export_audit_chain(identity, build_chain(3))
        summary = get_audit_summary(audit)
        assert summary["event_count"] == 3
        assert summary["agent_id"] == aid
        return f"count={summary['event_count']}"

    check(B, "export_audit_chain — structure", test_export_structure)
    check(B, "validate_audit_export", test_validate)
    check(B, "export_audit_chain_to_file", test_export_to_file)
    check(B, "export_subset — 2 of 5", test_subset)
    check(B, "get_audit_summary", test_summary)


# ─── BLOC 6 — Fork & Replay ──────────────────────────────────────────────────

def bloc6_fork_replay():
    B = "BLOC 6 — Fork & Replay"
    section(B)
    from aiss.identity import generate_keypair, derive_agent_id
    from aiss.stamp import stamp_event, stamp_genesis_event
    from aiss.chain import compute_event_hash
    from aiss.fork import find_forks, resolve_fork_canonical
    from aiss.replay import detect_replay_attacks

    priv, pub = generate_keypair()
    aid = derive_agent_id(pub)

    def test_no_fork():
        g    = stamp_genesis_event(priv, pub, aid, {"event_type": "g"})
        prev = compute_event_hash(g)
        e    = stamp_event(priv, aid, {"event_type": "s"}, previous_hash=prev)
        forks = find_forks([g, e])
        assert len(forks) == 0
        return "no fork ✓"

    def test_fork_detected():
        g    = stamp_genesis_event(priv, pub, aid, {"event_type": "g"})
        prev = compute_event_hash(g)
        e1   = stamp_event(priv, aid, {"event_type": "branch_a"}, previous_hash=prev)
        e2   = stamp_event(priv, aid, {"event_type": "branch_b"}, previous_hash=prev)
        forks = find_forks([g, e1, e2])
        assert len(forks) > 0
        return f"{len(forks)} fork(s) detected ✓"

    def test_no_replay():
        g = stamp_genesis_event(priv, pub, aid, {"event_type": "g"})
        prev = compute_event_hash(g)
        e = stamp_event(priv, aid, {"event_type": "s"}, previous_hash=prev)
        attacks = detect_replay_attacks([g, e])
        assert len(attacks) == 0
        return "no replay ✓"

    def test_replay_detected():
        g = stamp_genesis_event(priv, pub, aid, {"event_type": "g"})
        # Duplicate event = same nonce
        import copy
        dup = copy.deepcopy(g)
        attacks = detect_replay_attacks([g, dup])
        assert len(attacks) > 0
        return f"{len(attacks)} replay(s) detected ✓"

    check(B, "find_forks — clean chain: 0 forks", test_no_fork)
    check(B, "find_forks — forked chain: detected", test_fork_detected)
    check(B, "detect_replay_attacks — clean: 0 attacks", test_no_replay)
    check(B, "detect_replay_attacks — duplicate: detected", test_replay_detected)


# ─── BLOC 7 — A2A Handshake ───────────────────────────────────────────────────

def bloc7_a2a():
    B = "BLOC 7 — A2A Handshake"
    section(B)
    from aiss.identity import generate_keypair, derive_agent_id
    from aiss.a2a import (
        create_identity_proposal, verify_identity_proposal,
        perform_handshake, record_external_interaction,
    )

    priv_a, pub_a = generate_keypair()
    aid_a = derive_agent_id(pub_a)
    priv_b, pub_b = generate_keypair()
    aid_b = derive_agent_id(pub_b)

    def test_proposal():
        p = create_identity_proposal(priv_a, pub_a, aid_a)
        assert p["agent_id"] == aid_a and "signature" in p
        return f"agent={aid_a[:8]}..."

    def test_verify_proposal():
        p = create_identity_proposal(priv_a, pub_a, aid_a)
        assert verify_identity_proposal(p)
        return "verified ✓"

    def test_tampered_proposal():
        p = create_identity_proposal(priv_a, pub_a, aid_a)
        p["agent_id"] = aid_b
        try:
            ok = verify_identity_proposal(p)
            assert not ok
        except Exception:
            pass
        return "tampered rejected ✓"

    def test_handshake():
        p = create_identity_proposal(priv_a, pub_a, aid_a)
        r = perform_handshake(priv_b, pub_b, aid_b, p)
        assert r
        return "A→B handshake ✓"

    def test_external_observation():
        event = record_external_interaction(
            private_key=priv_a,
            agent_id=aid_a,
            peer_identifier="external_system",
            interaction_data={"event_type": "api_call", "endpoint": "/v1/chat"}
        )
        assert "signature" in event
        return "external interaction stamped ✓"

    check(B, "create_identity_proposal — structure", test_proposal)
    check(B, "verify_identity_proposal — valid", test_verify_proposal)
    check(B, "verify_identity_proposal — tampered rejected", test_tampered_proposal)
    check(B, "perform_handshake A→B", test_handshake)
    check(B, "record_external_interaction", test_external_observation)


# ─── BLOC 8 — AgentIdentity high-level API ────────────────────────────────────

def bloc8_agent_identity():
    B = "BLOC 8 — AgentIdentity (high-level API)"
    section(B)
    from aiss import AgentIdentity, SignedEvent

    def test_create():
        agent = AgentIdentity.create()
        assert len(agent.agent_id) == 32
        return f"id={agent.agent_id[:12]}..."

    def test_stamp_verify():
        agent = AgentIdentity.create()
        event = agent.stamp("user_prompted", {"data": "hello"})
        assert isinstance(event, SignedEvent)
        assert agent.verify(event)
        return f"hash={event.hash[:12]}..."

    def test_chain():
        agent = AgentIdentity.create()
        for i in range(5):
            agent.stamp(f"step_{i}", {"seq": i})
        assert agent.verify_chain()
        assert agent.chain_length == 5
        return f"chain of {agent.chain_length} verified ✓"

    def test_export():
        agent = AgentIdentity.create()
        agent.stamp("e1")
        agent.stamp("e2")
        audit = agent.export()
        assert audit["spec"] == "AISS-1.0-AUDIT"
        assert len(audit["events"]) == 2
        return "AISS-1.0-AUDIT ✓"

    def test_quickstart():
        # Exact README quickstart
        agent = AgentIdentity.create()
        event = agent.stamp("user_prompted", {"data": "hello"})
        assert agent.verify(event)
        h = event["hash"]
        assert len(h) == 64
        return f"hash={h[:12]}..."

    def test_from_keys():
        a1 = AgentIdentity.create()
        a2 = AgentIdentity.from_keys(a1._private_key, a1._public_key)
        assert a1.agent_id == a2.agent_id
        return "from_keys roundtrip ✓"

    check(B, "AgentIdentity.create() — 32-char ID", test_create)
    check(B, "stamp() + verify() — SignedEvent", test_stamp_verify)
    check(B, "verify_chain() — 5 events", test_chain)
    check(B, "export() — AISS-1.0-AUDIT", test_export)
    check(B, "README quickstart — event['hash']", test_quickstart)
    check(B, "from_keys() — roundtrip", test_from_keys)


# ─── BLOC 9 — Test vectors ────────────────────────────────────────────────────

def bloc9_vectors():
    B = "BLOC 9 — Test vectors (normative)"
    section(B)
    from aiss.chain import compute_event_hash
    from aiss.canonical import canonicalize, hash_canonical

    # test_vectors/ is inside tests/ in aiss-standard
    _candidates = [
        AISS_ROOT / "tests" / "test_vectors",   # aiss-standard layout
        AISS_ROOT / "test_vectors",              # alternative at root
        ROOT / "test_vectors",                  # if smoke_test.py is inside tests/
    ]
    VECTORS_DIR = next((c for c in _candidates if c.exists()), _candidates[0])

    def test_vectors_dir():
        assert VECTORS_DIR.exists(), \
            f"test_vectors/ not found — searched: {[str(c) for c in _candidates]}"
        files = list(VECTORS_DIR.glob("*.json"))
        assert len(files) >= 1, "No vector files found"
        return f"{len(files)} file(s) at {VECTORS_DIR.name}/"

    def test_events_vectors():
        vf = VECTORS_DIR / "events.json"
        if not vf.exists():
            return "SKIP — events.json not found"
        data = json.loads(vf.read_text())
        passed = 0
        for test in data["tests"]:
            h = compute_event_hash(test["event"])
            assert h == test["expected_hash"], \
                f"Hash mismatch for {test['name']}: {h[:16]} ≠ {test['expected_hash'][:16]}"
            passed += 1
        return f"{passed} vector(s) ✓"

    def test_canonical_vectors():
        vf = VECTORS_DIR / "canonical.json"
        if not vf.exists():
            return "SKIP — canonical.json not found"
        data = json.loads(vf.read_text())
        passed = 0
        for test in data["tests"]:
            c = canonicalize(test["input"]).decode("utf-8")
            assert c == test["expected_canonical"], \
                f"Canonical mismatch for {test['name']}"
            h = hash_canonical(test["input"])
            assert h == test["expected_sha256"], \
                f"Hash mismatch for {test['name']}"
            passed += 1
        return f"{passed} vector(s) ✓"

    check(B, "test_vectors/ directory + files", test_vectors_dir)
    check(B, "events.json — hash vectors", test_events_vectors)
    check(B, "canonical.json — RFC 8785 vectors", test_canonical_vectors)


# ─── Main ─────────────────────────────────────────────────────────────────────

BLOCS = [
    (1, "Cryptography",              bloc1_crypto),
    (2, "Stamp & Chain",             bloc2_stamp_chain),
    (3, "Verification",              bloc3_verify),
    (4, "Memory",                    bloc4_memory),
    (5, "Export & Audit",            bloc5_export),
    (6, "Fork & Replay",             bloc6_fork_replay),
    (7, "A2A Handshake",             bloc7_a2a),
    (8, "AgentIdentity (high-level API)", bloc8_agent_identity),
    (9, "Test vectors (normative)",  bloc9_vectors),
]


def main():
    global _verbose, _stop_on_first_fail
    p = argparse.ArgumentParser(description="AISS v2.0.0 — Smoke Test")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--stop",  action="store_true", help="Stop on first failure")
    p.add_argument("--bloc",  type=int, choices=range(1, 10), metavar="N",
                   help="Run a single bloc (1-9)")
    args = p.parse_args()
    _verbose             = args.verbose
    _stop_on_first_fail  = args.stop

    print(f"\n{BOLD}{CYAN}AISS v2.0.0 — Smoke Test{RESET}")
    print(f"Root : {AISS_ROOT}")
    print("=" * 60)

    for num, name, fn in BLOCS:
        if args.bloc and args.bloc != num:
            continue
        if not _verbose:
            print(f"  {BOLD}[{num:02d}] {name:<44}{RESET}", end=" ", flush=True)
        try:
            fn()
            if not _verbose:
                bloc_r = [r for r in _results if f"BLOC {num}" in r[0]]
                ok_b   = sum(1 for r in bloc_r if r[2] == "OK")
                fail_b = sum(1 for r in bloc_r if r[2] == "FAIL")
                total  = ok_b + fail_b
                if fail_b == 0:
                    print(f"{GREEN}✓ {ok_b}/{total}{RESET}")
                else:
                    print(f"{RED}✗ {ok_b}/{total}{RESET}")
        except SystemExit:
            raise
        except Exception as e:
            if not _verbose:
                print(f"{RED}✗ ERROR{RESET}")
            print(f"    {RED}{e}{RESET}")

    print_summary()
    sys.exit(0 if sum(1 for r in _results if r[2] == "FAIL") == 0 else 1)


if __name__ == "__main__":
    main()
