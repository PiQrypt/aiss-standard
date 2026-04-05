# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt
# e-Soleau: DSO2026006483 (19/02/2026) — DSO2026009143 (12/03/2026)
#
# AISS — Agent Identity and Signature Standard
# https://aiss-standard.org

"""
AISS Agent Memory System — RFC §18 (Canonical History)

Local-first, plaintext JSON storage for signed agent events.
Events are stored monthly in ~/.aiss/agents/<name>/events/plain/

Encrypted memory (AES-256-GCM, passphrase-protected) is available
in the full PiQrypt implementation: https://piqrypt.com

Architecture:
    ~/.aiss/
    └── agents/
        └── <agent_name>/
            ├── events/
            │   └── plain/      # Monthly JSON files: YYYY-MM.json
            └── index.db        # SQLite index for fast search

v1.8.4 additions:
    - agent_name parameter for per-agent isolation
    - IdentitySession integration
    - Backward compat: agent_name=None → "default" agent
"""

import json
import time
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from aiss.exceptions import AISSError
from aiss.logger import get_logger

logger = get_logger(__name__)

# ─── Import index (optional — fast search) ───────────────────────────────────
try:
    from aiss.index import get_index
    INDEX_AVAILABLE = True
except ImportError:
    INDEX_AVAILABLE = False
    get_index = None

# ─── Import agent_registry (optional — per-agent isolation) ──────────────────
try:
    from aiss.agent_registry import (
        get_events_plain_dir as _reg_plain_dir,
        get_keys_dir         as _reg_keys_dir,
        init_agent_dirs      as _reg_init_dirs,
        resolve_agent_name   as _resolve_agent,
    )
    REGISTRY_AVAILABLE = True
except ImportError:
    REGISTRY_AVAILABLE = False

# ─── Base paths ──────────────────────────────────────────────────────────────
AISS_DIR        = Path.home() / ".aiss"
EVENTS_PLAIN_DIR = AISS_DIR / "events" / "plain"
CONFIG_FILE      = AISS_DIR / "config.json"


# ─── Exceptions ──────────────────────────────────────────────────────────────

class MemoryLockedError(AISSError):
    """Raised when attempting to access encrypted memory without unlocking.
    Encrypted memory is a PiQrypt Pro feature."""
    pass


class MemoryCorruptedError(AISSError):
    """Memory file is corrupted or tampered."""
    pass


class PassphraseError(AISSError):
    """Invalid passphrase (PiQrypt Pro encrypted memory)."""
    pass


# ─── Path resolution ─────────────────────────────────────────────────────────

def _get_plain_dir(agent_name: Optional[str] = None, session: Any = None) -> Path:
    """
    Resolve plaintext storage directory for an agent.

    v1.8.4: uses agent_registry for per-agent isolation.
    Fallback: global ~/.aiss/events/plain/
    """
    if REGISTRY_AVAILABLE:
        name = _resolve_agent(agent_name, session)
        return _reg_plain_dir(name)
    return EVENTS_PLAIN_DIR


# ─── Directory initialization ────────────────────────────────────────────────

def init_memory_dirs(
    agent_name: Optional[str] = None,
    base_dir: Optional[str] = None,
) -> None:
    """
    Create directory structure for agent memory.

    Args:
        agent_name: Agent name for isolation (v1.8.4). None = "default"
        base_dir:   Override root directory (useful in tests/CI)
    """
    if base_dir is not None:
        _base = Path(base_dir)
        (_base / "events" / "plain").mkdir(parents=True, exist_ok=True)
        return

    if REGISTRY_AVAILABLE and agent_name:
        _reg_init_dirs(agent_name)
        return

    # Fallback — global dirs
    for d in [AISS_DIR, EVENTS_PLAIN_DIR]:
        d.mkdir(parents=True, exist_ok=True)

    if not CONFIG_FILE.exists():
        config = {
            "version":        "2.0.0",
            "retention_years": 10,
            "created_at":     int(time.time()),
            "standard":       "https://aiss-standard.org",
        }
        CONFIG_FILE.write_text(json.dumps(config, indent=2))

    logger.info(f"[AISS] Memory directories initialized at {AISS_DIR}")


def get_config() -> Dict[str, Any]:
    if not CONFIG_FILE.exists():
        init_memory_dirs()
    try:
        return json.loads(CONFIG_FILE.read_text())
    except Exception:
        return {"version": "2.0.0", "retention_years": 10}


# ─── Monthly file helpers ────────────────────────────────────────────────────

def _month_key(timestamp: int) -> str:
    dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    return dt.strftime("%Y-%m")


def _current_month() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m")


# ─── Store ───────────────────────────────────────────────────────────────────

def store_event(
    event: Dict[str, Any],
    agent_name: Optional[str] = None,
    session: Any = None,
    base_dir: Optional[str] = None,
) -> None:
    """
    Store a signed AISS event in local memory.

    Events are stored in monthly plaintext JSON files.
    The index is updated automatically for fast search.

    Args:
        event:      Signed AISS event dict
        agent_name: Agent name for isolation (v1.8.4). None = "default"
        session:    IdentitySession (agent_name deduced if provided)
        base_dir:   Override root directory (tests/CI)

    Example:
        >>> priv, pub = generate_keypair()
        >>> agent_id = derive_agent_id(pub)
        >>> event = stamp_event(priv, agent_id, {"action": "trade"})
        >>> store_event(event)
    """
    if base_dir is not None:
        plain_dir = Path(base_dir) / "events" / "plain"
        plain_dir.mkdir(parents=True, exist_ok=True)
        ts    = event.get("timestamp", int(time.time()))
        month = time.strftime("%Y-%m", time.localtime(
            ts if isinstance(ts, (int, float)) else int(time.time())
        ))
        ev_file = plain_dir / f"{month}.json"
        events = []
        if ev_file.exists():
            try:
                events = json.loads(ev_file.read_text())
            except Exception:
                events = []
        events.append(event)
        ev_file.write_text(json.dumps(events, indent=2))
        return

    store_event_free(event, agent_name=agent_name, session=session)


# keep the explicit name for direct callers
store_event_free = None  # defined below — forward ref resolved at end of module


def _store_event_free(
    event: Dict[str, Any],
    agent_name: Optional[str] = None,
    session: Any = None,
) -> None:
    """
    Store a signed event in plaintext monthly JSON file.

    Args:
        event:      Signed AISS event dict
        agent_name: Agent name for isolation (v1.8.4)
        session:    IdentitySession — agent_name deduced if provided
    """
    plain_dir = _get_plain_dir(agent_name, session)
    plain_dir.mkdir(parents=True, exist_ok=True)

    month    = _month_key(event.get("timestamp", int(time.time())))
    filepath = plain_dir / f"{month}.json"

    events = []
    if filepath.exists():
        try:
            events = json.loads(filepath.read_text())
        except (json.JSONDecodeError, OSError):
            events = []

    offset = len(json.dumps(events).encode("utf-8")) if events else 0
    events.append(event)
    filepath.write_text(json.dumps(events, indent=2))

    # Update index (non-critical)
    if INDEX_AVAILABLE and get_index:
        try:
            from aiss.chain import compute_event_hash
            event_hash   = compute_event_hash(event)
            payload      = event.get("payload", {})
            event_type   = payload.get("event_type") or payload.get("type")
            session_id   = payload.get("session_id")
            successor_id = payload.get("new_agent_id") if event_type == "key_rotation" else None

            with get_index(encrypted=False) as idx:
                idx.add_event(
                    event_hash=event_hash,
                    timestamp=event.get("timestamp", int(time.time())),
                    event_type=event_type,
                    agent_id=event.get("agent_id", ""),
                    nonce=event.get("nonce", ""),
                    file_path=f"{month}.json",
                    offset=offset,
                    length=len(json.dumps(event).encode("utf-8")),
                    successor_agent_id=successor_id,
                    session_id=session_id,
                )
        except Exception as e:
            logger.warning(f"Index update failed (non-critical): {e}")

    logger.debug("[AISS] Event stored (local memory)")


# Resolve forward reference
store_event_free = _store_event_free


# ─── Load ────────────────────────────────────────────────────────────────────

def load_events(
    month: Optional[str] = None,
    agent_id: Optional[str] = None,
    agent_name: Optional[str] = None,
    session: Any = None,
    base_dir: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Load events from local memory.

    Args:
        month:      Filter by month (YYYY-MM). None = all months
        agent_id:   Filter by agent_id
        agent_name: Agent name for isolation (v1.8.4)
        session:    IdentitySession
        base_dir:   Override root directory (tests/CI)

    Returns:
        List of events sorted by timestamp (ascending)
    """
    if base_dir is not None:
        plain_dir = Path(base_dir) / "events" / "plain"
        if not plain_dir.exists():
            return []
        all_events: List[Dict[str, Any]] = []
        for ev_file in sorted(plain_dir.glob("*.json")):
            if month and not ev_file.stem.startswith(month):
                continue
            try:
                data = json.loads(ev_file.read_text())
                if isinstance(data, list):
                    all_events.extend(data)
            except Exception:
                pass
        return all_events

    return load_events_free(
        month=month, agent_id=agent_id,
        agent_name=agent_name, session=session,
    )


def load_events_free(
    month: Optional[str] = None,
    agent_id: Optional[str] = None,
    agent_name: Optional[str] = None,
    session: Any = None,
) -> List[Dict[str, Any]]:
    """Load events from plaintext monthly JSON files."""
    plain_dir = _get_plain_dir(agent_name, session)
    plain_dir.mkdir(parents=True, exist_ok=True)

    all_events: List[Dict[str, Any]] = []
    files = [plain_dir / f"{month}.json"] if month else sorted(plain_dir.glob("*.json"))

    for f in files:
        if not f.exists():
            continue
        try:
            all_events.extend(json.loads(f.read_text()))
        except (json.JSONDecodeError, OSError):
            logger.warning(f"Could not read memory file: {f.name}")

    if agent_id:
        all_events = [e for e in all_events if e.get("agent_id") == agent_id]

    return sorted(all_events, key=lambda e: e.get("timestamp", 0))


# ─── Search ──────────────────────────────────────────────────────────────────

def search_events(
    participant: Optional[str] = None,
    event_type: Optional[str] = None,
    after: Optional[int] = None,
    before: Optional[int] = None,
    limit: int = 100,
    use_index: bool = True,
    session_id: Optional[str] = None,
    follow_rotation: bool = False,
) -> List[Dict[str, Any]]:
    """
    Search events in local memory.

    Args:
        participant:     Filter by agent_id (or payload.participants)
        event_type:      Filter by event_type
        after:           Lower bound Unix timestamp (inclusive)
        before:          Upper bound Unix timestamp (inclusive)
        limit:           Max results (default 100)
        use_index:       Use SQLite index for fast lookup (default True)
        session_id:      Filter by session_id — multi-agent sessions (v1.6)
        follow_rotation: Include all agent_ids in the rotation chain (v1.6)

    Returns:
        List of matching events sorted by timestamp

    Example:
        # All events for an agent including before key rotation
        results = search_events(participant=agent_id, follow_rotation=True)

        # All events in a multi-agent session
        results = search_events(session_id="sess_a3f9...")
    """
    # ── session_id fast path ──────────────────────────────────────────────────
    if session_id and use_index and INDEX_AVAILABLE and get_index:
        try:
            with get_index(encrypted=False) as idx:
                index_results = idx.search_by_session(session_id, limit=limit)
                if index_results is not None:
                    return _load_full_events_from_index(index_results)
        except Exception as e:
            logger.warning(f"Session index search failed, falling back: {e}")

    # ── follow_rotation — resolve full identity chain ─────────────────────────
    search_participants = None
    if follow_rotation and participant:
        try:
            from aiss.history import _resolve_identity_chain
            chain = _resolve_identity_chain(participant)
            if len(chain) > 1:
                search_participants = chain
        except Exception as e:
            logger.debug(f"[AISS] follow_rotation unavailable: {e}")

    # ── SQLite index fast path ────────────────────────────────────────────────
    if use_index and INDEX_AVAILABLE and get_index:
        try:
            with get_index(encrypted=False) as idx:
                if search_participants:
                    seen: set = set()
                    combined: List[Dict] = []
                    for pid in search_participants:
                        for entry in idx.search(
                            agent_id=pid, event_type=event_type,
                            from_timestamp=after, to_timestamp=before,
                            limit=limit,
                        ):
                            if entry["event_hash"] not in seen:
                                seen.add(entry["event_hash"])
                                combined.append(entry)
                    combined.sort(key=lambda x: x.get("timestamp", 0))
                    index_results = combined[:limit]
                else:
                    index_results = idx.search(
                        agent_id=participant, event_type=event_type,
                        from_timestamp=after, to_timestamp=before,
                        session_id=session_id, limit=limit,
                    )

                if index_results is not None:
                    return _load_full_events_from_index(index_results)

        except Exception as e:
            logger.warning(f"Index search failed, falling back to linear scan: {e}")

    # ── Linear scan fallback ──────────────────────────────────────────────────
    events = load_events()
    results = []
    _participants = search_participants or ([participant] if participant else None)

    for event in events:
        ts = event.get("timestamp", 0)
        if after  and ts < after:  continue
        if before and ts > before: continue

        if _participants:
            agent_match = event.get("agent_id", "") in _participants
            part_list   = event.get("payload", {}).get("participants", [])
            peer_match  = any(p in part_list for p in _participants)
            a2a_match   = (
                event.get("peer_agent_id", "") in _participants or
                event.get("payload", {}).get("peer_agent_id", "") in _participants
            )
            if not (agent_match or peer_match or a2a_match):
                continue

        if event_type:
            payload = event.get("payload", {})
            et = payload.get("event_type") or payload.get("type") or event.get("event_type", "")
            if et != event_type:
                continue

        if session_id:
            if event.get("payload", {}).get("session_id") != session_id:
                continue

        results.append(event)
        if len(results) >= limit:
            break

    return results


# ─── Index helper ────────────────────────────────────────────────────────────

def _load_full_events_from_index(
    index_results: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Load full events from storage based on SQLite index results."""
    from aiss.chain import compute_event_hash
    if not index_results:
        return []
    events_dict: Dict[str, Dict] = {}
    for entry in index_results:
        fp = entry["file_path"]
        if fp not in events_dict:
            file_events = load_events_free(month=fp.replace(".json", ""))
            events_dict[fp] = {compute_event_hash(e): e for e in file_events}
    return [
        events_dict.get(e["file_path"], {}).get(e["event_hash"])
        for e in index_results
        if events_dict.get(e["file_path"], {}).get(e["event_hash"])
    ]


# ─── Stats ───────────────────────────────────────────────────────────────────

def get_memory_stats(
    agent_name: Optional[str] = None,
    session: Any = None,
) -> Dict[str, Any]:
    """
    Return memory statistics for an agent.

    Args:
        agent_name: Agent name (v1.8.4). None = "default"
        session:    IdentitySession

    Returns:
        Dict with total_events, months breakdown, timestamps,
        retention_years, storage_path
    """
    config         = get_config()
    retention_years = config.get("retention_years", 10)
    plain_dir      = _get_plain_dir(agent_name, session)

    files      = sorted(plain_dir.glob("*.json")) if plain_dir.exists() else []
    total      = 0
    months     = []
    oldest_ts  = None
    newest_ts  = None

    for f in files:
        try:
            events = json.loads(f.read_text())
            count  = len(events)
            total += count
            months.append({"month": f.stem, "count": count})
            for e in events:
                ts = e.get("timestamp", 0)
                if oldest_ts is None or ts < oldest_ts: oldest_ts = ts
                if newest_ts is None or ts > newest_ts: newest_ts = ts
        except Exception:
            pass

    return {
        "total_events":      total,
        "months":            months,
        "oldest_timestamp":  oldest_ts,
        "newest_timestamp":  newest_ts,
        "retention_years":   retention_years,
        "storage_path":      str(plain_dir),
        "encrypted":         False,
        "standard":          "AISS/2.0.0",
    }


# ─── Public API ──────────────────────────────────────────────────────────────

__all__ = [
    # Init
    "init_memory_dirs",
    "get_config",
    # Store
    "store_event",
    "store_event_free",
    # Load
    "load_events",
    "load_events_free",
    # Search
    "search_events",
    # Stats
    "get_memory_stats",
    # Exceptions
    "MemoryLockedError",
    "MemoryCorruptedError",
    "PassphraseError",
]
