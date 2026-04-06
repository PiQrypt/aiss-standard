# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt
# e-Soleau: DSO2026006483 (19/02/2026) — DSO2026009143 (12/03/2026)
#
# AISS — Agent Identity and Signature Standard
# https://aiss-standard.org

"""
Audit Export Format — AISS RFC §22

Standard audit export format for regulatory compliance and forensic analysis.

Certified exports (PiQrypt CA signature, .pqz archives) are available
in the full PiQrypt implementation: https://piqrypt.com
"""

import json
import time
from typing import Dict, Any, List, Optional

from aiss.chain import compute_chain_hash


# ─── Core export ─────────────────────────────────────────────────────────────

def export_audit_chain(
    agent_identity: Dict[str, Any],
    events: List[Dict[str, Any]],
    include_metadata: bool = True,
) -> Dict[str, Any]:
    """
    Export event chain in AISS-1.0-AUDIT compliant format.

    Creates a standardized audit structure containing:
    - Agent identity document
    - Complete event chain
    - Chain integrity hash (tamper-evident)
    - Export metadata

    Designed for:
    - Regulatory compliance (EU AI Act, SOC2, HIPAA, GDPR)
    - Forensic analysis
    - Third-party audits
    - Archive / backup

    Args:
        agent_identity:   Agent identity document
        events:           List of signed events in chronological order
        include_metadata: Include export metadata (default: True)

    Returns:
        Audit export dict conforming to AISS RFC §22

    Example:
        >>> audit = export_audit_chain(identity, events)
        >>> audit['spec']
        'AISS-1.0-AUDIT'
        >>> audit['chain_integrity_hash']
        'a3f7e8...'
    """
    audit: Dict[str, Any] = {
        "spec":                 "AISS-1.0-AUDIT",
        "agent_identity":       agent_identity,
        "events":               events,
        "chain_integrity_hash": compute_chain_hash(events),
        "exported_at":          int(time.time()),
    }

    if include_metadata:
        audit["metadata"] = {
            "event_count":     len(events),
            "first_timestamp": events[0].get("timestamp") if events else None,
            "last_timestamp":  events[-1].get("timestamp") if events else None,
            "exporter":        "aiss/2.0.0",
            "standard":        "https://aiss-standard.org",
        }

    return audit


def export_audit_chain_to_file(
    events: List[Dict[str, Any]],
    agent_identity: Dict[str, Any],
    output_path: str,
    include_metadata: bool = True,
) -> str:
    """
    Export event chain to a JSON file.

    Convenience wrapper around export_audit_chain that writes to disk.

    Args:
        events:           Events in chronological order
        agent_identity:   Agent identity document
        output_path:      Path to write JSON file
        include_metadata: Include export metadata

    Returns:
        Path to written file
    """
    audit = export_audit_chain(agent_identity, events, include_metadata)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(audit, f, indent=2)
    return output_path


# ─── Validation ──────────────────────────────────────────────────────────────

def validate_audit_export(audit: Dict[str, Any]) -> bool:
    """
    Validate audit export structure and chain integrity.

    Checks:
    - Required fields present
    - Spec version correct
    - Chain integrity hash matches

    Args:
        audit: Audit export dict

    Returns:
        True if valid

    Raises:
        ValueError: If audit export invalid or chain integrity fails
    """
    required = ["spec", "agent_identity", "events", "chain_integrity_hash", "exported_at"]
    for field in required:
        if field not in audit:
            raise ValueError(f"Missing required field: {field}")

    if not audit["spec"].startswith("AISS-"):
        raise ValueError(f"Invalid spec version: {audit['spec']}")

    expected = compute_chain_hash(audit["events"])
    actual   = audit["chain_integrity_hash"]

    if expected != actual:
        raise ValueError(
            f"Chain integrity hash mismatch: "
            f"expected {expected[:16]}..., got {actual[:16]}..."
        )

    return True


# ─── Selective exports ───────────────────────────────────────────────────────

def export_subset(
    audit: Dict[str, Any],
    start_index: int = 0,
    end_index: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Export a subset of events from an audit chain.

    Useful for pagination, selective disclosure, or time-range exports.

    Args:
        audit:       Full audit export
        start_index: First event index (inclusive)
        end_index:   Last event index (exclusive, None = end)

    Returns:
        New audit export with subset of events
    """
    events = audit["events"][start_index:end_index]
    return export_audit_chain(
        agent_identity=audit["agent_identity"],
        events=events,
        include_metadata=True,
    )


def export_by_timerange(
    audit: Dict[str, Any],
    start_timestamp: int,
    end_timestamp: int,
) -> Dict[str, Any]:
    """
    Export events within a timestamp range.

    Args:
        audit:            Full audit export
        start_timestamp:  Start time (Unix UTC, inclusive)
        end_timestamp:    End time (Unix UTC, inclusive)

    Returns:
        New audit export with filtered events
    """
    events = [
        e for e in audit["events"]
        if start_timestamp <= e.get("timestamp", 0) <= end_timestamp
    ]
    return export_audit_chain(
        agent_identity=audit["agent_identity"],
        events=events,
        include_metadata=True,
    )


# ─── Summary ─────────────────────────────────────────────────────────────────

def get_audit_summary(audit: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate summary statistics from an audit export.

    Returns:
        Dict with agent_id, event_count, timespan_seconds,
        chain_hash, export_date, first_timestamp, last_timestamp
    """
    events  = audit["events"]
    summary = {
        "spec":        audit["spec"],
        "agent_id":    audit["agent_identity"].get("agent_id"),
        "event_count": len(events),
        "chain_hash":  audit["chain_integrity_hash"],
        "export_date": audit["exported_at"],
    }

    if events:
        first_ts = events[0].get("timestamp", 0)
        last_ts  = events[-1].get("timestamp", 0)
        summary.update({
            "first_timestamp":  first_ts,
            "last_timestamp":   last_ts,
            "timespan_seconds": last_ts - first_ts,
        })

    return summary


# ─── Public API ──────────────────────────────────────────────────────────────

__all__ = [
    "export_audit_chain",
    "export_audit_chain_to_file",
    "validate_audit_export",
    "export_subset",
    "export_by_timerange",
    "get_audit_summary",
]
