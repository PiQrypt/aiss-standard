# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt
"""
AISS telemetry stub — no-op.

Telemetry is a PiQrypt feature. In the AISS standard package,
all telemetry calls are silently ignored.
"""

def track(*args, **kwargs) -> None:
    """No-op — telemetry disabled in AISS standard package."""
    pass

def enable_telemetry() -> None:
    pass

def disable_telemetry() -> None:
    pass

def is_telemetry_enabled() -> bool:
    return False

def get_telemetry_status() -> dict:
    return {"enabled": False, "package": "aiss-standard"}
