# SPDX-License-Identifier: MIT
# Copyright (c) 2026 PiQrypt
#
# Vigil — AISS Behavioral Monitoring Dashboard
# Included in the AISS standard package.
#
# Powered by PiQrypt · https://piqrypt.com
# Full Vigil (extended VRS, unlimited bridges, Pro alerts) → pip install piqrypt

"""
Vigil — AISS standard monitoring dashboard.

Launches a local HTTP dashboard on port 8421 to monitor agent activity,
VRS (Verifiable Risk Score), and chain health.

    from vigil import start_vigil
    start_vigil()   # → http://localhost:8421

Vigil standard (this package):
  ✅ Full dashboard UI
  ✅ VRS — 7-day history
  ✅ CRITICAL alerts
  ✅ Up to 2 bridge types
  ✅ Chain health monitoring

Vigil Pro (pip install piqrypt):
  ✅ VRS — 90-day / unlimited history
  ✅ All alert levels (WARNING, INFO, DEBUG)
  ✅ Unlimited bridge types
  ✅ Agent CRUD + certified exports from UI
  ✅ TrustGate integration
"""

__version__ = "2.0.0"
__powered_by__ = "PiQrypt — https://piqrypt.com"

# Standard limits (AISS package)
VIGIL_VRS_DAYS      = 7
VIGIL_BRIDGE_LIMIT  = 2
VIGIL_ALERTS_FULL   = False   # CRITICAL only in standard
VIGIL_PORT_DEFAULT  = 8421

try:
    from vigil.vigil_server import start_vigil, stop_vigil, get_vigil_status
    __all__ = ["start_vigil", "stop_vigil", "get_vigil_status",
               "VIGIL_PORT_DEFAULT", "VIGIL_VRS_DAYS", "VIGIL_BRIDGE_LIMIT"]
except ImportError:
    # vigil_server dependencies not available
    __all__ = ["VIGIL_PORT_DEFAULT", "VIGIL_VRS_DAYS", "VIGIL_BRIDGE_LIMIT"]
