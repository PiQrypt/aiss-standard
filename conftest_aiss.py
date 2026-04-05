import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent

def pytest_configure(config):
    """Insert repo root at head of sys.path before any test collection."""
    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))
    # Force reload from local repo if already loaded from piqrypt
    for mod_name in list(sys.modules.keys()):
        if mod_name == "aiss" or mod_name.startswith("aiss."):
            del sys.modules[mod_name]
