import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent

def pytest_configure(config):
    """Insert repo root at head of sys.path before any test collection."""
    repo = str(_REPO_ROOT)
    # Retirer toutes les entrées existantes du path qui contiennent 'aiss'
    sys.path = [p for p in sys.path if 'site-packages' not in p or 'aiss' not in p]
    # Insérer le repo en tête
    if repo not in sys.path:
        sys.path.insert(0, repo)
    # Forcer le rechargement depuis le repo local
    for mod_name in list(sys.modules.keys()):
        if mod_name == "aiss" or mod_name.startswith("aiss."):
            del sys.modules[mod_name]
