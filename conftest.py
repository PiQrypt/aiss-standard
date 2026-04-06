import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent

def pytest_configure(config):
    repo = str(_REPO_ROOT)
    if repo not in sys.path:
        sys.path.insert(0, repo)
    # Suppression propre — ne pas laisser de résidus
    to_delete = [k for k in sys.modules if k == "aiss" or k.startswith("aiss.")]
    for k in to_delete:
        del sys.modules[k]