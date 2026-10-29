"""Resolve the transport and its required sibling Bridge runtime once."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BRIDGE_V3 = HERE.parent / "bridge-v3"
if not BRIDGE_V3.is_dir():
    raise RuntimeError(f"BRIDGE_V3_RUNTIME_MISSING: expected sibling runtime at {BRIDGE_V3}")

# Keep transport-local imports first, followed by the single shared runtime.
_paths = (str(HERE), str(BRIDGE_V3))
sys.path[:] = list(_paths) + [path for path in sys.path if path not in _paths]
