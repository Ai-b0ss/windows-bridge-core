"""Per-path Win32 long-path support; never changes global Windows policy."""
import os
from pathlib import Path


def extended_path(path, *, force=False):
    path=Path(path).absolute()
    value=str(path)
    if os.name != "nt" or value.startswith("\\\\?\\") or (len(value)<240 and not force):
        return path
    if value.startswith("\\\\"):
        return Path("\\\\?\\UNC\\"+value[2:])
    return Path("\\\\?\\"+value)
