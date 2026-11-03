from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from .errors import BackendError


def is_wsl() -> bool:
    """Detect whether we are running inside WSL2."""
    if sys.platform != "linux":
        return False
    # /proc/version typically mentions microsoft/WSL inside WSL.
    try:
        with open("/proc/version", "r", encoding="utf-8") as fh:
            content = fh.read().lower()
        return "microsoft" in content or "wsl" in content
    except OSError:
        return False


def is_windows() -> bool:
    return sys.platform == "win32"


def resolve_binary(configured: str, *, label: str) -> str:
    """Resolve a binary name/path, raising BackendError if not found."""
    candidate = configured.strip()
    if not candidate:
        raise BackendError(f"{label} name must be a non-empty string.")
    has_sep = os.sep in candidate or (os.altsep is not None and os.altsep in candidate)
    if has_sep or candidate.startswith("."):
        expanded = str(Path(candidate).expanduser())
        if not Path(expanded).exists():
            raise BackendError(f"{label} not found: {expanded}")
        return expanded
    resolved = shutil.which(candidate)
    if resolved is None:
        raise BackendError(f"{label} '{candidate}' was not found on PATH.")
    return resolved


def detect_backend(configured: str | None) -> str:
    """Choose 'plink' or 'sshpass' based on environment and config override."""
    if configured is not None:
        normalized = configured.strip().lower()
        if normalized not in {"plink", "sshpass"}:
            raise BackendError(
                f"Unknown backend '{configured}'; expected 'plink' or 'sshpass'."
            )
        return normalized
    if is_windows():
        return "plink"
    if is_wsl():
        return "sshpass"
    # Generic Linux/macOS: prefer sshpass if available, else plink.
    if shutil.which("sshpass") is not None:
        return "sshpass"
    return "plink"
