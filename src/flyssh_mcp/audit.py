from __future__ import annotations

import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

# Patterns we scrub from audit entries so passwords never land in the log.
_PASSWORD_HINT_RE = re.compile(r"-pw\s+\S+", re.IGNORECASE)
_SSHPASS_PASS_RE = re.compile(r"sshpass\s+-p\s+\S+", re.IGNORECASE)


def _mask(text: str) -> str:
    text = _PASSWORD_HINT_RE.sub("-pw ***", text)
    text = _SSHPASS_PASS_RE.sub("sshpass -p ***", text)
    return text


class AuditLog:
    """Append-only audit log of ssh_exec invocations."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # Create the file with restrictive permissions if it doesn't exist.
        if not self._path.exists():
            fd = os.open(str(self._path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.close(fd)
        else:
            try:
                self._path.chmod(0o600)
            except OSError:
                pass

    def record_exec(
        self,
        *,
        target: str,
        command: str,
        exit_code: int | None,
        timed_out: bool,
        duration_ms: int,
    ) -> None:
        ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        status = "TIMEOUT" if timed_out else (str(exit_code) if exit_code is not None else "?")
        masked_command = _mask(command)
        line = f"{ts} | target={target} | exit={status} | dur={duration_ms}ms | cmd={masked_command}\n"
        with self._lock:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()

    def record(self, *, event: str, target: str, detail: str = "") -> None:
        ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        masked = _mask(detail)
        line = f"{ts} | event={event} | target={target} | {masked}\n".rstrip() + "\n"
        with self._lock:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
