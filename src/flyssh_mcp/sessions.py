from __future__ import annotations

import codecs
import errno
import os
import select
import signal
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .backend import _wait_for_exit, _terminate_process
from .errors import SessionNotFoundError, ValidationError

DEFAULT_MAX_OUTPUT_CHARS = 65_536
DEFAULT_UNREAD_BUFFER_CAP = 1_048_576  # 1 MiB
DEFAULT_SESSION_START_WAIT_SECONDS = 1.0
DEFAULT_SESSION_READ_WAIT_SECONDS = 1.0
DEFAULT_SESSION_WRITE_WAIT_SECONDS = 1.0
DEFAULT_SESSION_STOP_WAIT_SECONDS = 2.0


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _split_return_code(return_code):
    if return_code is None:
        return None, None
    if return_code >= 0:
        return return_code, None
    return None, -return_code


class Session:
    """A persistent interactive remote shell."""

    def __init__(self, *, session_id, target, process, remote_command, transcript_path, ssh_command):
        self.session_id = session_id
        self.target = target
        self.process = process
        self.remote_command = remote_command
        self.ssh_command = ssh_command
        self._condition = threading.Condition()
        self._decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self._unread_output = ""
        self._unread_dropped_chars = 0
        self._total_output_chars = 0
        self._started_at = _utcnow()
        self._ended_at = None
        self._last_output_mono = None
        self._eof = False
        self._transcript_path = transcript_path
        self._transcript_path.parent.mkdir(parents=True, exist_ok=True)
        self._transcript_lock = threading.Lock()
        transcript_fd = os.open(str(self._transcript_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        self._transcript_file = os.fdopen(transcript_fd, "a", encoding="utf-8")
        self._master_fd = getattr(process, "_flyssh_master_fd", None)
        self._read_fd = None
        self._stdout_stream = None
        if self._master_fd is not None:
            self._read_fd = self._master_fd
        else:
            self._stdout_stream = process.stdout
        self._reader = threading.Thread(target=self._reader_loop, name=f"flyssh-session-{session_id}", daemon=True)
        self._reader.start()

    def _append_transcript(self, text):
        if not text:
            return
        with self._transcript_lock:
            self._transcript_file.write(text)
            self._transcript_file.flush()

    def _close_transcript(self):
        with self._transcript_lock:
            if not self._transcript_file.closed:
                self._transcript_file.close()

    def _read_chunk_blocking(self):
        """Blocking read for pipe-based sessions (plink on Windows).

        Uses os.read on the raw file descriptor so we get data as soon as it
        arrives, without waiting for a buffer fill.  Returns b'' on EOF."""
        stream = self._stdout_stream
        if stream is None:
            return b""
        try:
            fd = stream.fileno()
        except (OSError, ValueError):
            return b""
        try:
            data = os.read(fd, 4096)
        except OSError as exc:
            if exc.errno in {errno.EIO, errno.EBADF}:
                return b""
            raise
        return data or b""

    def _read_chunk_pty(self):
        """Non-blocking read for PTY-based sessions (sshpass on WSL)."""
        try:
            ready, _, _ = select.select([self._read_fd], [], [], 0.2)
        except (OSError, ValueError):
            return b""
        if not ready:
            return None
        try:
            data = os.read(self._read_fd, 4096)
        except OSError as exc:
            if exc.errno in {errno.EIO, errno.EBADF}:
                return b""
            raise
        return data

    def _reader_loop(self):
        try:
            while True:
                if self._read_fd is not None:
                    data = self._read_chunk_pty()
                    if data is None:
                        if self.process.poll() is not None:
                            data = self._read_chunk_pty()
                            if not data:
                                break
                        else:
                            continue
                else:
                    data = self._read_chunk_blocking()
                if data == b"":
                    break
                text = self._decoder.decode(data)
                if not text:
                    continue
                self._append_transcript(text)
                with self._condition:
                    self._append_unread_locked(text)
                    self._condition.notify_all()
        finally:
            final_text = self._decoder.decode(b"", final=True)
            self._append_transcript(final_text)
            with self._condition:
                if final_text:
                    self._append_unread_locked(final_text)
                self._eof = True
                self._ended_at = self._ended_at or _utcnow()
                self._condition.notify_all()
            self._close_transcript()

    def _append_unread_locked(self, text):
        self._total_output_chars += len(text)
        self._last_output_mono = time.monotonic()
        new_len = len(self._unread_output) + len(text)
        if new_len <= DEFAULT_UNREAD_BUFFER_CAP:
            self._unread_output += text
            return
        combined_overflow = new_len - DEFAULT_UNREAD_BUFFER_CAP
        drop_from_existing = min(combined_overflow, len(self._unread_output))
        drop_from_text = combined_overflow - drop_from_existing
        self._unread_dropped_chars += combined_overflow
        self._unread_output = self._unread_output[drop_from_existing:] + text[drop_from_text:]

    def _pop_output_locked(self, max_output_chars):
        if max_output_chars <= 0:
            return "", False
        if len(self._unread_output) <= max_output_chars:
            output = self._unread_output
            self._unread_output = ""
            return output, False
        output = self._unread_output[:max_output_chars]
        self._unread_output = self._unread_output[max_output_chars:]
        return output, True

    def _snapshot_locked(self, *, output, truncated):
        return_code = self.process.poll()
        exit_code, term_signal = _split_return_code(return_code)
        running = return_code is None
        now = _utcnow()
        end = now if running else (self._ended_at or now)
        uptime_seconds = round((end - self._started_at).total_seconds(), 1)
        mono_now = time.monotonic()
        idle_seconds = round(mono_now - self._last_output_mono, 1) if self._last_output_mono is not None else None
        return {
            "session_id": self.session_id,
            "target": self.target,
            "running": running,
            "exit_code": exit_code,
            "signal": term_signal,
            "output": output,
            "truncated": truncated,
            "pending_output_chars": len(self._unread_output),
            "uptime_seconds": uptime_seconds,
            "idle_seconds": idle_seconds,
            "transcript_path": str(self._transcript_path),
        }

    def read(self, *, wait_seconds, max_output_chars):
        deadline = time.monotonic() + wait_seconds
        with self._condition:
            while True:
                # Return promptly once we have any buffered output.
                if self._unread_output:
                    break
                # If the process has exited and nothing is buffered, we're done.
                if self.process.poll() is not None:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0 or self._eof:
                    break
                self._condition.wait(timeout=min(remaining, 0.1))
            output, truncated = self._pop_output_locked(max_output_chars)
            return self._snapshot_locked(output=output, truncated=truncated)

    def write(self, *, input_text, wait_seconds, max_output_chars):
        if not isinstance(input_text, str):
            raise ValidationError("'input' must be a string.")
        payload = input_text.encode("utf-8")
        with self._condition:
            if self.process.poll() is not None:
                raise ValidationError(f"Session '{self.session_id}' has already exited.")
            # Drain any stale buffered output so the post-write read waits for
            # the command's own output rather than returning leftover text.
            self._unread_output = ""
        written = 0
        try:
            if self._master_fd is not None:
                buffer = memoryview(payload)
                while written < len(buffer):
                    n = os.write(self._master_fd, buffer[written:])
                    if n <= 0:
                        raise OSError(errno.EIO, "short write")
                    written += n
            else:
                stream = self.process.stdin
                if stream is None:
                    raise ValidationError(f"Session '{self.session_id}' is not writable.")
                stream.write(payload)
                stream.flush()
                written = len(payload)
        except (OSError, ValueError) as exc:
            raise ValidationError(f"Failed to write to session '{self.session_id}': {exc}") from exc
        result = self.read(wait_seconds=wait_seconds, max_output_chars=max_output_chars)
        result["bytes_written"] = written
        return result

    def stop(self, *, force, wait_seconds, max_output_chars):
        with self._condition:
            was_running = self.process.poll() is None
        termination_signal = None
        forced_kill = False
        if was_running:
            termination_signal = "SIGKILL" if force else "SIGTERM"
            forced_kill = _terminate_process(self.process, grace_period=wait_seconds)
            with self._condition:
                self._ended_at = self._ended_at or _utcnow()
                self._condition.notify_all()
        self._reader.join(timeout=0.5)
        final = self.read(wait_seconds=min(wait_seconds, 0.25), max_output_chars=max_output_chars)
        final["was_running"] = was_running
        final["termination_signal"] = termination_signal
        final["forced_kill"] = forced_kill
        return final

    def summary(self):
        with self._condition:
            return self._snapshot_locked(output="", truncated=False)


class SessionManager:
    def __init__(self, *, state_dir):
        self._lock = threading.RLock()
        self._sessions = {}
        self._state_dir = state_dir

    def _allocate_session_id(self):
        while True:
            sid = uuid.uuid4().hex[:12]
            if sid not in self._sessions:
                return sid

    def start(self, *, target, process, remote_command, ssh_command):
        with self._lock:
            session_id = self._allocate_session_id()
            transcript_path = self._state_dir / session_id / "transcript.log"
            session = Session(
                session_id=session_id,
                target=target,
                process=process,
                remote_command=remote_command,
                transcript_path=transcript_path,
                ssh_command=ssh_command,
            )
            self._sessions[session_id] = session
            return session

    def get(self, session_id):
        if not isinstance(session_id, str) or not session_id.strip():
            raise ValidationError("'session_id' must be a non-empty string.")
        with self._lock:
            session = self._sessions.get(session_id)
        if session is None:
            raise SessionNotFoundError(f"Unknown session_id '{session_id}'.")
        return session

    def list_sessions(self, *, include_exited=True):
        with self._lock:
            sessions = list(self._sessions.values())
        summaries = []
        for session in sessions:
            summary = session.summary()
            if not include_exited and not summary["running"]:
                continue
            summaries.append(summary)
        return {"count": len(summaries), "sessions": summaries}

    def close(self):
        with self._lock:
            sessions = list(self._sessions.values())
        for session in sessions:
            try:
                session.stop(force=True, wait_seconds=0.5, max_output_chars=1)
            except Exception:
                continue
