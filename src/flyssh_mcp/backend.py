from __future__ import annotations

import codecs
import errno
import os
import select
import shlex
import signal
import subprocess
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import HostEntry
from .env import resolve_binary
from .errors import BackendError, ValidationError
from .validators import _check_blocked_ssh_options


# ---------------------------------------------------------------- helpers


def _split_return_code(return_code: int | None) -> tuple[int | None, int | None]:
    if return_code is None:
        return None, None
    if return_code >= 0:
        return return_code, None
    return None, -return_code


def _wait_for_exit(process: subprocess.Popen[Any], timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return True
        time.sleep(0.05)
    return process.poll() is not None


def _signal_process(process: subprocess.Popen[Any], sig: int) -> None:
    try:
        if sys.platform == "win32":
            process.terminate() if sig == signal.SIGTERM else process.kill()
        else:
            os.killpg(os.getpgid(process.pid), sig)
    except (ProcessLookupError, OSError):
        pass


def _terminate_process(
    process: subprocess.Popen[Any],
    *,
    grace_period: float = 1.0,
) -> bool:
    """Terminate *process*; return True if SIGKILL was needed."""
    if process.poll() is not None:
        return False
    try:
        if sys.platform == "win32":
            process.terminate()
        else:
            _signal_process(process, signal.SIGTERM)
    except OSError:
        pass
    if _wait_for_exit(process, grace_period):
        return False
    try:
        process.kill()
    except OSError:
        pass
    _wait_for_exit(process, 1.0)
    return True


def _run_without_pty(argv: list[str], *, timeout: float | None) -> dict[str, Any]:
    start = time.monotonic()
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        start_new_session=(sys.platform != "win32"),
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_process(process)
        stdout, stderr = process.communicate()
    duration_ms = int((time.monotonic() - start) * 1000)
    exit_code, term_signal = _split_return_code(process.returncode)
    return {
        "exit_code": exit_code,
        "signal": term_signal,
        "stdout": stdout or "",
        "stderr": stderr or "",
        "timed_out": timed_out,
        "duration_ms": duration_ms,
    }


def _run_without_pty_binary_safe(
    argv: list[str], *, timeout: float | None, input_text: str | None = None
) -> dict[str, Any]:
    """Like ``_run_without_pty`` but communicates in raw bytes (no newline translation)."""
    start = time.monotonic()
    input_bytes = input_text.encode("utf-8") if input_text is not None else None
    process = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=(sys.platform != "win32"),
    )
    timed_out = False
    try:
        stdout_bytes, stderr_bytes = process.communicate(input=input_bytes, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_process(process)
        stdout_bytes, stderr_bytes = process.communicate()
    duration_ms = int((time.monotonic() - start) * 1000)
    exit_code, term_signal = _split_return_code(process.returncode)
    return {
        "exit_code": exit_code,
        "signal": term_signal,
        "stdout": (stdout_bytes or b"").decode("utf-8", errors="replace"),
        "stderr": (stderr_bytes or b"").decode("utf-8", errors="replace"),
        "timed_out": timed_out,
        "duration_ms": duration_ms,
    }


# ---------------------------------------------------------------- backend ABC


class Backend:
    """Abstract transport backend for executing commands on a remote host."""

    name: str = "abstract"

    def __init__(self, host: HostEntry, connect_timeout: float | None = None) -> None:
        self.host = host
        self.connect_timeout = connect_timeout

    # ---- one-shot command execution
    def exec(
        self,
        remote_command: str,
        *,
        timeout: float | None = None,
        input_text: str | None = None,
    ) -> dict[str, Any]:
        raise NotImplementedError

    # ---- run a remote POSIX script with positional args (for file tools)
    def exec_script(
        self,
        script: str,
        args: list[str],
        *,
        timeout: float | None = None,
        input_text: str | None = None,
    ) -> dict[str, Any]:
        words = [shlex.quote(script), "sh", *(shlex.quote(a) for a in args)]
        remote_command = "exec sh -c " + " ".join(words)
        return self.exec(remote_command, timeout=timeout, input_text=input_text)

    # ---- file transfer
    def scp(
        self,
        direction: str,
        sources: list[str],
        destination: str,
        *,
        recursive: bool = False,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        raise NotImplementedError

    # ---- open a persistent interactive session
    def open_session(self, remote_command: str | None) -> subprocess.Popen[Any]:
        """Return a Popen whose stdin/stdout are pipes for read/write."""
        raise NotImplementedError

    def close(self) -> None:
        pass


# ---------------------------------------------------------------- PlinkBackend


class PlinkBackend(Backend):
    name = "plink"

    def __init__(
        self,
        host: HostEntry,
        plink_path: str,
        connect_timeout: float | None = None,
        pscp_path: str | None = None,
        extra_args: list[str] | None = None,
    ) -> None:
        super().__init__(host, connect_timeout)
        self.plink_binary = resolve_binary(plink_path, label="plink")
        self.pscp_path = pscp_path
        self.extra_args = list(extra_args) if extra_args else []

    def _base_argv(self, *, batch: bool = True) -> list[str]:
        argv: list[str] = [self.plink_binary]
        argv += ["-P", str(self.host.port)]
        if self.host.password:
            argv += ["-pw", self.host.password]
        if self.host.host_key:
            argv += ["-hostkey", self.host.host_key]
        if batch:
            argv.append("-batch")
        argv += list(self.extra_args)
        _check_blocked_ssh_options(argv, "extra_args")
        argv.append(f"{self.host.user}@{self.host.host}")
        return argv

    def exec(
        self,
        remote_command: str,
        *,
        timeout: float | None = None,
        input_text: str | None = None,
    ) -> dict[str, Any]:
        argv = self._base_argv() + [remote_command]
        effective_timeout = timeout if timeout is not None else self.connect_timeout
        return _run_without_pty_binary_safe(
            argv, timeout=effective_timeout, input_text=input_text
        )

    def scp(
        self,
        direction: str,
        sources: list[str],
        destination: str,
        *,
        recursive: bool = False,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        # Resolve pscp: prefer configured, else plink's sibling pscp.exe.
        pscp = self.pscp_path
        if pscp:
            pscp_binary = resolve_binary(pscp, label="pscp")
        else:
            # Try pscp alongside plink.
            plink_dir = Path(self.plink_binary).parent
            candidate = plink_dir / "pscp.exe"
            if candidate.exists():
                pscp_binary = str(candidate)
            else:
                found = resolve_binary("pscp", label="pscp")
                pscp_binary = found
        argv: list[str] = [pscp_binary]
        argv += ["-P", str(self.host.port)]
        if self.host.password:
            argv += ["-pw", self.host.password]
        if self.host.host_key:
            argv += ["-hostkey", self.host.host_key]
        if recursive:
            argv.append("-r")
        argv += list(self.extra_args)
        _check_blocked_ssh_options(argv, "extra_args")
        if direction == "upload":
            argv += list(sources)
            argv.append(f"{self.host.user}@{self.host.host}:{destination}")
        else:
            for src in sources:
                argv.append(f"{self.host.user}@{self.host.host}:{src}")
            argv.append(destination)
        effective_timeout = timeout if timeout is not None else self.connect_timeout
        return _run_without_pty(argv, timeout=effective_timeout)

    def open_session(self, remote_command: str | None) -> subprocess.Popen[Any]:
        argv = self._base_argv(batch=False)
        if remote_command:
            argv.append(remote_command)
        try:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
            )
        except OSError as exc:
            raise BackendError(f"Failed to start plink session: {exc}") from exc
        return process


# ---------------------------------------------------------------- SshpassBackend


class SshpassBackend(Backend):
    name = "sshpass"

    def __init__(
        self,
        host: HostEntry,
        sshpass_path: str,
        connect_timeout: float | None = None,
        extra_args: list[str] | None = None,
    ) -> None:
        super().__init__(host, connect_timeout)
        self.sshpass_binary = resolve_binary(sshpass_path, label="sshpass")
        self.extra_args = list(extra_args) if extra_args else []

    def _ssh_argv(self, *, tty: bool = False) -> list[str]:
        argv: list[str] = [
            self.sshpass_binary, "-p", self.host.password,
            "ssh",
            "-p", str(self.host.port),
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
        ]
        if self.connect_timeout is not None:
            argv += ["-o", f"ConnectTimeout={int(self.connect_timeout)}"]
        if tty:
            argv.append("-tt")
        argv += list(self.extra_args)
        _check_blocked_ssh_options(argv, "extra_args")
        argv.append(f"{self.host.user}@{self.host.host}")
        return argv

    def exec(
        self,
        remote_command: str,
        *,
        timeout: float | None = None,
        input_text: str | None = None,
    ) -> dict[str, Any]:
        argv = self._ssh_argv() + [remote_command]
        effective_timeout = timeout if timeout is not None else self.connect_timeout
        return _run_without_pty_binary_safe(
            argv, timeout=effective_timeout, input_text=input_text
        )

    def scp(
        self,
        direction: str,
        sources: list[str],
        destination: str,
        *,
        recursive: bool = False,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        argv: list[str] = [
            self.sshpass_binary, "-p", self.host.password,
            "scp",
            "-P", str(self.host.port),
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
        ]
        if recursive:
            argv.append("-r")
        argv += list(self.extra_args)
        _check_blocked_ssh_options(argv, "extra_args")
        if direction == "upload":
            argv += list(sources)
            argv.append(f"{self.host.user}@{self.host.host}:{destination}")
        else:
            for src in sources:
                argv.append(f"{self.host.user}@{self.host.host}:{src}")
            argv.append(destination)
        effective_timeout = timeout if timeout is not None else self.connect_timeout
        return _run_without_pty(argv, timeout=effective_timeout)

    def open_session(self, remote_command: str | None) -> subprocess.Popen[Any]:
        argv = self._ssh_argv(tty=True)
        if remote_command:
            argv.append(remote_command)
        # Use a PTY pair so the remote shell behaves interactively.
        master_fd, slave_fd = os.openpty()
        try:
            process = subprocess.Popen(
                argv,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                start_new_session=True,
                close_fds=True,
            )
        except OSError as exc:
            os.close(master_fd)
            try:
                os.close(slave_fd)
            except OSError:
                pass
            raise BackendError(f"Failed to start sshpass session: {exc}") from exc
        finally:
            try:
                os.close(slave_fd)
            except OSError:
                pass
        # Stash the master fd on the process for the session manager.
        process._flyssh_master_fd = master_fd  # type: ignore[attr-defined]
        process._flyssh_pty = True  # type: ignore[attr-defined]
        return process


# ---------------------------------------------------------------- factory


def make_backend(
    backend_name: str,
    host: HostEntry,
    *,
    plink_path: str,
    sshpass_path: str,
    pscp_path: str = "",
    connect_timeout: float | None = None,
    extra_args: list[str] | None = None,
) -> Backend:
    if backend_name == "plink":
        return PlinkBackend(
            host, plink_path=plink_path,
            connect_timeout=connect_timeout, extra_args=extra_args,
            pscp_path=pscp_path or None,
        )
    if backend_name == "sshpass":
        return SshpassBackend(
            host, sshpass_path=sshpass_path,
            connect_timeout=connect_timeout, extra_args=extra_args,
        )
    raise BackendError(f"Unknown backend '{backend_name}'.")
