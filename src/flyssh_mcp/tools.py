from __future__ import annotations

import os
import shlex
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .backend import Backend, make_backend
from .config import Config, HostEntry
from .env import detect_backend
from .errors import (
    BackendError,
    FlysshMcpError,
    RemoteFileError,
    SessionNotFoundError,
    ValidationError,
)
from .filetools import (
    _CREATE_SCRIPT,
    _EXISTING_FILE_SCRIPT,
    _GREP_SCRIPT,
    _GLOB_SCRIPT,
    _VIEW_SCRIPT,
    _apply_edits,
    _edits_argument,
    _expand_braces,
    _parse_view_range,
    _remote_file_error_for_exit,
    _shield_leading_dash,
    glob_to_regex,
    _GREP_MATCH_LINE_RE,
)
from .sessions import (
    DEFAULT_MAX_OUTPUT_CHARS,
    DEFAULT_SESSION_READ_WAIT_SECONDS,
    DEFAULT_SESSION_START_WAIT_SECONDS,
    DEFAULT_SESSION_STOP_WAIT_SECONDS,
    DEFAULT_SESSION_WRITE_WAIT_SECONDS,
    SessionManager,
)
from .validators import (
    _bool_argument,
    _build_export_commands,
    _env_argument,
    _float_argument,
    _int_argument,
    _string_argument,
    _string_list_argument,
    build_exec_remote_command,
    build_session_remote_command,
)

DEFAULT_VIEW_MAX_BYTES = 20_480
_ALLOWED_GREP_OUTPUT_MODES = {"content", "files_with_matches", "count"}


class ToolService:
    """Holds shared state and implements the 14 flyssh-mcp tools."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.config = config.maybe_reload()
        backend_name = detect_backend(self.config.backend)
        self.backend_name = backend_name
        self.state_dir = self.config.state_dir
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.sessions = SessionManager(state_dir=self.state_dir)
        self.audit = AuditLog(self.state_dir / "audit.log")

    # ----------------------------------------------------------- helpers
    def _reload_config(self) -> None:
        self.config = self.config.maybe_reload()

    def _make_backend(self, target: str) -> tuple[Backend, HostEntry]:
        self._reload_config()
        host = self.config.resolve_target(target)
        connect_timeout = float(self.config.defaults.get("connect_timeout", 10))
        backend = make_backend(
            self.backend_name,
            host,
            plink_path=self.config.plink_path,
            sshpass_path=self.config.sshpass_path,
            pscp_path=self.config.pscp_path,
            connect_timeout=connect_timeout,
        )
        return backend, host

    def _default_exec_timeout(self) -> float | None:
        return float(self.config.defaults.get("exec_timeout", 30))

    # ====================================================== ssh_exec
    def ssh_exec(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        target = _string_argument(arguments, "target", required=True)
        command = _string_argument(arguments, "command", required=True, strip=False)
        cwd = _string_argument(arguments, "cwd")
        shell = _string_argument(arguments, "shell")
        environment = _env_argument(arguments)
        timeout = _float_argument(arguments, "timeout", default=self._default_exec_timeout(), minimum=0.0, allow_zero=False)
        backend, host = self._make_backend(target)
        remote_command = build_exec_remote_command(command, cwd=cwd, environment=environment, shell=shell)
        result = backend.exec(remote_command, timeout=timeout)
        result["ok"] = result["exit_code"] == 0 and not result["timed_out"]
        result["target"] = target
        result["command"] = command
        self.audit.record_exec(
            target=target, command=command,
            exit_code=result["exit_code"], timed_out=result["timed_out"],
            duration_ms=result["duration_ms"],
        )
        return result

    # ====================================================== ssh_scp
    def ssh_scp(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        target = _string_argument(arguments, "target", required=True)
        direction = _string_argument(arguments, "direction", required=True)
        if direction not in {"upload", "download"}:
            raise ValidationError("'direction' must be one of: upload, download.")
        sources = _string_list_argument(arguments, "sources", required=True, strip=False, minimum_length=1)
        destination = _string_argument(arguments, "destination", required=True, strip=False)
        recursive = _bool_argument(arguments, "recursive", default=False)
        timeout = _float_argument(arguments, "timeout", default=self._default_exec_timeout(), minimum=0.0, allow_zero=False)
        backend, host = self._make_backend(target)
        if direction == "upload":
            normalized_sources = []
            for src in sources:
                expanded = str(Path(src).expanduser())
                if not Path(expanded).exists():
                    raise ValidationError(f"Local source path does not exist: {expanded}")
                if Path(expanded).is_dir() and not recursive:
                    raise ValidationError(f"Local source is a directory; set recursive=true: {expanded}")
                normalized_sources.append(expanded)
            normalized_destination = destination
        else:
            normalized_sources = sources
            expanded_dest = str(Path(destination).expanduser())
            parent = Path(expanded_dest)
            if parent.exists() and parent.is_dir():
                normalized_destination = expanded_dest
            else:
                if not parent.parent.exists():
                    raise ValidationError(f"Parent directory for local destination does not exist: {parent.parent}")
                normalized_destination = expanded_dest
        result = backend.scp(
            direction, normalized_sources, normalized_destination,
            recursive=recursive, timeout=timeout,
        )
        result["ok"] = result["exit_code"] == 0 and not result["timed_out"]
        result["target"] = target
        result["direction"] = direction
        self.audit.record(event="scp", target=target, detail=f"direction={direction} dest={destination}")
        return result

    # ====================================================== ssh_view
    def ssh_view(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        target = _string_argument(arguments, "target", required=True)
        path = _string_argument(arguments, "path", required=True)
        force_full = _bool_argument(arguments, "force_read_large_files", default=False)
        max_bytes = _int_argument(arguments, "max_bytes", default=DEFAULT_VIEW_MAX_BYTES, minimum=1, allow_zero=False)
        timeout = _float_argument(arguments, "timeout", default=self._default_exec_timeout(), minimum=0.0, allow_zero=False)
        view_range = arguments.get("view_range")
        backend, host = self._make_backend(target)
        start_line = None
        end_line = None
        shielded_path = _shield_leading_dash(path)
        if view_range is not None:
            start_line, end_line = _parse_view_range(view_range)
            mode = "range"
            script_args = [shielded_path, mode, str(start_line), str(end_line), ""]
        elif force_full:
            mode = "full"
            script_args = [shielded_path, mode, "", "", ""]
        else:
            mode = "auto"
            script_args = [shielded_path, mode, "", "", str(max_bytes)]
        result = backend.exec_script(_VIEW_SCRIPT, script_args, timeout=timeout)
        error = _remote_file_error_for_exit(result["exit_code"], path, timed_out=result["timed_out"], stderr=result["stderr"])
        if error is not None:
            raise error
        stdout = result["stdout"]
        separator = stdout.find("\x00")
        header, payload = (stdout, "") if separator == -1 else (stdout[:separator], stdout[separator + 1:])
        if header == "DIR":
            entries = []
            for line in payload.split("\n"):
                if not line:
                    continue
                kind, _, entry_path = line.partition("\t")
                entries.append({"path": entry_path, "type": "directory" if kind == "d" else "file"})
            return {"ok": True, "target": target, "path": path, "is_directory": True, "entries": entries}
        header_parts = header.split("\t")
        if len(header_parts) != 3 or header_parts[0] != "FILE":
            raise RemoteFileError(f"Unexpected response reading remote file: {path}")
        size_bytes = int(header_parts[1])
        total_lines = int(header_parts[2])
        truncated = mode == "auto" and size_bytes > max_bytes
        response = {
            "ok": True, "target": target, "path": path, "is_directory": False,
            "content": payload, "size_bytes": size_bytes, "total_lines": total_lines,
            "truncated": truncated,
        }
        if start_line is not None:
            response["start_line"] = start_line
            response["end_line"] = end_line
        return response

    # ====================================================== ssh_create
    def ssh_create(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        target = _string_argument(arguments, "target", required=True)
        path = _string_argument(arguments, "path", required=True)
        content = arguments.get("content")
        if not isinstance(content, str):
            raise ValidationError("'content' is required and must be a string.")
        if "\x00" in content:
            raise ValidationError("'content' cannot contain NUL bytes.")
        timeout = _float_argument(arguments, "timeout", default=self._default_exec_timeout(), minimum=0.0, allow_zero=False)
        backend, host = self._make_backend(target)
        result = backend.exec_script(_CREATE_SCRIPT, [_shield_leading_dash(path)], timeout=timeout, input_text=content)
        error = _remote_file_error_for_exit(result["exit_code"], path, timed_out=result["timed_out"], stderr=result["stderr"])
        if error is not None:
            raise error
        return {"ok": True, "target": target, "path": path, "bytes_written": len(content.encode("utf-8"))}

    # ====================================================== ssh_edit
    def ssh_edit(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        target = _string_argument(arguments, "target", required=True)
        path = _string_argument(arguments, "path", required=True)
        edits = _edits_argument(arguments)
        timeout = _float_argument(arguments, "timeout", default=self._default_exec_timeout(), minimum=0.0, allow_zero=False)
        backend, host = self._make_backend(target)
        shielded_path = _shield_leading_dash(path)
        read_result = backend.exec_script(_EXISTING_FILE_SCRIPT, [shielded_path, "read"], timeout=timeout)
        error = _remote_file_error_for_exit(read_result["exit_code"], path, timed_out=read_result["timed_out"], stderr=read_result["stderr"])
        if error is not None:
            raise error
        updated_content = _apply_edits(read_result["stdout"], edits)
        write_result = backend.exec_script(_EXISTING_FILE_SCRIPT, [shielded_path, "write"], timeout=timeout, input_text=updated_content)
        error = _remote_file_error_for_exit(write_result["exit_code"], path, timed_out=write_result["timed_out"], stderr=write_result["stderr"])
        if error is not None:
            raise error
        return {"ok": True, "target": target, "path": path, "edits_applied": len(edits), "bytes_written": len(updated_content.encode("utf-8"))}

    # ====================================================== ssh_grep
    def ssh_grep(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        target = _string_argument(arguments, "target", required=True)
        pattern = _string_argument(arguments, "pattern", required=True, strip=False)
        path = _string_argument(arguments, "path", strip=False) or "."
        glob_filter = _string_argument(arguments, "glob", strip=False)
        case_insensitive = _bool_argument(arguments, "case_insensitive", default=False)
        output_mode = _string_argument(arguments, "output_mode") or "files_with_matches"
        if output_mode not in _ALLOWED_GREP_OUTPUT_MODES:
            allowed = ", ".join(sorted(_ALLOWED_GREP_OUTPUT_MODES))
            raise ValidationError(f"'output_mode' must be one of: {allowed}.")
        context = _int_argument(arguments, "context", default=None, minimum=0)
        context_before = _int_argument(arguments, "context_before", default=0, minimum=0)
        context_after = _int_argument(arguments, "context_after", default=0, minimum=0)
        if context is not None:
            context_before = context_after = context
        if (context_before or context_after) and output_mode != "content":
            raise ValidationError("'context' only apply when output_mode is 'content'.")
        head_limit = _int_argument(arguments, "head_limit", default=None, minimum=1, allow_zero=False)
        timeout = _float_argument(arguments, "timeout", default=self._default_exec_timeout(), minimum=0.0, allow_zero=False)
        backend, host = self._make_backend(target)
        mode_flags = []
        if output_mode == "files_with_matches":
            mode_flags.append("-l")
        elif output_mode == "count":
            mode_flags.append("-c")
        else:
            mode_flags.append("-n")
            if context_before and context_before == context_after:
                mode_flags.extend(["-C", str(context_before)])
            else:
                if context_before:
                    mode_flags.extend(["-B", str(context_before)])
                if context_after:
                    mode_flags.extend(["-A", str(context_after)])
        case_flags = ["-i"] if case_insensitive else []
        include_flags = []
        if glob_filter:
            for variant in _expand_braces(glob_filter):
                include_flags.extend(["--include", variant])
        script_args = [_shield_leading_dash(path), *mode_flags, *case_flags, *include_flags, "--", pattern]
        result = backend.exec_script(_GREP_SCRIPT, script_args, timeout=timeout)
        exit_code = result["exit_code"]
        if result["timed_out"]:
            raise RemoteFileError(f"Remote search under '{path}' timed out.")
        if exit_code == 21:
            raise RemoteFileError(f"Remote path does not exist: {path}")
        # grep exit code 2 means an error occurred (e.g. permission denied on
        # some files) but it may still have produced partial results.  Only
        # fail if there is no stdout at all.
        if exit_code is not None and exit_code > 1 and not result["stdout"].strip():
            message = result["stderr"].strip() or f"grep exited with code {exit_code}."
            raise RemoteFileError(f"Remote search under '{path}' failed: {message}")
        lines = result["stdout"].split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        matches = []
        if output_mode == "files_with_matches":
            matches = list(lines)
        elif output_mode == "count":
            for line in lines:
                file_path, _, count_str = line.rpartition(":")
                if not file_path:
                    continue
                try:
                    count = int(count_str)
                except ValueError:
                    continue
                if count > 0:
                    matches.append({"path": file_path, "count": count})
        else:
            for line in lines:
                found = _GREP_MATCH_LINE_RE.match(line)
                if found is None:
                    continue
                entry = {"path": found.group("path"), "line_number": int(found.group("line")), "line": found.group("text")}
                if found.group("sep") == "-":
                    entry["is_context"] = True
                matches.append(entry)
        truncated = False
        if head_limit is not None and len(matches) > head_limit:
            matches = matches[:head_limit]
            truncated = True
        return {"ok": True, "target": target, "pattern": pattern, "path": path, "output_mode": output_mode, "matches": matches, "truncated": truncated}

    # ====================================================== ssh_glob
    def ssh_glob(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        target = _string_argument(arguments, "target", required=True)
        pattern = _string_argument(arguments, "pattern", required=True, strip=False)
        path = _string_argument(arguments, "path", strip=False) or "."
        head_limit = _int_argument(arguments, "head_limit", default=None, minimum=1, allow_zero=False)
        timeout = _float_argument(arguments, "timeout", default=self._default_exec_timeout(), minimum=0.0, allow_zero=False)
        backend, host = self._make_backend(target)
        result = backend.exec_script(_GLOB_SCRIPT, [_shield_leading_dash(path)], timeout=timeout)
        error = _remote_file_error_for_exit(result["exit_code"], path, timed_out=result["timed_out"], stderr=result["stderr"])
        if error is not None:
            raise error
        regex = glob_to_regex(pattern)
        candidates = (line[2:] if line.startswith("./") else line for line in result["stdout"].split("\n") if line)
        matched = sorted(candidate for candidate in candidates if regex.fullmatch(candidate))
        truncated = False
        if head_limit is not None and len(matched) > head_limit:
            matched = matched[:head_limit]
            truncated = True
        return {"ok": True, "target": target, "path": path, "pattern": pattern, "matches": matched, "truncated": truncated}

    # ====================================================== session tools
    def ssh_start_session(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        target = _string_argument(arguments, "target", required=True)
        cwd = _string_argument(arguments, "cwd")
        shell = _string_argument(arguments, "shell")
        environment = _env_argument(arguments)
        wait_seconds = _float_argument(arguments, "wait_seconds", default=DEFAULT_SESSION_START_WAIT_SECONDS, minimum=0.0)
        max_output_chars = _int_argument(arguments, "max_output_chars", default=DEFAULT_MAX_OUTPUT_CHARS, minimum=1, allow_zero=False)
        backend, host = self._make_backend(target)
        remote_command = build_session_remote_command(cwd=cwd, environment=environment, shell=shell)
        process = backend.open_session(remote_command)
        ssh_command = getattr(backend, "ssh_command", None) or backend.name
        session = self.sessions.start(target=target, process=process, remote_command=remote_command, ssh_command=ssh_command)
        result = session.read(wait_seconds=wait_seconds, max_output_chars=max_output_chars)
        self.audit.record(event="start_session", target=target, detail=f"session_id={session.session_id}")
        return result

    def ssh_write_session(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        session_id = _string_argument(arguments, "session_id", required=True)
        input_text = arguments.get("input")
        if not isinstance(input_text, str):
            raise ValidationError("'input' is required and must be a string.")
        # Auto-append newline unless the input already ends with one or is a
        # control character sequence like Ctrl-C (\u0003).
        if not input_text.endswith("\n") and not input_text.endswith("\r") and "\u0003" not in input_text:
            input_text = input_text + "\n"
        wait_seconds = _float_argument(arguments, "wait_seconds", default=DEFAULT_SESSION_WRITE_WAIT_SECONDS, minimum=0.0)
        max_output_chars = _int_argument(arguments, "max_output_chars", default=DEFAULT_MAX_OUTPUT_CHARS, minimum=1, allow_zero=False)
        session = self.sessions.get(session_id)
        return session.write(input_text=input_text, wait_seconds=wait_seconds, max_output_chars=max_output_chars)

    def ssh_read_session(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        session_id = _string_argument(arguments, "session_id", required=True)
        wait_seconds = _float_argument(arguments, "wait_seconds", default=DEFAULT_SESSION_READ_WAIT_SECONDS, minimum=0.0)
        max_output_chars = _int_argument(arguments, "max_output_chars", default=DEFAULT_MAX_OUTPUT_CHARS, minimum=1, allow_zero=False)
        session = self.sessions.get(session_id)
        return session.read(wait_seconds=wait_seconds, max_output_chars=max_output_chars)

    def ssh_stop_session(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        session_id = _string_argument(arguments, "session_id", required=True)
        force = _bool_argument(arguments, "force", default=False)
        wait_seconds = _float_argument(arguments, "wait_seconds", default=DEFAULT_SESSION_STOP_WAIT_SECONDS, minimum=0.0)
        max_output_chars = _int_argument(arguments, "max_output_chars", default=DEFAULT_MAX_OUTPUT_CHARS, minimum=1, allow_zero=False)
        session = self.sessions.get(session_id)
        result = session.stop(force=force, wait_seconds=wait_seconds, max_output_chars=max_output_chars)
        self.audit.record(event="stop_session", target=session.target, detail=f"session_id={session_id}")
        return result

    def ssh_list_sessions(self, arguments: Mapping[str, Any] | None = None) -> dict[str, Any]:
        arguments = arguments or {}
        include_exited = _bool_argument(arguments, "include_exited", default=True)
        return self.sessions.list_sessions(include_exited=include_exited)

    # ====================================================== auxiliary tools
    def ssh_list_hosts(self, arguments: Mapping[str, Any] | None = None) -> dict[str, Any]:
        self._reload_config()
        hosts = [entry.safe_summary() for entry in self.config.hosts.values()]
        return {"ok": True, "count": len(hosts), "hosts": hosts}

    def ssh_test(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        target = _string_argument(arguments, "target", required=True)
        timeout = _float_argument(arguments, "timeout", default=10.0, minimum=0.0, allow_zero=False)
        backend, host = self._make_backend(target)
        start = time.monotonic()
        try:
            result = backend.exec("echo ok", timeout=timeout)
        except FlysshMcpError as exc:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return {"ok": False, "target": target, "status": "fail", "error": str(exc), "duration_ms": elapsed_ms}
        elapsed_ms = int((time.monotonic() - start) * 1000)
        ok = result["exit_code"] == 0 and result["stdout"].strip() == "ok"
        return {
            "ok": ok, "target": target,
            "status": "ok" if ok else "fail",
            "stdout": result["stdout"].strip(),
            "stderr": result["stderr"].strip(),
            "exit_code": result["exit_code"],
            "duration_ms": elapsed_ms,
        }

    def close(self) -> None:
        self.sessions.close()
