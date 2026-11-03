from __future__ import annotations

import asyncio
import json
import sys
from typing import Any, Optional

from mcp.server.mcpserver import MCPServer

from .config import Config
from .errors import FlysshMcpError
from .tools import ToolService

TOOL_DESCRIPTIONS: dict[str, str] = {
    "ssh_exec": (
        "Execute a one-shot command on a remote host over SSH (password auth). "
        "Returns stdout, stderr, exit_code, and timed_out flag. "
        "WARNING: the agent can run arbitrary commands on the target host as the configured user."
    ),
    "ssh_scp": (
        "Copy files to/from a remote host using scp (password auth). "
        "direction 'upload' sends local sources to remote destination; "
        "'download' fetches remote sources to local destination."
    ),
    "ssh_view": (
        "Read a remote file or list a remote directory (2 levels deep). "
        "For files, supports view_range for line ranges and force_read_large_files to bypass the size cap."
    ),
    "ssh_create": (
        "Create a new remote file with the given content. Fails if the path already exists."
    ),
    "ssh_edit": (
        "Edit a remote file by applying exact string replacements. Each old_str must match exactly one location."
    ),
    "ssh_grep": (
        "Search file contents on a remote host using grep. Supports content/files_with_matches/count output modes, glob filters, and context lines."
    ),
    "ssh_glob": (
        "Find files on a remote host matching a glob pattern. Supports **, {a,b}, *, ?, and character classes."
    ),
    "ssh_start_session": (
        "Start a persistent interactive shell session on a remote host. Returns a session_id for subsequent read/write/stop calls."
    ),
    "ssh_write_session": (
        "Write input to an interactive session (auto-appends a newline). Use \\u0003 for Ctrl-C."
    ),
    "ssh_read_session": (
        "Read output from an interactive session, waiting up to wait_seconds for new output."
    ),
    "ssh_stop_session": (
        "Stop and close an interactive session."
    ),
    "ssh_list_sessions": (
        "List active (and optionally exited) interactive sessions."
    ),
    "ssh_list_hosts": (
        "List configured host aliases (host, port, user) without revealing passwords."
    ),
    "ssh_test": (
        "Test connectivity to a host alias by running 'echo ok'. Returns ok/fail and latency."
    ),
}


def _make_server(service: ToolService) -> MCPServer:
    server = MCPServer(name="flyssh-mcp", version="1.0.0")
    _register_all_tools(server, service)
    return server


def _register_all_tools(server: MCPServer, service: ToolService) -> None:
    def ssh_exec(
        target: str,
        command: str,
        cwd: Optional[str] = None,
        env: Optional[dict[str, str]] = None,
        shell: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> dict[str, Any]:
        """Execute a one-shot command on a remote host."""
        args: dict[str, Any] = {"target": target, "command": command}
        if cwd is not None:
            args["cwd"] = cwd
        if env is not None:
            args["env"] = env
        if shell is not None:
            args["shell"] = shell
        if timeout is not None:
            args["timeout"] = timeout
        return service.ssh_exec(args)

    def ssh_scp(
        target: str,
        direction: str,
        sources: list[str],
        destination: str,
        recursive: bool = False,
        timeout: Optional[float] = None,
    ) -> dict[str, Any]:
        """Copy files to/from a remote host."""
        args = {"target": target, "direction": direction, "sources": sources, "destination": destination, "recursive": recursive}
        if timeout is not None:
            args["timeout"] = timeout
        return service.ssh_scp(args)

    def ssh_view(
        target: str,
        path: str,
        view_range: Optional[list[int]] = None,
        force_read_large_files: bool = False,
        max_bytes: int = 20480,
        timeout: Optional[float] = None,
    ) -> dict[str, Any]:
        """Read a remote file or list a remote directory."""
        args = {"target": target, "path": path, "force_read_large_files": force_read_large_files, "max_bytes": max_bytes}
        if view_range is not None:
            args["view_range"] = view_range
        if timeout is not None:
            args["timeout"] = timeout
        return service.ssh_view(args)

    def ssh_create(
        target: str,
        path: str,
        content: str,
        timeout: Optional[float] = None,
    ) -> dict[str, Any]:
        """Create a new remote file."""
        args = {"target": target, "path": path, "content": content}
        if timeout is not None:
            args["timeout"] = timeout
        return service.ssh_create(args)

    def ssh_edit(
        target: str,
        path: str,
        edits: list[dict[str, str]],
        timeout: Optional[float] = None,
    ) -> dict[str, Any]:
        """Edit a remote file by applying exact string replacements."""
        args = {"target": target, "path": path, "edits": edits}
        if timeout is not None:
            args["timeout"] = timeout
        return service.ssh_edit(args)

    def ssh_grep(
        target: str,
        pattern: str,
        path: str = ".",
        glob: Optional[str] = None,
        case_insensitive: bool = False,
        output_mode: str = "files_with_matches",
        context: Optional[int] = None,
        context_before: int = 0,
        context_after: int = 0,
        head_limit: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> dict[str, Any]:
        """Search file contents on a remote host."""
        args = {"target": target, "pattern": pattern, "path": path, "case_insensitive": case_insensitive, "output_mode": output_mode, "context_before": context_before, "context_after": context_after}
        if glob is not None:
            args["glob"] = glob
        if context is not None:
            args["context"] = context
        if head_limit is not None:
            args["head_limit"] = head_limit
        if timeout is not None:
            args["timeout"] = timeout
        return service.ssh_grep(args)

    def ssh_glob(
        target: str,
        pattern: str,
        path: str = ".",
        head_limit: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> dict[str, Any]:
        """Find files on a remote host matching a glob pattern."""
        args = {"target": target, "pattern": pattern, "path": path}
        if head_limit is not None:
            args["head_limit"] = head_limit
        if timeout is not None:
            args["timeout"] = timeout
        return service.ssh_glob(args)

    def ssh_start_session(
        target: str,
        cwd: Optional[str] = None,
        shell: Optional[str] = None,
        env: Optional[dict[str, str]] = None,
        wait_seconds: float = 1.0,
        max_output_chars: int = 65536,
    ) -> dict[str, Any]:
        """Start a persistent interactive shell session."""
        args = {"target": target, "wait_seconds": wait_seconds, "max_output_chars": max_output_chars}
        if cwd is not None:
            args["cwd"] = cwd
        if shell is not None:
            args["shell"] = shell
        if env is not None:
            args["env"] = env
        return service.ssh_start_session(args)

    def ssh_write_session(
        session_id: str,
        input: str,
        wait_seconds: float = 1.0,
        max_output_chars: int = 65536,
    ) -> dict[str, Any]:
        """Write input to an interactive session."""
        return service.ssh_write_session({"session_id": session_id, "input": input, "wait_seconds": wait_seconds, "max_output_chars": max_output_chars})

    def ssh_read_session(
        session_id: str,
        wait_seconds: float = 1.0,
        max_output_chars: int = 65536,
    ) -> dict[str, Any]:
        """Read output from an interactive session."""
        return service.ssh_read_session({"session_id": session_id, "wait_seconds": wait_seconds, "max_output_chars": max_output_chars})

    def ssh_stop_session(
        session_id: str,
        force: bool = False,
        wait_seconds: float = 2.0,
        max_output_chars: int = 65536,
    ) -> dict[str, Any]:
        """Stop and close an interactive session."""
        return service.ssh_stop_session({"session_id": session_id, "force": force, "wait_seconds": wait_seconds, "max_output_chars": max_output_chars})

    def ssh_list_sessions(include_exited: bool = True) -> dict[str, Any]:
        """List active interactive sessions."""
        return service.ssh_list_sessions({"include_exited": include_exited})

    def ssh_list_hosts() -> dict[str, Any]:
        """List configured host aliases without revealing passwords."""
        return service.ssh_list_hosts({})

    def ssh_test(target: str, timeout: float = 10.0) -> dict[str, Any]:
        """Test connectivity to a host alias."""
        return service.ssh_test({"target": target, "timeout": timeout})

    tools = [
        ssh_exec, ssh_scp, ssh_view, ssh_create, ssh_edit, ssh_grep, ssh_glob,
        ssh_start_session, ssh_write_session, ssh_read_session, ssh_stop_session,
        ssh_list_sessions, ssh_list_hosts, ssh_test,
    ]
    for fn in tools:
        server.add_tool(fn, description=TOOL_DESCRIPTIONS.get(fn.__name__, fn.__name__))


def _self_check(config: Config) -> None:
    warnings = config.check_permissions()
    for w in warnings:
        print(f"flyssh-mcp: WARNING: {w}", file=sys.stderr)


async def _async_main() -> None:
    try:
        config = Config.load()
    except Exception as exc:
        print(f"flyssh-mcp: config error: {exc}", file=sys.stderr)
        sys.exit(1)
    _self_check(config)
    service = ToolService(config)
    server = _make_server(service)
    try:
        await server.run_stdio_async()
    finally:
        service.close()


def main() -> None:
    try:
        asyncio.run(_async_main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
