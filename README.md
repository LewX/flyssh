# flyssh-mcp

A stdio MCP (Model Context Protocol) server that lets AI coding agents operate
remote machines via **password-authenticated SSH**.  Supports Windows (plink
backend) and WSL2 (sshpass backend) with automatic environment detection.

## Features

- **14 tools**: command execution, file operations, interactive sessions, file
  transfer, and host management.
- **Password auth**: passwords stored in a JSON config file (permission 600).
- **Host aliases**: refer to hosts by alias (`web1`) instead of `user@host:port`.
- **Dual backend**: plink on Windows, sshpass on WSL/Linux — auto-detected.
- **Hot reload**: config file changes are picked up on the next tool call.
- **Audit log**: every `ssh_exec` is recorded (passwords masked).
- **Security**: blocked SSH options, shlex-quoted arguments, env var validation.

## Installation

```bash
git clone <repo> && cd flyssh-mcp
python -m venv .venv
.venv\Scripts\pip install -e .
```

## Configuration

Create `~/.ssh-mcp/config.json` (on Windows: `C:\Users\<you>\.ssh-mcp\config.json`):

```json
{
  "hosts": {
    "web1": {
      "host": "192.168.1.100",
      "port": 22,
      "user": "youruser",
      "password": "yourpassword",
      "host_key": "SHA256:..."
    }
  },
  "defaults": { "connect_timeout": 10, "exec_timeout": 30 },
  "plink_path": "C:\\Users\\you\\plink.exe",
  "pscp_path": "C:\\Users\\you\\pscp.exe",
  "sshpass_path": "sshpass",
  "state_dir": "~/.local/state/flyssh-mcp"
}
```

- `host_key` (optional): the plink host-key fingerprint.  Get it with
  `plink -v -P <port> user@host "echo ok"` and look for
  `Host key fingerprint is: SHA256:...`.  Without it, plink with `-batch`
  will refuse unknown hosts.
- `pscp_path` (optional): path to pscp.exe for file transfer.  If omitted,
  flyssh-mcp looks for `pscp.exe` next to plink, then on PATH.
- `backend` (optional): `"plink"` or `"sshpass"` to force a backend; omit for
  auto-detection.

Set file permissions to 600 (Unix) — on Windows the server warns if the ACL
is too permissive but still runs.

## Connecting to Codex / Claude Code / Copilot

Add to your MCP client config:

```json
{
  "mcpServers": {
    "flyssh": {
      "command": "C:\\Users\\you\\flyssh-mcp\\.venv\\Scripts\\python.exe",
      "args": ["-m", "flyssh_mcp"]
    }
  }
}
```

## Tools

### Execution (2)
| Tool | Description |
|------|-------------|
| `ssh_exec` | Run a one-shot command. Returns stdout/stderr/exit_code/timed_out. |
| `ssh_scp` | Upload/download files via scp. |

### File operations (5)
| Tool | Description |
|------|-------------|
| `ssh_view` | Read a file (with line ranges) or list a directory (2 levels). |
| `ssh_create` | Create a new file (fails if it exists). Content via stdin pipe. |
| `ssh_edit` | Exact string replacement; each `old_str` must match once. |
| `ssh_grep` | Recursive grep with content/files/count modes, glob filters, context. |
| `ssh_glob` | Find files matching `**`, `{a,b}`, `*`, `?`, `[seq]`. |

### Interactive sessions (5)
| Tool | Description |
|------|-------------|
| `ssh_start_session` | Open a persistent shell; returns `session_id`. |
| `ssh_write_session` | Send input (auto-appends `\n`; `\u0003` = Ctrl-C). |
| `ssh_read_session` | Read pending output (waits up to `wait_seconds`). |
| `ssh_stop_session` | Close a session. |
| `ssh_list_sessions` | List active sessions. |

### Auxiliary (2)
| Tool | Description |
|------|-------------|
| `ssh_list_hosts` | List configured aliases (no passwords). |
| `ssh_test` | Test connectivity (`echo ok`); returns ok/fail + latency. |

## Security notes

- **Passwords are stored in plaintext** in the config file.  Protect it with
  file permissions (600).  The server warns on startup if permissions are loose.
- An agent with `ssh_exec` can run **arbitrary commands** on the target host as
  the configured user.  Only connect to hosts you trust the agent to manage.
- Passwords never appear in tool return values or the audit log.
- SSH options that execute local commands (`ProxyCommand`, `LocalCommand`,
  port forwarding) are blocked in extra args.

## WSL setup

```bash
sudo apt install sshpass
```

The sshpass backend uses `sshpass -p <pass> ssh -tt -o StrictHostKeyChecking=accept-new`.

## Testing

```bash
.venv\Scripts\python.exe -m pytest tests/ -v
```

## License

MIT
