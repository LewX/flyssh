from __future__ import annotations

import json
import os
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import ConfigError, ValidationError

DEFAULT_CONFIG_DIR = Path.home() / ".ssh-mcp"
DEFAULT_CONFIG_PATH = DEFAULT_CONFIG_DIR / "config.json"
DEFAULT_STATE_DIR = Path.home() / ".local" / "state" / "flyssh-mcp"

_EMPTY_TEMPLATE: dict[str, Any] = {
    "hosts": {},
    "defaults": {"connect_timeout": 10, "exec_timeout": 30},
    "plink_path": "plink",
    "sshpass_path": "sshpass",
    "state_dir": str(DEFAULT_STATE_DIR),
}


@dataclass
class HostEntry:
    alias: str
    host: str
    port: int = 22
    user: str = "root"
    password: str = ""
    host_key: str | None = None  # cached plink host-key fingerprint
    extra: dict[str, Any] = field(default_factory=dict)

    def safe_summary(self) -> dict[str, Any]:
        """Return a dict without the password (for ssh_list_hosts)."""
        summary: dict[str, Any] = {
            "alias": self.alias,
            "host": self.host,
            "port": self.port,
            "user": self.user,
        }
        if self.host_key is not None:
            summary["host_key"] = self.host_key
        return summary


@dataclass
class Config:
    path: Path
    hosts: dict[str, HostEntry]
    defaults: dict[str, Any]
    plink_path: str
    sshpass_path: str
    state_dir: Path
    pscp_path: str = ''
    backend: str | None = None  # "plink" | "sshpass" | None (auto)
    raw: dict[str, Any] = field(default_factory=dict)
    _mtime: float = 0.0

    # ------------------------------------------------------------------ load
    @classmethod
    def load(cls, path: Path | str | None = None) -> "Config":
        config_path = Path(path).expanduser() if path else DEFAULT_CONFIG_PATH
        if not config_path.exists():
            cls._create_template(config_path)
            raise ConfigError(
                f"Config file did not exist; created an empty template at "
                f"{config_path}. Edit it to add hosts, then restart."
            )
        return cls._read(config_path)

    @staticmethod
    def _create_template(config_path: Path) -> None:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            config_path.parent.chmod(0o700)
        except OSError:
            pass
        config_path.write_text(
            json.dumps(_EMPTY_TEMPLATE, indent=2) + "\n", encoding="utf-8"
        )
        try:
            config_path.chmod(0o600)
        except OSError:
            pass

    @classmethod
    def _read(cls, config_path: Path) -> "Config":
        try:
            data = json.loads(config_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ConfigError(f"Config file {config_path} is not valid JSON: {exc}") from exc
        except OSError as exc:
            raise ConfigError(f"Cannot read config file {config_path}: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigError(f"Config file {config_path} must be a JSON object.")
        hosts_raw = data.get("hosts", {})
        if not isinstance(hosts_raw, dict):
            raise ConfigError("'hosts' in config must be an object.")
        hosts: dict[str, HostEntry] = {}
        for alias, entry in hosts_raw.items():
            if not isinstance(entry, dict):
                raise ConfigError(f"Host entry '{alias}' must be an object.")
            host = entry.get("host")
            if not isinstance(host, str) or not host:
                raise ConfigError(f"Host '{alias}' is missing a 'host' string.")
            port = int(entry.get("port", 22))
            user = str(entry.get("user", "root"))
            password = str(entry.get("password", ""))
            host_key = entry.get("host_key")
            extra = {k: v for k, v in entry.items()
                     if k not in {"host", "port", "user", "password", "host_key"}}
            hosts[alias] = HostEntry(
                alias=alias, host=host, port=port, user=user,
                password=password, host_key=host_key, extra=extra,
            )
        defaults = data.get("defaults", {})
        if not isinstance(defaults, dict):
            raise ConfigError("'defaults' in config must be an object.")
        plink_path = str(data.get("plink_path", "plink"))
        sshpass_path = str(data.get("sshpass_path", "sshpass"))
        pscp_path = str(data.get("pscp_path", ""))
        state_dir_raw = data.get("state_dir", str(DEFAULT_STATE_DIR))
        state_dir = Path(state_dir_raw).expanduser()
        backend = data.get("backend")
        try:
            mtime = config_path.stat().st_mtime
        except OSError:
            mtime = 0.0
        return cls(
            path=config_path,
            hosts=hosts,
            defaults=defaults,
            plink_path=plink_path,
            sshpass_path=sshpass_path,
            pscp_path=pscp_path,
            state_dir=state_dir,
            backend=backend,
            raw=data,
            _mtime=mtime,
        )

    # ------------------------------------------------------------- hot reload
    def maybe_reload(self) -> "Config":
        """Re-read the config file if its mtime changed; return self or a new Config."""
        try:
            current_mtime = self.path.stat().st_mtime
        except OSError:
            return self
        if current_mtime == self._mtime:
            return self
        # mtime changed -> reload
        return Config._read(self.path)

    # ------------------------------------------------------------- host lookup
    def resolve_target(self, target: str) -> HostEntry:
        """Resolve a target alias or ``user@host:port`` string to a HostEntry.

        If *target* is a configured alias, return that entry.  Otherwise parse
        it as ``[user@]host[:port]`` and look for a matching host in config to
        supply the password; if no match, the password is empty (connection
        will likely fail, but we let the backend surface that).
        """
        if target in self.hosts:
            return self.hosts[target]
        # Parse user@host:port
        user: str | None = None
        host_part = target
        if "@" in target:
            user, host_part = target.split("@", 1)
        port = 22
        if ":" in host_part:
            host_part, port_str = host_part.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                raise ValidationError(
                    f"Target '{target}' has an invalid port; expected user@host:port."
                )
        if not host_part:
            raise ValidationError(f"Target '{target}' is missing a host.")
        # Try to find a matching host entry by host+port for the password.
        password = ""
        host_key: str | None = None
        for entry in self.hosts.values():
            if entry.host == host_part and entry.port == port:
                password = entry.password
                host_key = entry.host_key
                if user is None:
                    user = entry.user
                break
        return HostEntry(
            alias=target,
            host=host_part,
            port=port,
            user=user or "root",
            password=password,
            host_key=host_key,
        )

    # ------------------------------------------------------------- host update
    def update_host_key(self, alias: str, host_key: str) -> None:
        """Persist a discovered host-key fingerprint back into the config file."""
        if alias not in self.hosts:
            return
        self.hosts[alias].host_key = host_key
        # Rewrite the raw dict and save.
        raw = dict(self.raw)
        hosts_raw = dict(raw.get("hosts", {}))
        entry_raw = dict(hosts_raw.get(alias, {}))
        entry_raw["host_key"] = host_key
        hosts_raw[alias] = entry_raw
        raw["hosts"] = hosts_raw
        self.raw = raw
        try:
            self.path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
            try:
                self.path.chmod(0o600)
            except OSError:
                pass
            self._mtime = self.path.stat().st_mtime
        except OSError as exc:
            print(f"flyssh-mcp: warning: failed to persist host_key for '{alias}': {exc}",
                  file=sys.stderr)

    # ----------------------------------------------------------- permission ck
    def check_permissions(self) -> list[str]:
        """Return a list of warning strings if config permissions are too loose."""
        warnings: list[str] = []
        try:
            dir_mode = stat.S_IMODE(self.path.parent.stat().st_mode)
            if dir_mode & 0o077:
                warnings.append(
                    f"Config directory {self.path.parent} is group/other accessible "
                    f"(mode {oct(dir_mode)}); recommend 0700 since it contains passwords."
                )
        except OSError:
            pass
        try:
            file_mode = stat.S_IMODE(self.path.stat().st_mode)
            if file_mode & 0o077:
                warnings.append(
                    f"Config file {self.path} is group/other readable "
                    f"(mode {oct(file_mode)}); recommend 0600 since it contains passwords."
                )
        except OSError:
            pass
        return warnings
