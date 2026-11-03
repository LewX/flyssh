from __future__ import annotations

import re
import shlex
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .errors import ValidationError

_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# SSH options that execute local commands or open local resources.  These are
# blocked in extra args to prevent prompt-injection attacks from running
# arbitrary commands on the *local* machine.
_BLOCKED_SSH_OPTIONS = {
    "proxycommand",
    "localcommand",
    "permitlocalcommand",
    "localforward",
    "remoteforward",
    "dynamicforward",
}

_BLOCKED_SSH_SHORT_FLAGS = {"-L", "-R", "-D", "-W"}


def _string_argument(
    arguments: Mapping[str, Any],
    name: str,
    *,
    required: bool = False,
    strip: bool = True,
) -> str | None:
    value = arguments.get(name)
    if value is None:
        if required:
            raise ValidationError(f"'{name}' is required.")
        return None
    if not isinstance(value, str):
        raise ValidationError(f"'{name}' must be a string.")
    if "\x00" in value:
        raise ValidationError(f"'{name}' cannot contain NUL bytes.")
    normalized = value.strip() if strip else value
    if not normalized.strip():
        raise ValidationError(f"'{name}' must be a non-empty string.")
    return normalized


def _bool_argument(arguments: Mapping[str, Any], name: str, *, default: bool = False) -> bool:
    value = arguments.get(name)
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        mapping = {
            "true": True,
            "false": False,
            "yes": True,
            "no": False,
            "on": True,
            "off": False,
        }
        if normalized in mapping:
            return mapping[normalized]
    raise ValidationError(f"'{name}' must be a boolean.")


def _float_argument(
    arguments: Mapping[str, Any],
    name: str,
    *,
    default: float | None = None,
    minimum: float = 0.0,
    allow_zero: bool = True,
) -> float | None:
    value = arguments.get(name)
    if value is None:
        return default
    if isinstance(value, bool):
        raise ValidationError(f"'{name}' must be a number.")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"'{name}' must be a number.") from exc
    if number < minimum or (not allow_zero and number == 0):
        comparator = ">=" if allow_zero else ">"
        raise ValidationError(f"'{name}' must be {comparator} {minimum}.")
    return number


def _int_argument(
    arguments: Mapping[str, Any],
    name: str,
    *,
    default: int | None = None,
    minimum: int = 0,
    allow_zero: bool = True,
) -> int | None:
    value = arguments.get(name)
    if value is None:
        return default
    if isinstance(value, bool):
        raise ValidationError(f"'{name}' must be an integer.")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"'{name}' must be an integer.") from exc
    if number < minimum or (not allow_zero and number == 0):
        comparator = ">=" if allow_zero else ">"
        raise ValidationError(f"'{name}' must be {comparator} {minimum}.")
    return number


def _path_argument(
    arguments: Mapping[str, Any],
    name: str,
    *,
    must_exist: bool = False,
) -> str | None:
    value = _string_argument(arguments, name)
    if value is None:
        return None
    path = Path(value).expanduser()
    if must_exist and not path.exists():
        raise ValidationError(f"'{name}' does not exist: {path}")
    if not must_exist and not path.parent.exists():
        raise ValidationError(f"Parent directory for '{name}' does not exist: {path.parent}")
    return str(path)


def _string_list_argument(
    arguments: Mapping[str, Any],
    name: str,
    *,
    required: bool = False,
    strip: bool = False,
    minimum_length: int = 0,
) -> list[str]:
    value = arguments.get(name)
    if value is None:
        if required:
            raise ValidationError(f"'{name}' is required.")
        return []
    if not isinstance(value, list):
        raise ValidationError(f"'{name}' must be an array of strings.")
    if len(value) < minimum_length:
        comparator = "at least" if minimum_length > 0 else "exactly"
        raise ValidationError(f"'{name}' must contain {comparator} {minimum_length} item(s).")
    normalized: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str):
            raise ValidationError(f"'{name}[{index}]' must be a string.")
        if "\x00" in item:
            raise ValidationError(f"'{name}[{index}]' cannot contain NUL bytes.")
        candidate = item.strip() if strip else item
        if not candidate.strip():
            raise ValidationError(f"'{name}[{index}]' must be a non-empty string.")
        normalized.append(candidate)
    return normalized


def _env_argument(arguments: Mapping[str, Any], name: str = "env") -> dict[str, str]:
    value = arguments.get(name)
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValidationError(f"'{name}' must be an object mapping strings to strings.")
    normalized: dict[str, str] = {}
    for raw_key, raw_value in value.items():
        if not isinstance(raw_key, str) or not _ENV_NAME_RE.fullmatch(raw_key):
            raise ValidationError(
                f"Environment variable names in '{name}' must match {_ENV_NAME_RE.pattern}."
            )
        if not isinstance(raw_value, str):
            raise ValidationError(f"Environment variable '{raw_key}' must have a string value.")
        if "\x00" in raw_value:
            raise ValidationError(f"Environment variable '{raw_key}' cannot contain NUL bytes.")
        normalized[raw_key] = raw_value
    return normalized


def _check_blocked_ssh_options(args: list[str], name: str) -> None:
    """Reject SSH -o options that would execute local commands."""
    for i, arg in enumerate(args):
        if arg in _BLOCKED_SSH_SHORT_FLAGS:
            raise ValidationError(
                f"'{name}' contains blocked SSH flag '{arg}'."
            )
        raw_option: str | None = None
        if arg == "-o" and i + 1 < len(args):
            raw_option = args[i + 1]
        elif arg.startswith("-o") and len(arg) > 2:
            raw_option = arg[2:]
        if raw_option is not None:
            option_key = raw_option.split("=", 1)[0].strip()
            if option_key.lower() in _BLOCKED_SSH_OPTIONS:
                raise ValidationError(
                    f"'{name}' contains blocked SSH option '{option_key}'. "
                    "This option can execute local commands and is not permitted."
                )


def _build_export_commands(environment: Mapping[str, str]) -> list[str]:
    return [f"export {name}={shlex.quote(value)}" for name, value in environment.items()]


def build_exec_remote_command(
    command: str,
    *,
    cwd: str | None,
    environment: Mapping[str, str],
    shell: str | None,
) -> str:
    if shell is None and cwd is None and not environment:
        return command
    script_parts = _build_export_commands(environment)
    body = command
    if cwd is not None:
        body = f"cd {shlex.quote(cwd)} && {body}"
    script_parts.append(body)
    script = "; ".join(script_parts)
    wrapper_shell = shell or "sh"
    return f"exec {shlex.quote(wrapper_shell)} -c {shlex.quote(script)}"


def build_session_remote_command(
    *,
    cwd: str | None,
    environment: Mapping[str, str],
    shell: str | None,
) -> str | None:
    if shell is None and cwd is None and not environment:
        return None
    script_parts = _build_export_commands(environment)
    shell_exec = (
        f"exec {shlex.quote(shell)} -i"
        if shell is not None
        else 'exec "${SHELL:-/bin/sh}" -i'
    )
    if cwd is not None:
        shell_exec = f"cd {shlex.quote(cwd)} && {shell_exec}"
    script_parts.append(shell_exec)
    script = "; ".join(script_parts)
    return f"exec sh -c {shlex.quote(script)}"
