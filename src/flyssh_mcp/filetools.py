from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from .errors import RemoteFileError, ValidationError

# Reserved exit codes used by the remote POSIX shell scripts.  Chosen to avoid
# colliding with common shell/utility exit statuses (0-2, 126, 127, 130).
_EXIT_NOT_FOUND = 21
_EXIT_NOT_REGULAR_FILE = 22
_EXIT_IS_DIRECTORY = 23
_EXIT_ALREADY_EXISTS = 24
_EXIT_NO_PARENT_DIR = 25
_EXIT_NOT_DIRECTORY = 26

# Matches both grep match lines ("path:line:text") and context lines
# ("path-line-text"); the backreference requires the same separator on
# both sides.
_GREP_MATCH_LINE_RE = re.compile(
    r"\A(?P<path>.*?)(?P<sep>[:-])(?P<line>\d+)(?P=sep)(?P<text>.*)\Z", re.DOTALL
)

# $1=path $2=mode('range'|'full'|'auto') $3=start $4=end(or -1) $5=max_bytes
_VIEW_SCRIPT = r"""
P=$1
MODE=$2
if [ ! -e "$P" ]; then exit 21; fi
if [ -d "$P" ]; then
  printf 'DIR\0'
  find "$P" -mindepth 1 -maxdepth 2 -name ".*" -prune -o -print 2>/dev/null | sort | while IFS= read -r entry; do
    if [ -d "$entry" ]; then
      printf 'd\t%s\n' "$entry"
    else
      printf 'f\t%s\n' "$entry"
    fi
  done
  exit 0
fi
if [ ! -f "$P" ]; then exit 22; fi
SIZE=$(wc -c < "$P" | tr -d '[:space:]')
LINES=$(wc -l < "$P" | tr -d '[:space:]')
printf 'FILE\t%s\t%s\0' "$SIZE" "$LINES"
case "$MODE" in
  range)
    START=$3
    END=$4
    if [ "$END" = "-1" ]; then
      sed -n "${START},\$p" "$P"
    else
      sed -n "${START},${END}p" "$P"
    fi
    ;;
  full)
    cat "$P"
    ;;
  *)
    MAXB=$5
    if [ "$SIZE" -gt "$MAXB" ]; then
      head -c "$MAXB" "$P"
    else
      cat "$P"
    fi
    ;;
esac
"""

# $1=path.  Content is piped over stdin.  Refuses to clobber.
_CREATE_SCRIPT = r"""
P=$1
if [ -e "$P" ]; then exit 24; fi
D=$(dirname "$P")
if [ ! -d "$D" ]; then exit 25; fi
cat > "$P"
"""

# $1=path $2=mode('read'|'write').  Used by ssh_edit.
_EXISTING_FILE_SCRIPT = r"""
P=$1
MODE=$2
if [ ! -e "$P" ]; then exit 21; fi
if [ -d "$P" ]; then exit 23; fi
if [ ! -f "$P" ]; then exit 22; fi
if [ "$MODE" = "write" ]; then
  cat > "$P"
else
  cat "$P"
fi
"""

# args: [path <flags...> -- pattern].  Prefers PCRE (-P), falls back to ERE (-E).
_GREP_SCRIPT = r"""
P=$1
shift
if [ ! -e "$P" ]; then exit 21; fi
GREP=grep
if command -v ggrep >/dev/null 2>&1; then GREP=ggrep; fi
if printf 'x' | "$GREP" -P 'x' >/dev/null 2>&1; then FLAG=-P; else FLAG=-E; fi
exec "$GREP" -r -I -H "$FLAG" --exclude-dir=.git --exclude-dir=.hg --exclude-dir=.svn "$@" "$P"
"""

# $1=path (a directory).  Enumerates files for ssh_glob.
_GLOB_SCRIPT = r"""
P=$1
if [ ! -e "$P" ]; then exit 21; fi
if [ ! -d "$P" ]; then exit 26; fi
cd "$P" || exit 26
find . -type d \( -name .git -o -name .hg -o -name .svn \) -prune -o -type f -print 2>/dev/null || true
"""


def _shield_leading_dash(path: str) -> str:
    if path.startswith("-") and not path.startswith("/"):
        return f"./{path}"
    return path


def _remote_file_error_for_exit(
    exit_code: int | None, path: str, *, timed_out: bool, stderr: str
) -> RemoteFileError | None:
    if timed_out:
        return RemoteFileError(f"Remote operation on '{path}' timed out.")
    if exit_code == 0:
        return None
    if exit_code == _EXIT_NOT_FOUND:
        return RemoteFileError(f"Remote path does not exist: {path}")
    if exit_code == _EXIT_NOT_REGULAR_FILE:
        return RemoteFileError(f"Remote path exists but is not a regular file: {path}")
    if exit_code == _EXIT_IS_DIRECTORY:
        return RemoteFileError(f"Remote path is a directory, not a file: {path}")
    if exit_code == _EXIT_ALREADY_EXISTS:
        return RemoteFileError(f"Remote path already exists: {path}")
    if exit_code == _EXIT_NO_PARENT_DIR:
        return RemoteFileError(f"Parent directory does not exist remotely for: {path}")
    if exit_code == _EXIT_NOT_DIRECTORY:
        return RemoteFileError(f"Remote path exists but is not a directory: {path}")
    message = stderr.strip() or f"remote command exited with code {exit_code}."
    return RemoteFileError(f"Remote operation on '{path}' failed: {message}")


def _parse_view_range(value: Any) -> tuple[int, int]:
    if not isinstance(value, list) or len(value) != 2:
        raise ValidationError("'view_range' must be a two-element array, e.g. [start, end].")
    start_raw, end_raw = value
    if isinstance(start_raw, bool) or isinstance(end_raw, bool):
        raise ValidationError("'view_range' elements must be integers.")
    try:
        start = int(start_raw)
        end = int(end_raw)
    except (TypeError, ValueError) as exc:
        raise ValidationError("'view_range' elements must be integers.") from exc
    if start < 1:
        raise ValidationError("'view_range[0]' (start line) must be >= 1.")
    if end != -1 and end < start:
        raise ValidationError("'view_range[1]' (end line) must be -1 (end of file) or >= start line.")
    return start, end


def _edits_argument(arguments: Mapping[str, Any]) -> list[tuple[str, str]]:
    value = arguments.get("edits")
    if not isinstance(value, list) or not value:
        raise ValidationError(
            "'edits' is required and must be a non-empty array of {old_str, new_str} objects."
        )
    parsed: list[tuple[str, str]] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise ValidationError(f"'edits[{index}]' must be an object with 'old_str' and 'new_str'.")
        old_str = item.get("old_str")
        new_str = item.get("new_str")
        if not isinstance(old_str, str) or not old_str:
            raise ValidationError(f"'edits[{index}].old_str' is required and must be a non-empty string.")
        if "\x00" in old_str:
            raise ValidationError(f"'edits[{index}].old_str' cannot contain NUL bytes.")
        if not isinstance(new_str, str):
            raise ValidationError(f"'edits[{index}].new_str' is required and must be a string.")
        if "\x00" in new_str:
            raise ValidationError(f"'edits[{index}].new_str' cannot contain NUL bytes.")
        parsed.append((old_str, new_str))
    return parsed


def _apply_edits(content: str, edits: list[tuple[str, str]]) -> str:
    updated = content
    for index, (old_str, new_str) in enumerate(edits):
        count = updated.count(old_str)
        if count == 0:
            raise RemoteFileError(
                f"'edits[{index}].old_str' was not found in the file "
                "(checked after applying any earlier edits in this call)."
            )
        if count > 1:
            raise RemoteFileError(
                f"'edits[{index}].old_str' matches {count} locations in the file; "
                "it must match exactly one. Include more surrounding context to make it unique."
            )
        updated = updated.replace(old_str, new_str, 1)
    return updated


_BRACE_GROUP_RE = re.compile(r"\{([^{}]*)\}")


def _expand_braces(pattern: str) -> list[str]:
    match = _BRACE_GROUP_RE.search(pattern)
    if match is None:
        return [pattern]
    prefix, suffix = pattern[: match.start()], pattern[match.end() :]
    expanded: list[str] = []
    for option in match.group(1).split(","):
        expanded.extend(_expand_braces(prefix + option + suffix))
    return expanded


def _translate_glob_segment(segment: str) -> str:
    chars: list[str] = []
    i, n = 0, len(segment)
    while i < n:
        c = segment[i]
        if c == "*":
            chars.append("[^/]*")
            i += 1
        elif c == "?":
            chars.append("[^/]")
            i += 1
        elif c == "[":
            j = i + 1
            if j < n and segment[j] in "!^":
                j += 1
            if j < n and segment[j] == "]":
                j += 1
            while j < n and segment[j] != "]":
                j += 1
            if j >= n:
                chars.append(re.escape("["))
                i += 1
            else:
                inner = segment[i + 1 : j]
                if inner.startswith("!") or inner.startswith("^"):
                    inner = "^" + inner[1:]
                inner = inner.replace("\\", "\\\\")
                chars.append(f"[{inner}]")
                i = j + 1
        else:
            chars.append(re.escape(c))
            i += 1
    return "".join(chars)


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    non_hidden_segment = "[^/.][^/]*"
    alternatives: list[str] = []
    for variant in _expand_braces(pattern):
        segments = variant.split("/")
        fragments: list[str | None] = []
        for segment in segments:
            if segment == "**":
                fragments.append(None)
            else:
                fragment = _translate_glob_segment(segment)
                if not segment.startswith("."):
                    fragment = r"(?!\.)" + fragment
                fragments.append(fragment)
        pieces: list[str] = []
        last_index = len(fragments) - 1
        for index, fragment in enumerate(fragments):
            previous_is_double_star = index > 0 and fragments[index - 1] is None
            needs_slash_join = index > 0 and not previous_is_double_star
            if fragment is None:
                if needs_slash_join:
                    pieces.append("/")
                if index == last_index:
                    pieces.append(f"(?:{non_hidden_segment}(?:/{non_hidden_segment})*)?")
                else:
                    pieces.append(f"(?:{non_hidden_segment}/)*")
            else:
                if needs_slash_join:
                    pieces.append("/")
                pieces.append(fragment)
        alternatives.append("".join(pieces))
    combined = "|".join(f"(?:{alt})" for alt in alternatives)
    return re.compile(f"(?:{combined})", re.DOTALL)
