"""Exception hierarchy for flyssh-mcp.

Modeled on the ssh-mcp error types but with a ``FlysshMcpError`` base so the
prefix is distinct from the upstream project.
"""

from __future__ import annotations


class FlysshMcpError(Exception):
    """Base exception for flyssh-mcp failures."""


class ValidationError(FlysshMcpError):
    """Raised when tool arguments are invalid."""


class SessionNotFoundError(FlysshMcpError):
    """Raised when a session id is unknown."""


class RemoteFileError(FlysshMcpError):
    """Raised when a remote file/directory operation cannot proceed as requested."""


class BackendError(FlysshMcpError):
    """Raised when the chosen backend cannot perform the requested operation."""


class ConfigError(FlysshMcpError):
    """Raised when the configuration file is missing or malformed."""
