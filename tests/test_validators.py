from __future__ import annotations

import unittest

from flyssh_mcp.errors import ValidationError
from flyssh_mcp.validators import (
    _bool_argument,
    _check_blocked_ssh_options,
    _env_argument,
    _float_argument,
    _int_argument,
    _string_argument,
    _string_list_argument,
    build_exec_remote_command,
)


class StringArgumentTests(unittest.TestCase):
    def test_required_missing(self) -> None:
        with self.assertRaises(ValidationError):
            _string_argument({}, "name", required=True)

    def test_required_empty(self) -> None:
        with self.assertRaises(ValidationError):
            _string_argument({"name": "  "}, "name", required=True)

    def test_not_string(self) -> None:
        with self.assertRaises(ValidationError):
            _string_argument({"name": 123}, "name")

    def test_nul_bytes(self) -> None:
        with self.assertRaises(ValidationError):
            _string_argument({"name": "a\x00b"}, "name")

    def test_strip(self) -> None:
        self.assertEqual(_string_argument({"name": "  hello  "}, "name"), "hello")

    def test_no_strip(self) -> None:
        self.assertEqual(_string_argument({"name": "  hello  "}, "name", strip=False), "  hello  ")

    def test_optional_missing(self) -> None:
        self.assertIsNone(_string_argument({}, "name"))


class BoolArgumentTests(unittest.TestCase):
    def test_default(self) -> None:
        self.assertFalse(_bool_argument({}, "flag", default=False))
        self.assertTrue(_bool_argument({}, "flag", default=True))

    def test_bool(self) -> None:
        self.assertTrue(_bool_argument({"flag": True}, "flag"))
        self.assertFalse(_bool_argument({"flag": False}, "flag"))

    def test_string(self) -> None:
        self.assertTrue(_bool_argument({"flag": "yes"}, "flag"))
        self.assertFalse(_bool_argument({"flag": "no"}, "flag"))
        self.assertTrue(_bool_argument({"flag": "true"}, "flag"))
        self.assertFalse(_bool_argument({"flag": "off"}, "flag"))

    def test_invalid(self) -> None:
        with self.assertRaises(ValidationError):
            _bool_argument({"flag": "maybe"}, "flag")


class IntArgumentTests(unittest.TestCase):
    def test_default(self) -> None:
        self.assertEqual(_int_argument({}, "n", default=42), 42)

    def test_valid(self) -> None:
        self.assertEqual(_int_argument({"n": 10}, "n"), 10)

    def test_bool_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            _int_argument({"n": True}, "n")

    def test_minimum(self) -> None:
        with self.assertRaises(ValidationError):
            _int_argument({"n": -1}, "n", minimum=0)


class FloatArgumentTests(unittest.TestCase):
    def test_valid(self) -> None:
        self.assertEqual(_float_argument({"x": 3.14}, "x"), 3.14)

    def test_no_zero(self) -> None:
        with self.assertRaises(ValidationError):
            _float_argument({"x": 0}, "x", allow_zero=False)


class StringListArgumentTests(unittest.TestCase):
    def test_required_missing(self) -> None:
        with self.assertRaises(ValidationError):
            _string_list_argument({}, "items", required=True)

    def test_not_list(self) -> None:
        with self.assertRaises(ValidationError):
            _string_list_argument({"items": "hello"}, "items")

    def test_valid(self) -> None:
        result = _string_list_argument({"items": ["a", "b"]}, "items")
        self.assertEqual(result, ["a", "b"])

    def test_empty_item(self) -> None:
        with self.assertRaises(ValidationError):
            _string_list_argument({"items": ["a", "  "]}, "items")


class EnvArgumentTests(unittest.TestCase):
    def test_empty(self) -> None:
        self.assertEqual(_env_argument({}), {})

    def test_valid(self) -> None:
        result = _env_argument({"env": {"FOO": "bar", "BAZ": "qux"}})
        self.assertEqual(result, {"FOO": "bar", "BAZ": "qux"})

    def test_invalid_name(self) -> None:
        with self.assertRaises(ValidationError):
            _env_argument({"env": {"123BAD": "val"}})

    def test_non_string_value(self) -> None:
        with self.assertRaises(ValidationError):
            _env_argument({"env": {"FOO": 123}})


class BlockedSshOptionsTests(unittest.TestCase):
    def test_allows_normal_options(self) -> None:
        _check_blocked_ssh_options(["-o", "ServerAliveInterval=60"], "extra_args")

    def test_blocks_proxycommand(self) -> None:
        with self.assertRaises(ValidationError):
            _check_blocked_ssh_options(["-o", "ProxyCommand=evil"], "extra_args")

    def test_blocks_localforward_flag(self) -> None:
        with self.assertRaises(ValidationError):
            _check_blocked_ssh_options(["-L", "8080:host:80"], "extra_args")

    def test_blocks_compact_option(self) -> None:
        with self.assertRaises(ValidationError):
            _check_blocked_ssh_options(["-oLocalCommand=evil"], "extra_args")


class BuildExecRemoteCommandTests(unittest.TestCase):
    def test_plain_command(self) -> None:
        self.assertEqual(build_exec_remote_command("ls", cwd=None, environment={}, shell=None), "ls")

    def test_with_cwd(self) -> None:
        result = build_exec_remote_command("ls", cwd="/tmp", environment={}, shell=None)
        self.assertIn("cd /tmp", result)
        self.assertIn("ls", result)

    def test_with_env(self) -> None:
        result = build_exec_remote_command("ls", cwd=None, environment={"FOO": "bar"}, shell=None)
        self.assertIn("export FOO=bar", result)

    def test_with_shell(self) -> None:
        result = build_exec_remote_command("ls", cwd=None, environment={}, shell="bash")
        self.assertIn("bash", result)


if __name__ == "__main__":
    unittest.main()
