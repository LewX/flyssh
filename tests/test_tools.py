from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from flyssh_mcp.config import Config, HostEntry
from flyssh_mcp.errors import RemoteFileError, ValidationError
from flyssh_mcp.tools import ToolService


class ToolServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.config_path = Path(self.tmpdir) / "config.json"
        self.config_path.write_text(json.dumps({
            "hosts": {
                "web1": {"host": "10.0.0.1", "port": 22, "user": "admin", "password": "pw"},
            },
            "defaults": {"connect_timeout": 5, "exec_timeout": 10},
            "plink_path": "plink",
            "sshpass_path": "sshpass",
            "state_dir": self.tmpdir,
        }), encoding="utf-8")
        self.config = Config.load(self.config_path)
        # Force plink backend but mock resolve_binary
        with patch("flyssh_mcp.env.detect_backend", return_value="plink"), \
             patch("flyssh_mcp.backend.resolve_binary", return_value="plink"):
            self.service = ToolService(self.config)

    def _mock_backend(self) -> MagicMock:
        backend = MagicMock()
        backend.name = "plink"
        backend.exec.return_value = {
            "exit_code": 0, "stdout": "", "stderr": "", "timed_out": False,
            "duration_ms": 10, "signal": None,
        }
        backend.exec_script.return_value = {
            "exit_code": 0, "stdout": "", "stderr": "", "timed_out": False,
            "duration_ms": 10, "signal": None,
        }
        return backend

    @patch("flyssh_mcp.tools.ToolService._make_backend")
    def test_ssh_exec(self, mock_make: MagicMock) -> None:
        backend = self._mock_backend()
        backend.exec.return_value = {
            "exit_code": 0, "stdout": "hello\n", "stderr": "", "timed_out": False,
            "duration_ms": 100, "signal": None,
        }
        mock_make.return_value = (backend, self.config.hosts["web1"])
        result = self.service.ssh_exec({"target": "web1", "command": "echo hello"})
        self.assertTrue(result["ok"])
        self.assertEqual(result["stdout"], "hello\n")
        self.assertEqual(result["target"], "web1")

    @patch("flyssh_mcp.tools.ToolService._make_backend")
    def test_ssh_exec_missing_target(self, mock_make: MagicMock) -> None:
        with self.assertRaises(ValidationError):
            self.service.ssh_exec({"command": "echo hello"})

    @patch("flyssh_mcp.tools.ToolService._make_backend")
    def test_ssh_exec_missing_command(self, mock_make: MagicMock) -> None:
        with self.assertRaises(ValidationError):
            self.service.ssh_exec({"target": "web1"})

    @patch("flyssh_mcp.tools.ToolService._make_backend")
    def test_ssh_list_hosts_no_password(self, mock_make: MagicMock) -> None:
        result = self.service.ssh_list_hosts({})
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 1)
        host = result["hosts"][0]
        self.assertEqual(host["alias"], "web1")
        self.assertNotIn("password", host)

    @patch("flyssh_mcp.tools.ToolService._make_backend")
    def test_ssh_test_ok(self, mock_make: MagicMock) -> None:
        backend = self._mock_backend()
        backend.exec.return_value = {
            "exit_code": 0, "stdout": "ok\n", "stderr": "", "timed_out": False,
            "duration_ms": 50, "signal": None,
        }
        mock_make.return_value = (backend, self.config.hosts["web1"])
        result = self.service.ssh_test({"target": "web1"})
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "ok")

    @patch("flyssh_mcp.tools.ToolService._make_backend")
    def test_ssh_test_fail(self, mock_make: MagicMock) -> None:
        backend = self._mock_backend()
        backend.exec.return_value = {
            "exit_code": 1, "stdout": "", "stderr": "connection refused", "timed_out": False,
            "duration_ms": 50, "signal": None,
        }
        mock_make.return_value = (backend, self.config.hosts["web1"])
        result = self.service.ssh_test({"target": "web1"})
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "fail")

    @patch("flyssh_mcp.tools.ToolService._make_backend")
    def test_ssh_view_file(self, mock_make: MagicMock) -> None:
        backend = self._mock_backend()
        backend.exec_script.return_value = {
            "exit_code": 0, "stdout": "FILE\t12\t2\x00hello\nworld\n", "stderr": "",
            "timed_out": False, "duration_ms": 10, "signal": None,
        }
        mock_make.return_value = (backend, self.config.hosts["web1"])
        result = self.service.ssh_view({"target": "web1", "path": "/tmp/test.txt"})
        self.assertTrue(result["ok"])
        self.assertFalse(result["is_directory"])
        self.assertEqual(result["content"], "hello\nworld\n")
        self.assertEqual(result["size_bytes"], 12)

    @patch("flyssh_mcp.tools.ToolService._make_backend")
    def test_ssh_view_directory(self, mock_make: MagicMock) -> None:
        backend = self._mock_backend()
        backend.exec_script.return_value = {
            "exit_code": 0, "stdout": "DIR\x00f\t/etc/hosts\nd\t/etc/apt\n", "stderr": "",
            "timed_out": False, "duration_ms": 10, "signal": None,
        }
        mock_make.return_value = (backend, self.config.hosts["web1"])
        result = self.service.ssh_view({"target": "web1", "path": "/etc"})
        self.assertTrue(result["ok"])
        self.assertTrue(result["is_directory"])
        self.assertEqual(len(result["entries"]), 2)
        self.assertEqual(result["entries"][0]["type"], "file")
        self.assertEqual(result["entries"][1]["type"], "directory")

    @patch("flyssh_mcp.tools.ToolService._make_backend")
    def test_ssh_view_not_found(self, mock_make: MagicMock) -> None:
        backend = self._mock_backend()
        backend.exec_script.return_value = {
            "exit_code": 21, "stdout": "", "stderr": "", "timed_out": False,
            "duration_ms": 10, "signal": None,
        }
        mock_make.return_value = (backend, self.config.hosts["web1"])
        with self.assertRaises(RemoteFileError):
            self.service.ssh_view({"target": "web1", "path": "/nonexistent"})

    @patch("flyssh_mcp.tools.ToolService._make_backend")
    def test_ssh_create(self, mock_make: MagicMock) -> None:
        backend = self._mock_backend()
        mock_make.return_value = (backend, self.config.hosts["web1"])
        result = self.service.ssh_create({"target": "web1", "path": "/tmp/new.txt", "content": "hello"})
        self.assertTrue(result["ok"])
        self.assertEqual(result["bytes_written"], 5)

    @patch("flyssh_mcp.tools.ToolService._make_backend")
    def test_ssh_create_already_exists(self, mock_make: MagicMock) -> None:
        backend = self._mock_backend()
        backend.exec_script.return_value = {
            "exit_code": 24, "stdout": "", "stderr": "", "timed_out": False,
            "duration_ms": 10, "signal": None,
        }
        mock_make.return_value = (backend, self.config.hosts["web1"])
        with self.assertRaises(RemoteFileError):
            self.service.ssh_create({"target": "web1", "path": "/tmp/exists.txt", "content": "hello"})

    @patch("flyssh_mcp.tools.ToolService._make_backend")
    def test_ssh_edit(self, mock_make: MagicMock) -> None:
        backend = self._mock_backend()
        # First call: read (returns content), second call: write (returns success)
        backend.exec_script.side_effect = [
            {"exit_code": 0, "stdout": "hello world", "stderr": "", "timed_out": False, "duration_ms": 10, "signal": None},
            {"exit_code": 0, "stdout": "", "stderr": "", "timed_out": False, "duration_ms": 10, "signal": None},
        ]
        mock_make.return_value = (backend, self.config.hosts["web1"])
        result = self.service.ssh_edit({"target": "web1", "path": "/tmp/test.txt", "edits": [{"old_str": "world", "new_str": "WORLD"}]})
        self.assertTrue(result["ok"])
        self.assertEqual(result["edits_applied"], 1)

    @patch("flyssh_mcp.tools.ToolService._make_backend")
    def test_ssh_edit_no_match(self, mock_make: MagicMock) -> None:
        backend = self._mock_backend()
        backend.exec_script.return_value = {
            "exit_code": 0, "stdout": "hello world", "stderr": "", "timed_out": False,
            "duration_ms": 10, "signal": None,
        }
        mock_make.return_value = (backend, self.config.hosts["web1"])
        with self.assertRaises(RemoteFileError):
            self.service.ssh_edit({"target": "web1", "path": "/tmp/test.txt", "edits": [{"old_str": "nonexistent", "new_str": "x"}]})

    @patch("flyssh_mcp.tools.ToolService._make_backend")
    def test_ssh_grep_files_with_matches(self, mock_make: MagicMock) -> None:
        backend = self._mock_backend()
        backend.exec_script.return_value = {
            "exit_code": 0, "stdout": "/etc/hosts\n/etc/passwd\n", "stderr": "",
            "timed_out": False, "duration_ms": 10, "signal": None,
        }
        mock_make.return_value = (backend, self.config.hosts["web1"])
        result = self.service.ssh_grep({"target": "web1", "pattern": "root", "path": "/etc", "output_mode": "files_with_matches"})
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["matches"]), 2)

    @patch("flyssh_mcp.tools.ToolService._make_backend")
    def test_ssh_glob(self, mock_make: MagicMock) -> None:
        backend = self._mock_backend()
        backend.exec_script.return_value = {
            "exit_code": 0, "stdout": "./hosts\n./hostname\n./passwd\n", "stderr": "",
            "timed_out": False, "duration_ms": 10, "signal": None,
        }
        mock_make.return_value = (backend, self.config.hosts["web1"])
        result = self.service.ssh_glob({"target": "web1", "pattern": "host*", "path": "/etc"})
        self.assertTrue(result["ok"])
        self.assertIn("hosts", result["matches"])
        self.assertIn("hostname", result["matches"])
        self.assertNotIn("passwd", result["matches"])

    @patch("flyssh_mcp.tools.ToolService._make_backend")
    def test_ssh_scp_upload(self, mock_make: MagicMock) -> None:
        backend = self._mock_backend()
        backend.scp.return_value = {
            "exit_code": 0, "stdout": "", "stderr": "", "timed_out": False,
            "duration_ms": 100, "signal": None,
        }
        mock_make.return_value = (backend, self.config.hosts["web1"])
        # Create a local file
        local = Path(self.tmpdir) / "local.txt"
        local.write_text("test", encoding="utf-8")
        result = self.service.ssh_scp({"target": "web1", "direction": "upload", "sources": [str(local)], "destination": "/remote/path"})
        self.assertTrue(result["ok"])
        self.assertEqual(result["direction"], "upload")

    @patch("flyssh_mcp.tools.ToolService._make_backend")
    def test_ssh_scp_invalid_direction(self, mock_make: MagicMock) -> None:
        with self.assertRaises(ValidationError):
            self.service.ssh_scp({"target": "web1", "direction": "sideways", "sources": ["a"], "destination": "b"})

    def test_ssh_list_sessions_empty(self) -> None:
        result = self.service.ssh_list_sessions({})
        self.assertEqual(result["count"], 0)


if __name__ == "__main__":
    unittest.main()
