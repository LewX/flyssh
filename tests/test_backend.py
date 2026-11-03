from __future__ import annotations

import unittest
from unittest.mock import patch, MagicMock

from flyssh_mcp.config import HostEntry
from flyssh_mcp.backend import PlinkBackend, SshpassBackend, make_backend
from flyssh_mcp.errors import BackendError


class PlinkBackendArgvTests(unittest.TestCase):
    def _make_backend(self, **kwargs) -> PlinkBackend:
        host = HostEntry(
            alias="web1", host="10.0.0.1", port=50163, user="testuser",
            password="testpass123", host_key="SHA256:abc",
        )
        with patch("flyssh_mcp.backend.resolve_binary", return_value="C:\\plink.exe"):
            return PlinkBackend(host, plink_path="plink", **kwargs)

    def test_base_argv_contains_port_password_hostkey(self) -> None:
        backend = self._make_backend()
        argv = backend._base_argv()
        self.assertIn("-P", argv)
        self.assertIn("50163", argv)
        self.assertIn("-pw", argv)
        self.assertIn("testpass123", argv)
        self.assertIn("-hostkey", argv)
        self.assertIn("SHA256:abc", argv)
        self.assertIn("-batch", argv)
        self.assertIn("testuser@10.0.0.1", argv)

    def test_exec_passes_remote_command(self) -> None:
        backend = self._make_backend()
        with patch("flyssh_mcp.backend._run_without_pty_binary_safe") as mock_run:
            mock_run.return_value = {"exit_code": 0, "stdout": "", "stderr": "", "timed_out": False, "duration_ms": 10, "signal": None}
            backend.exec("echo hello", timeout=5)
            call_args = mock_run.call_args
            argv = call_args[0][0]
            self.assertIn("echo hello", argv)
            self.assertEqual(argv[0], "C:\\plink.exe")

    def test_scp_upload_uses_pscp(self) -> None:
        backend = self._make_backend(pscp_path="C:\\pscp.exe")
        with patch("flyssh_mcp.backend.resolve_binary", return_value="C:\\pscp.exe"):
            with patch("flyssh_mcp.backend._run_without_pty") as mock_run:
                mock_run.return_value = {"exit_code": 0, "stdout": "", "stderr": "", "timed_out": False, "duration_ms": 10, "signal": None}
                backend.scp("upload", ["local.txt"], "/remote/path", timeout=5)
                argv = mock_run.call_args[0][0]
                self.assertEqual(argv[0], "C:\\pscp.exe")
                self.assertIn("local.txt", argv)
                self.assertIn("testuser@10.0.0.1:/remote/path", argv)


class SshpassBackendArgvTests(unittest.TestCase):
    def _make_backend(self) -> SshpassBackend:
        host = HostEntry(
            alias="web1", host="10.0.0.1", port=50163, user="testuser",
            password="testpass123",
        )
        with patch("flyssh_mcp.backend.resolve_binary", return_value="/usr/bin/sshpass"):
            return SshpassBackend(host, sshpass_path="sshpass")

    def test_ssh_argv_contains_sshpass_and_password(self) -> None:
        backend = self._make_backend()
        argv = backend._ssh_argv()
        self.assertEqual(argv[0], "/usr/bin/sshpass")
        self.assertEqual(argv[1], "-p")
        self.assertEqual(argv[2], "testpass123")
        self.assertEqual(argv[3], "ssh")
        self.assertIn("50163", argv)
        self.assertIn("testuser@10.0.0.1", argv)
        # Should have accept-new host key checking
        self.assertIn("StrictHostKeyChecking=accept-new", argv)

    def test_exec_passes_remote_command(self) -> None:
        backend = self._make_backend()
        with patch("flyssh_mcp.backend._run_without_pty_binary_safe") as mock_run:
            mock_run.return_value = {"exit_code": 0, "stdout": "", "stderr": "", "timed_out": False, "duration_ms": 10, "signal": None}
            backend.exec("echo hello", timeout=5)
            argv = mock_run.call_args[0][0]
            self.assertIn("echo hello", argv)

    def test_scp_download(self) -> None:
        backend = self._make_backend()
        with patch("flyssh_mcp.backend._run_without_pty") as mock_run:
            mock_run.return_value = {"exit_code": 0, "stdout": "", "stderr": "", "timed_out": False, "duration_ms": 10, "signal": None}
            backend.scp("download", ["/remote/file"], "local.txt", timeout=5)
            argv = mock_run.call_args[0][0]
            self.assertIn("testuser@10.0.0.1:/remote/file", argv)
            self.assertIn("local.txt", argv)


class MakeBackendTests(unittest.TestCase):
    def test_make_plink_backend(self) -> None:
        host = HostEntry(alias="web1", host="10.0.0.1", port=22, user="admin", password="pw")
        with patch("flyssh_mcp.backend.resolve_binary", return_value="plink"):
            backend = make_backend("plink", host, plink_path="plink", sshpass_path="sshpass")
            self.assertIsInstance(backend, PlinkBackend)

    def test_make_sshpass_backend(self) -> None:
        host = HostEntry(alias="web1", host="10.0.0.1", port=22, user="admin", password="pw")
        with patch("flyssh_mcp.backend.resolve_binary", return_value="/usr/bin/sshpass"):
            backend = make_backend("sshpass", host, plink_path="plink", sshpass_path="sshpass")
            self.assertIsInstance(backend, SshpassBackend)

    def test_make_unknown_backend(self) -> None:
        host = HostEntry(alias="web1", host="10.0.0.1", port=22, user="admin", password="pw")
        with self.assertRaises(BackendError):
            make_backend("telnet", host, plink_path="plink", sshpass_path="sshpass")


if __name__ == "__main__":
    unittest.main()
