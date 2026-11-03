from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from flyssh_mcp.config import Config, HostEntry
from flyssh_mcp.errors import ConfigError, ValidationError


class ConfigLoadingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.config_path = Path(self.tmpdir) / "config.json"

    def _write_config(self, data: dict) -> Path:
        self.config_path.write_text(json.dumps(data), encoding="utf-8")
        return self.config_path

    def test_load_valid_config(self) -> None:
        self._write_config({
            "hosts": {
                "web1": {"host": "10.0.0.1", "port": 22, "user": "admin", "password": "secret"},
            },
            "defaults": {"connect_timeout": 5, "exec_timeout": 20},
            "plink_path": "plink",
            "sshpass_path": "sshpass",
        })
        config = Config.load(self.config_path)
        self.assertEqual(len(config.hosts), 1)
        self.assertIn("web1", config.hosts)
        self.assertEqual(config.hosts["web1"].host, "10.0.0.1")
        self.assertEqual(config.hosts["web1"].port, 22)
        self.assertEqual(config.hosts["web1"].user, "admin")
        self.assertEqual(config.hosts["web1"].password, "secret")
        self.assertEqual(config.defaults["connect_timeout"], 5)

    def test_load_missing_config_creates_template(self) -> None:
        path = Path(self.tmpdir) / "subdir" / "config.json"
        with self.assertRaises(ConfigError) as ctx:
            Config.load(path)
        self.assertIn("created an empty template", str(ctx.exception))
        self.assertTrue(path.exists())

    def test_load_invalid_json(self) -> None:
        self.config_path.write_text("not json", encoding="utf-8")
        with self.assertRaises(ConfigError):
            Config.load(self.config_path)

    def test_load_non_object_json(self) -> None:
        self._write_config([1, 2, 3])
        with self.assertRaises(ConfigError):
            Config.load(self.config_path)

    def test_load_hosts_not_object(self) -> None:
        self._write_config({"hosts": [1, 2]})
        with self.assertRaises(ConfigError):
            Config.load(self.config_path)

    def test_load_host_missing_host_field(self) -> None:
        self._write_config({"hosts": {"web1": {"port": 22}}})
        with self.assertRaises(ConfigError):
            Config.load(self.config_path)


class AliasResolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.config_path = Path(self.tmpdir) / "config.json"
        self.config_path.write_text(json.dumps({
            "hosts": {
                "web1": {"host": "10.0.0.1", "port": 2222, "user": "admin", "password": "pw1"},
                "web2": {"host": "10.0.0.2", "port": 22, "user": "root", "password": "pw2"},
            },
        }), encoding="utf-8")
        self.config = Config.load(self.config_path)

    def test_resolve_alias(self) -> None:
        entry = self.config.resolve_target("web1")
        self.assertEqual(entry.host, "10.0.0.1")
        self.assertEqual(entry.port, 2222)
        self.assertEqual(entry.user, "admin")
        self.assertEqual(entry.password, "pw1")

    def test_resolve_user_at_host_port(self) -> None:
        entry = self.config.resolve_target("admin@10.0.0.1:2222")
        self.assertEqual(entry.host, "10.0.0.1")
        self.assertEqual(entry.port, 2222)
        self.assertEqual(entry.user, "admin")
        # Password should be found from matching host entry
        self.assertEqual(entry.password, "pw1")

    def test_resolve_host_port_no_user(self) -> None:
        entry = self.config.resolve_target("10.0.0.2:22")
        self.assertEqual(entry.host, "10.0.0.2")
        self.assertEqual(entry.port, 22)
        self.assertEqual(entry.user, "root")
        self.assertEqual(entry.password, "pw2")

    def test_resolve_unknown_host_no_password(self) -> None:
        entry = self.config.resolve_target("user@10.0.0.99:22")
        self.assertEqual(entry.host, "10.0.0.99")
        self.assertEqual(entry.user, "user")
        self.assertEqual(entry.password, "")

    def test_resolve_invalid_port(self) -> None:
        with self.assertRaises(ValidationError):
            self.config.resolve_target("user@host:notaport")


class HotReloadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.config_path = Path(self.tmpdir) / "config.json"
        self.config_path.write_text(json.dumps({
            "hosts": {"web1": {"host": "10.0.0.1", "port": 22, "user": "admin", "password": "pw1"}},
        }), encoding="utf-8")
        self.config = Config.load(self.config_path)

    def test_no_reload_when_mtime_unchanged(self) -> None:
        reloaded = self.config.maybe_reload()
        self.assertIs(reloaded, self.config)

    def test_reload_when_mtime_changes(self) -> None:
        import time
        time.sleep(0.1)
        self.config_path.write_text(json.dumps({
            "hosts": {
                "web1": {"host": "10.0.0.1", "port": 22, "user": "admin", "password": "pw1"},
                "web2": {"host": "10.0.0.2", "port": 22, "user": "root", "password": "pw2"},
            },
        }), encoding="utf-8")
        reloaded = self.config.maybe_reload()
        self.assertIsNot(reloaded, self.config)
        self.assertEqual(len(reloaded.hosts), 2)


class SafeSummaryTests(unittest.TestCase):
    def test_safe_summary_excludes_password(self) -> None:
        entry = HostEntry(alias="web1", host="10.0.0.1", port=22, user="admin", password="secret")
        summary = entry.safe_summary()
        self.assertNotIn("password", summary)
        self.assertEqual(summary["alias"], "web1")
        self.assertEqual(summary["host"], "10.0.0.1")


if __name__ == "__main__":
    unittest.main()
