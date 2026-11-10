"""Security properties: auth, input limits, tamper detection, restore escapes."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlsplit

from tests import __doc__ as _tests_package  # noqa: F401
from tests.helpers import SECRET, Harness, make_tree, rel_prefix

from haven.backup import BackupOptions, BackupRunner
from haven.chunker import ChunkParams
from haven.errors import (
    AuthError,
    ConfigError,
    ForbiddenError,
    IntegrityError,
    NotFoundError,
    ObjectMissing,
    TooLargeError,
    UsageError,
)
from haven.manifest import make_manifest, new_snapshot_id, sign_manifest
from haven.packfile import write_pack_file
from haven.restore import RestoreOptions, RestoreRunner
from haven.transport import RemoteRepo
from haven.util import canonical_json, sha256_file

POSIX = os.name == "posix"


def raw_request(url: str, method: str, path: str, body: bytes | None = None, headers: dict | None = None):
    parts = urlsplit(url)
    connection = http.client.HTTPConnection(parts.hostname, parts.port, timeout=20)
    try:
        all_headers = {"Content-Length": str(len(body) if body else 0)}
        all_headers.update(headers or {})
        connection.request(method, path, body=body, headers=all_headers)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="haven-sec-"))
        self.harness = Harness(self.tmp).start()
        self.api = self.harness.api()
        self.backup_api = self.harness.api(self.harness.backup_token)
        self.source = make_tree(self.tmp / "source")
        self.client = self.harness.client(cache=self.tmp / "cache.sqlite")

    def tearDown(self):
        try:
            self.harness.stop()
        finally:
            shutil.rmtree(self.tmp, ignore_errors=True)

    # -- authentication ---------------------------------------------------
    def test_health_is_public(self):
        status, body = raw_request(self.harness.url, "GET", "/v1/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "ok")

    def test_missing_token_is_rejected(self):
        status, body = raw_request(self.harness.url, "GET", "/v1/repo")
        self.assertEqual(status, 401)
        self.assertIn("unauthorized", body.decode())

    def test_bad_token_is_rejected(self):
        status, _body = raw_request(
            self.harness.url, "GET", "/v1/repo", headers={"Authorization": "Bearer nope"}
        )
        self.assertEqual(status, 401)
        with self.assertRaises(AuthError):
            self.harness.api("hvn_wrong").repo_info()

    def test_backup_token_cannot_run_admin_tasks(self):
        self.assertTrue(self.backup_api.repo_info()["repo_id"])
        with self.assertRaises(ForbiddenError):
            self.backup_api.gc(apply=False)
        with self.assertRaises(ForbiddenError):
            self.backup_api.prune({"keep_last": 1}, apply=False)
        with self.assertRaises(ForbiddenError):
            self.backup_api.metrics()

    def test_revoked_token_stops_working(self):
        # Tokens created through the daemon's own store are live immediately;
        # a file added behind its back needs `systemctl reload` (SIGHUP).
        token = self.harness.server.tokens.add("temporary", ["backup"])
        api = self.harness.api(token)
        self.assertTrue(api.repo_info()["repo_id"])
        self.harness.server.tokens.revoke("temporary")
        with self.assertRaises(AuthError):
            api.repo_info()

    # -- limits / tampering ----------------------------------------------
    def test_oversized_upload_rejected(self):
        tmp = Path(tempfile.mkdtemp(prefix="haven-sec-small-"))
        try:
            harness = Harness(tmp, max_pack_bytes=2048).start()
            try:
                payload = b"x" * 100_000
                pack = tmp / "big.pack"
                write_pack_file(pack, [(hashlib.sha256(b"y").hexdigest(), 0, len(payload), payload)])
                api = harness.api()
                with self.assertRaises(TooLargeError):
                    api.upload_pack(pack, expected_id=sha256_file(pack))
            finally:
                harness.stop()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_tampered_pack_rejected(self):
        pack = self.tmp / "pack.pack"
        payload = b"important data"
        pack_id, _count, _size = write_pack_file(
            pack, [(hashlib.sha256(payload).hexdigest(), 0, len(payload), payload)]
        )
        raw = bytearray(pack.read_bytes())
        raw[-40] ^= 0xFF
        pack.write_bytes(bytes(raw))
        with self.assertRaises(IntegrityError):
            self.api.upload_pack(pack, expected_id=pack_id)
        self.assertEqual(self.harness.repo.pack_ids(), [])

    def test_pack_with_lying_object_id_rejected(self):
        pack = self.tmp / "liar.pack"
        payload = b"payload"
        pack_id, _count, _size = write_pack_file(
            pack, [(hashlib.sha256(b"other").hexdigest(), 0, len(payload), payload)]
        )
        with self.assertRaises(IntegrityError):
            self.api.upload_pack(pack, expected_id=pack_id)
        self.assertEqual(self.harness.repo.pack_ids(), [])

    def test_pack_path_traversal_rejected(self):
        status, _body = raw_request(
            self.harness.url,
            "GET",
            "/v1/packs/../../etc/passwd?offset=0&length=10",
            headers={"Authorization": f"Bearer {self.harness.token}"},
        )
        self.assertIn(status, (400, 404))

    # -- manifests --------------------------------------------------------
    def _signed(self, entries, *, secret: bytes = SECRET) -> dict:
        return make_manifest(
            snapshot_id=new_snapshot_id(),
            host="attacker",
            paths=["/etc"],
            entries=entries,
            chunker=ChunkParams(),
            codec="zlib:6",
            excludes=[],
            stats={},
            secret=secret,
        )

    def test_manifest_with_traversal_rejected_by_server(self):
        entries = [
            {"p": "../../etc/cron.d/pwn", "t": "f", "m": 0o644, "mt": 0.0, "s": 4, "c": [["a" * 64, 4]]}
        ]
        with self.assertRaises(ConfigError):
            self.api.put_snapshot(self._signed(entries))
        self.assertEqual(self.harness.repo.list_snapshots(), [])

    def test_manifest_with_absolute_path_rejected(self):
        entries = [{"p": "/etc/shadow", "t": "f", "m": 0o644, "mt": 0.0, "s": 4, "c": [["a" * 64, 4]]}]
        with self.assertRaises(ConfigError):
            self.api.put_snapshot(self._signed(entries))

    def test_manifest_signed_with_wrong_secret_rejected(self):
        entries = [{"p": "etc/hosts", "t": "f", "m": 0o644, "mt": 0.0, "s": 4, "c": [["a" * 64, 4]]}]
        with self.assertRaises(IntegrityError):
            self.api.put_snapshot(self._signed(entries, secret=b"\x99" * 32))

    def test_manifest_with_missing_objects_rejected(self):
        entries = [{"p": "etc/hosts", "t": "f", "m": 0o644, "mt": 0.0, "s": 4, "c": [["b" * 64, 4]]}]
        with self.assertRaises(ObjectMissing):
            self.api.put_snapshot(self._signed(entries))
        self.assertEqual(self.harness.repo.list_snapshots(), [])

    def test_unknown_snapshot_returns_404(self):
        with self.assertRaises(NotFoundError):
            self.api.get_snapshot("20260101T000000Z-deadbeef")

    def test_snapshot_id_traversal_returns_404(self):
        status, _body = raw_request(
            self.harness.url,
            "GET",
            "/v1/snapshots/..%2F..%2Fetc%2Fpasswd",
            headers={"Authorization": f"Bearer {self.harness.token}"},
        )
        self.assertIn(status, (400, 404))

    # -- restore escapes --------------------------------------------------
    @unittest.skipUnless(POSIX, "needs real symlinks")
    def test_restore_refuses_symlink_escape(self):
        runner = BackupRunner(
            self.harness.api(), self.client, BackupOptions(sources=[str(self.source)])
        )
        result = runner.run()
        manifest = self.harness.api().get_snapshot(result["snapshot"])
        chunk = None
        for entry in manifest["entries"]:
            if entry.get("t") == "f" and entry.get("c"):
                chunk = entry["c"][0]
                break
        self.assertIsNotNone(chunk)
        outside = self.tmp / "outside"
        outside.mkdir()
        evil_entries = [
            {
                "p": "escape",
                "t": "l",
                "m": 0o777,
                "mt": 0.0,
                "u": 0,
                "g": 0,
                "tg": str(outside),
            },
            {
                "p": "escape/pwned",
                "t": "f",
                "m": 0o644,
                "mt": 0.0,
                "u": 0,
                "g": 0,
                "s": chunk[1],
                "c": [[chunk[0], chunk[1]]],
            },
        ]
        evil = self._signed(evil_entries)
        self.api.put_snapshot(evil)
        target = self.tmp / "restore-evil"
        outcome = RestoreRunner(
            self.harness.api(), evil, RestoreOptions(target=target, overwrite="always")
        ).run()
        self.assertFalse((outside / "pwned").exists())
        self.assertFalse(outcome["ok"])
        self.assertTrue(any("outside the restore target" in item for item in outcome["errors"]))

    @unittest.skipUnless(POSIX, "needs real symlinks")
    def test_restore_refuses_to_write_through_existing_symlink(self):
        runner = BackupRunner(
            self.harness.api(), self.client, BackupOptions(sources=[str(self.source)])
        )
        result = runner.run()
        manifest = self.harness.api().get_snapshot(result["snapshot"])
        outside = self.tmp / "outside2"
        outside.mkdir()
        target = self.tmp / "restore-linked"
        target.mkdir()
        base = target / rel_prefix(self.source)
        base.mkdir(parents=True, exist_ok=True)
        os.symlink(str(outside), base / "etc")
        outcome = RestoreRunner(
            self.harness.api(), manifest, RestoreOptions(target=target, overwrite="always")
        ).run()
        self.assertFalse((outside / "hosts").exists())
        self.assertFalse(outcome["ok"])

    # -- token file permissions -------------------------------------------
    @unittest.skipUnless(POSIX, "POSIX permissions only")
    def test_token_file_must_not_be_world_readable(self):
        from haven.server.auth import TokenStore
        from haven.errors import ConfigError

        path = self.tmp / "loose-tokens.json"
        shutil.copy(self.harness.tokens_file, path)
        os.chmod(path, 0o644)
        with self.assertRaises(ConfigError):
            TokenStore(path)


if __name__ == "__main__":
    unittest.main()
