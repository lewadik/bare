"""Repository behaviour: packs, snapshots, retention hooks, GC, recovery."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import unittest
import unittest.mock
import uuid
from pathlib import Path

from tests import __doc__ as _tests_package  # noqa: F401

from haven.chunker import ChunkParams
from haven.codec import encode
from haven.errors import (
    ConflictError,
    IntegrityError,
    NotFoundError,
    ObjectMissing,
    RepositoryError,
    UsageError,
)
from haven.manifest import make_manifest, new_snapshot_id, sign_manifest
from haven.packfile import write_pack_file
from haven.retention import RetentionPolicy
from haven.server.store import Repository

SECRET = b"\x33" * 32


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="haven-store-"))
        self.repo = Repository.create(self.tmp / "repo", name="test", secret=SECRET)

    def tearDown(self):
        self.repo.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- helpers ----------------------------------------------------------
    def _pack(self, payloads: list[bytes]) -> tuple[Path, str, list[list]]:
        objects = []
        refs: list[list] = []
        for payload in payloads:
            flags, data = encode(payload, 1, 6)
            objects.append((sha(payload), flags, len(payload), data))
            refs.append([sha(payload), len(payload)])
        path = self.tmp / f"upload-{uuid.uuid4().hex}.pack"
        pack_id, _count, _size = write_pack_file(path, objects)
        return path, pack_id, refs

    def _install(self, payloads: list[bytes]) -> list[list]:
        path, pack_id, refs = self._pack(payloads)
        result = self.repo.install_pack(path, expected_id=pack_id)
        self.assertFalse(result["duplicate"])
        return refs

    def _manifest(self, files: dict[str, list[list]], *, snapshot_id: str | None = None, host: str = "web-01", secret: bytes = SECRET) -> dict:
        entries = [{"p": "data", "t": "d", "m": 0o755, "mt": 0.0, "u": 0, "g": 0}]
        for name, refs in files.items():
            entries.append(
                {
                    "p": f"data/{name}",
                    "t": "f",
                    "m": 0o644,
                    "mt": 0.0,
                    "u": 0,
                    "g": 0,
                    "s": sum(length for _obj, length in refs),
                    "c": [[obj, length] for obj, length in refs],
                }
            )
        return make_manifest(
            snapshot_id=snapshot_id or new_snapshot_id(),
            host=host,
            paths=["/data"],
            entries=entries,
            chunker=ChunkParams(),
            codec="zlib:6",
            excludes=[],
            stats={"files": len(files)},
            secret=secret,
        )

    # -- packs ------------------------------------------------------------
    def test_pack_lifecycle(self):
        payload = b"hello haven" * 100
        refs = self._install([payload])
        obj_id = refs[0][0]
        self.assertEqual(self.repo.object_exists([obj_id, "0" * 64]), [obj_id])
        located, missing = self.repo.locate([obj_id])
        self.assertEqual(missing, [])
        pack_id, offset, length, flags, plainlen = located[obj_id]
        raw = self.repo.read_range(pack_id, offset, length)
        self.assertEqual(len(raw), length)
        self.assertEqual((flags, plainlen), (1, len(payload)))
        self.assertEqual(self.repo.stats()["objects"], 1)

    def test_duplicate_pack_is_idempotent(self):
        path, pack_id, _refs = self._pack([b"same bytes"])
        first = self.repo.install_pack(path, expected_id=pack_id)
        self.assertFalse(first["duplicate"])
        path2, pack_id2, _ = self._pack([b"same bytes"])
        self.assertEqual(pack_id, pack_id2)
        second = self.repo.install_pack(path2, expected_id=pack_id2)
        self.assertTrue(second["duplicate"])
        self.assertEqual(self.repo.stats()["objects"], 1)

    def test_corrupt_object_rejected(self):
        payload = b"liar"
        wrong = sha(b"different")
        path = self.tmp / "bad.pack"
        write_pack_file(path, [(wrong, 0, len(payload), payload)])
        with self.assertRaises(IntegrityError):
            self.repo.install_pack(path)
        self.assertEqual(self.repo.stats()["objects"], 0)
        self.assertEqual(list((self.tmp / "repo" / "packs").glob("*.pack")), [])

    def test_expected_id_mismatch_rejected(self):
        path, _pack_id, _ = self._pack([b"abc"])
        with self.assertRaises(IntegrityError):
            self.repo.install_pack(path, expected_id="0" * 64)
        self.assertEqual(self.repo.stats()["objects"], 0)

    def test_read_range_bounds(self):
        refs = self._install([b"abc" * 1000])
        located, _ = self.repo.locate([refs[0][0]])
        pack_id, offset, length, _flags, _plainlen = located[refs[0][0]]
        pack_size = (self.tmp / "repo" / "packs" / f"{pack_id}.pack").stat().st_size
        with self.assertRaises(UsageError):
            self.repo.read_range(pack_id, 0, pack_size + 1)
        with self.assertRaises(UsageError):
            self.repo.read_range("../etc", 0, 10)
        with self.assertRaises(NotFoundError):
            self.repo.read_range("a" * 64, 0, 10)

    # -- snapshots --------------------------------------------------------
    def test_snapshot_lifecycle(self):
        refs = self._install([b"file body"])
        manifest = self._manifest({"a.txt": refs})
        result = self.repo.put_snapshot(manifest)
        self.assertEqual(result["id"], manifest["id"])
        again = self.repo.put_snapshot(manifest)
        self.assertTrue(again["existing"])
        loaded = self.repo.get_snapshot(manifest["id"])
        self.assertEqual(loaded["id"], manifest["id"])
        listing = self.repo.list_snapshots()
        self.assertEqual(len(listing), 1)
        self.assertEqual(listing[0]["host"], "web-01")
        self.repo.delete_snapshot(manifest["id"])
        with self.assertRaises(NotFoundError):
            self.repo.get_snapshot(manifest["id"])
        self.assertEqual(self.repo.list_snapshots(), [])

    def test_snapshot_requires_its_objects(self):
        manifest = self._manifest({"a.txt": [["b" * 64, 4]]})
        with self.assertRaises(ObjectMissing):
            self.repo.put_snapshot(manifest)
        self.assertEqual(self.repo.list_snapshots(), [])

    def test_snapshot_rejects_bad_signature(self):
        refs = self._install([b"body"])
        good = self._manifest({"a.txt": refs})
        bad = sign_manifest({key: value for key, value in good.items() if key != "signature"}, b"\x44" * 32)
        with self.assertRaises(IntegrityError):
            self.repo.put_snapshot(bad)

    def test_snapshot_conflict_on_different_content(self):
        refs = self._install([b"body"])
        snapshot_id = new_snapshot_id()
        self.repo.put_snapshot(self._manifest({"a.txt": refs}, snapshot_id=snapshot_id))
        other = self._manifest({"b.txt": refs}, snapshot_id=snapshot_id)
        with self.assertRaises(ConflictError):
            self.repo.put_snapshot(other)

    # -- prune / gc -------------------------------------------------------
    def test_prune_keeps_newest(self):
        refs = self._install([b"body"])
        ids = []
        for _ in range(3):
            manifest = self._manifest({"a.txt": refs})
            self.repo.put_snapshot(manifest)
            ids.append(manifest["id"])
        policy = RetentionPolicy(keep_last=1, keep_daily=0, keep_weekly=0, keep_monthly=0)
        report = self.repo.prune(policy, apply=True)
        self.assertEqual(report["deleted"], sorted(ids[:2]))
        remaining = self.repo.list_snapshots()
        self.assertEqual(len(remaining), 1)

    def test_gc_removes_dead_packs(self):
        refs_a = self._install([b"alpha" * 500])
        refs_b = self._install([b"beta" * 500])
        first = self._manifest({"a.txt": refs_a})
        second = self._manifest({"b.txt": refs_b})
        self.repo.put_snapshot(first)
        self.repo.put_snapshot(second)
        self.repo.delete_snapshot(first["id"])
        report = self.repo.gc(apply=True, min_age_hours=0)
        self.assertEqual(report["dead_packs"], 1)
        self.assertEqual(len(report["deleted"]), 1)
        self.assertEqual(len(self.repo.pack_ids()), 1)
        self.assertEqual(self.repo.object_exists([refs_a[0][0]]), [])
        self.assertEqual(self.repo.object_exists([refs_b[0][0]]), [refs_b[0][0]])

    def test_gc_repacks_partially_live_pack(self):
        shared = b"shared-chunk" * 200
        only_first = b"only-in-first" * 200
        refs = self._install([shared, only_first])
        first = self._manifest({"a.txt": refs})
        second = self._manifest({"b.txt": [refs[0]]})
        self.repo.put_snapshot(first)
        self.repo.put_snapshot(second)
        self.repo.delete_snapshot(first["id"])
        report = self.repo.gc(apply=True, min_age_hours=0)
        self.assertEqual(report["dead_packs"], 0)
        self.assertEqual(report["partial_packs"], 1)
        self.assertEqual(len(report["repacked"]), 1)
        self.assertEqual(self.repo.object_exists([refs[0][0]]), [refs[0][0]])
        self.assertEqual(self.repo.object_exists([refs[1][0]]), [])
        # the surviving snapshot must still be fully readable
        located, missing = self.repo.locate([refs[0][0]])
        self.assertEqual(missing, [])
        pack_id, offset, length, _flags, _plainlen = located[refs[0][0]]
        self.assertGreater(len(self.repo.read_range(pack_id, offset, length)), 0)

    def test_gc_respects_min_age(self):
        refs = self._install([b"young"])
        manifest = self._manifest({"a.txt": refs})
        self.repo.put_snapshot(manifest)
        self.repo.delete_snapshot(manifest["id"])
        report = self.repo.gc(apply=True, min_age_hours=1)
        self.assertEqual(report["dead_packs"], 0)
        self.assertEqual(len(self.repo.pack_ids()), 1)

    def test_gc_dry_run_changes_nothing(self):
        refs = self._install([b"orphan"])
        report = self.repo.gc(apply=False, min_age_hours=0)
        self.assertEqual(report["dead_packs"], 1)
        self.assertEqual(len(self.repo.pack_ids()), 1)

    # -- recovery / verification -----------------------------------------
    def test_index_rebuild_after_state_loss(self):
        refs = self._install([b"payload" * 100])
        manifest = self._manifest({"a.txt": refs})
        self.repo.put_snapshot(manifest)
        self.repo.close()
        (self.tmp / "repo" / "state" / "index.sqlite").unlink()
        for suffix in ("-wal", "-shm"):
            (self.tmp / "repo" / "state" / f"index.sqlite{suffix}").unlink(missing_ok=True)
        repo = Repository(self.tmp / "repo", SECRET)
        try:
            self.assertEqual(repo.object_exists([refs[0][0]]), [refs[0][0]])
            self.assertEqual(repo.stats()["snapshots"], 1)
            report = repo.verify(deep=True)
            self.assertTrue(report["ok"], report["errors"])
        finally:
            repo.close()
            self.repo = repo  # so tearDown closes the right instance

    def test_verify_detects_corruption(self):
        refs = self._install([b"payload" * 100])
        self.repo.put_snapshot(self._manifest({"a.txt": refs}))
        self.assertTrue(self.repo.verify(deep=True)["ok"])
        pack_id = self.repo.pack_ids()[0]
        path = self.tmp / "repo" / "packs" / f"{pack_id}.pack"
        raw = bytearray(path.read_bytes())
        raw[30] ^= 0xFF
        path.write_bytes(bytes(raw))
        report = self.repo.verify(deep=True)
        self.assertFalse(report["ok"])
        self.assertTrue(any("pack" in error for error in report["errors"]))

    def test_rotate_secret_resigns_manifests(self):
        refs = self._install([b"body"])
        manifest = self._manifest({"a.txt": refs})
        self.repo.put_snapshot(manifest)
        new_secret = b"\x77" * 32
        report = self.repo.rotate_secret(new_secret)
        self.assertEqual(report["resigned"], 1)
        # the rotated repository verifies the new signature
        self.assertEqual(self.repo.get_snapshot(manifest["id"])["id"], manifest["id"])
        # a handle still holding the old secret does not
        stale = Repository(self.tmp / "repo", SECRET)
        try:
            with self.assertRaises(IntegrityError):
                stale.get_snapshot(manifest["id"])
        finally:
            stale.close()
        self.repo.close()
        reopened = Repository(self.tmp / "repo", new_secret)
        try:
            self.assertEqual(len(reopened.list_snapshots()), 1)
        finally:
            reopened.close()
            self.repo = reopened

    # -- integrity of the destructive paths -------------------------------
    def test_gc_refuses_to_run_on_a_tampered_manifest(self):
        refs = self._install([b"payload-kept-alive" * 100])
        manifest = self._manifest({"a.txt": refs})
        self.repo.put_snapshot(manifest)
        # Remove the only reference without re-signing: the HMAC no longer matches.
        path = self.tmp / "repo" / "snapshots" / f"{manifest['id']}.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["entries"] = [entry for entry in document["entries"] if entry["t"] == "d"]
        path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(RepositoryError):
            self.repo.gc(apply=True, min_age_hours=0)
        self.assertEqual(self.repo.object_exists([refs[0][0]]), [refs[0][0]])
        self.assertEqual(len(self.repo.pack_ids()), 1)

    def test_prune_refuses_to_run_on_a_tampered_manifest(self):
        refs = self._install([b"payload" * 100])
        manifest = self._manifest({"a.txt": refs})
        self.repo.put_snapshot(manifest)
        path = self.tmp / "repo" / "snapshots" / f"{manifest['id']}.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["host"] = "attacker"
        path.write_text(json.dumps(document), encoding="utf-8")
        policy = RetentionPolicy(keep_last=1, keep_daily=0, keep_weekly=0, keep_monthly=0)
        with self.assertRaises(RepositoryError):
            self.repo.prune(policy, apply=True)
        self.assertEqual(len(self.repo.list_snapshots()), 1)

    def test_gc_rejects_non_finite_age(self):
        refs = self._install([b"payload"])
        self.repo.put_snapshot(self._manifest({"a.txt": refs}))
        with self.assertRaises(UsageError):
            self.repo.gc(apply=True, min_age_hours=float("nan"))
        with self.assertRaises(UsageError):
            self.repo.gc(apply=True, min_age_hours=float("inf"))

    def test_rotate_secret_is_resumable(self):
        refs = self._install([b"body"])
        for index in range(2):
            self.repo.put_snapshot(self._manifest({f"f{index}.txt": refs}))
        new_secret = b"\x55" * 32
        real_replace = os.replace
        renames = {"snapshots": 0}

        def flaky_replace(source, target):
            source_name, target_name = str(source), str(target)
            is_snapshot_rename = (
                source_name.endswith(".json.new")
                and target_name.endswith(".json")
                and not target_name.endswith(".meta.json")
            )
            if is_snapshot_rename:
                renames["snapshots"] += 1
                if renames["snapshots"] == 2:  # fail after one manifest moved
                    raise OSError("simulated crash")
            return real_replace(source, target)

        with unittest.mock.patch("haven.server.store.os.replace", side_effect=flaky_replace):
            with self.assertRaises(RepositoryError):
                self.repo.rotate_secret(new_secret)
        report = self.repo.rotate_secret(new_secret)
        self.assertGreaterEqual(report["already_signed"], 1)
        self.assertEqual(report["resigned"] + report["already_signed"], 2)
        for summary in self.repo.list_snapshots():
            self.assertTrue(self.repo.get_snapshot(summary["id"])["id"])

    def test_metrics_text(self):
        refs = self._install([b"payload"])
        self.repo.put_snapshot(self._manifest({"a.txt": refs}))
        text = self.repo.metrics_text()
        self.assertIn("haven_repo_objects 1", text)
        self.assertIn('haven_snapshots{host="web-01"} 1', text)

    def test_info(self):
        info = self.repo.info()
        self.assertEqual(info["format"], 1)
        self.assertEqual(info["name"], "test")
        self.assertEqual(len(info["key_id"]), 16)


if __name__ == "__main__":
    unittest.main()
