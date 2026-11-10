"""End to end: backup over HTTP, incremental dedup, restore, prune, gc, CLI."""

from __future__ import annotations

import io
import json
import os
import shutil
import socket
import stat
import sys
import tempfile
import unittest
import unittest.mock
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from tests import __doc__ as _tests_package  # noqa: F401
from tests.helpers import Harness, make_tree, rel_prefix

from haven.backup import BackupOptions, BackupRunner, HookFailed
from haven.chunker import iter_chunks as real_iter_chunks
from haven.cli import main as cli_main
from haven.errors import IntegrityError, ObjectMissing, UsageError
from haven.manifest import new_snapshot_id
from haven.restore import RestoreOptions, RestoreRunner
from haven.transport import RemoteRepo

POSIX = os.name == "posix"


class E2EBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="haven-e2e-"))
        self.harness = Harness(self.tmp).start()
        self.client = self.harness.client(cache=self.tmp / "cache.sqlite")
        self.repo = RemoteRepo.from_config(self.client)
        self.source = make_tree(self.tmp / "source")
        self.logs: list[str] = []

    def tearDown(self):
        try:
            self.harness.stop()
        finally:
            shutil.rmtree(self.tmp, ignore_errors=True)

    def backup(self, **kwargs) -> dict:
        options = BackupOptions(sources=kwargs.pop("sources", [str(self.source)]), **kwargs)
        runner = BackupRunner(self.repo, self.client, options, log=self.logs.append)
        return runner.run()

    def restore(self, manifest: dict, target: Path, **kwargs) -> dict:
        runner = RestoreRunner(
            self.repo, manifest, RestoreOptions(target=target, **kwargs), log=self.logs.append
        )
        return runner.run()

    def expected_files(self) -> int:
        return sum(
            1 for path in self.source.rglob("*") if path.is_file() and not path.is_symlink()
        )

    def cli(self, *args: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli_main(self.harness.cli_args() + list(args))
        return code, out.getvalue(), err.getvalue()

    def assert_tree_restored(self, target: Path) -> None:
        base = target / rel_prefix(self.source)
        self.assertEqual((base / "etc" / "hosts").read_bytes(), (self.source / "etc" / "hosts").read_bytes())
        self.assertEqual((base / "etc" / "empty").read_bytes(), b"")
        self.assertEqual(
            (base / "var" / "blob.bin").read_bytes(), (self.source / "var" / "blob.bin").read_bytes()
        )
        self.assertEqual(
            (base / "unicode-\u00e9\u4e2d.txt").read_text(encoding="utf-8"),
            (self.source / "unicode-\u00e9\u4e2d.txt").read_text(encoding="utf-8"),
        )
        self.assertTrue((base / "etc" / "nested").is_dir())
        self.assertFalse((base / "etc" / "nested" / "app.conf").stat().st_size == 0)
        if (self.source / "current").is_symlink():
            self.assertTrue((base / "current").is_symlink())
            self.assertEqual(os.readlink(base / "current"), os.readlink(self.source / "current"))
        hardlink = self.source / "etc" / "hosts-hardlink"
        if hardlink.exists() and not hardlink.is_symlink():
            restored = base / "etc" / "hosts-hardlink"
            self.assertTrue(restored.exists())
            self.assertEqual(restored.read_bytes(), hardlink.read_bytes())
            if POSIX:
                self.assertEqual(restored.stat().st_ino, (base / "etc" / "hosts").stat().st_ino)
        if POSIX:
            self.assertEqual(
                stat.S_IMODE((base / "etc" / "hosts").stat().st_mode),
                stat.S_IMODE((self.source / "etc" / "hosts").stat().st_mode),
            )


class BackupRestoreTests(E2EBase):
    def test_round_trip(self):
        result = self.backup(label="nightly")
        self.assertIsNotNone(result["snapshot"])
        self.assertEqual(result["stats"]["files"], self.expected_files())
        self.assertGreater(result["upload"]["pack_bytes"], 0)
        manifest = self.repo.get_snapshot(result["snapshot"])
        self.assertEqual(manifest["host"], socket.gethostname())
        self.assertEqual(manifest["label"], "nightly")

        target = self.tmp / "restore"
        restore = self.restore(manifest, target)
        self.assertTrue(restore["ok"], restore["errors"])
        self.assertEqual(restore["errors"], [])
        self.assert_tree_restored(target)

    def test_second_run_uploads_nothing(self):
        first = self.backup()
        second = self.backup()
        self.assertEqual(second["stats"]["chunks_new"], 0)
        self.assertEqual(second["stats"]["bytes_new"], 0)
        self.assertEqual(second["upload"]["pack_bytes"], 0)
        self.assertEqual(second["stats"]["chunks_reused"], second["stats"]["chunks"])
        self.assertNotEqual(first["snapshot"], second["snapshot"])

    def test_incremental_after_edit(self):
        first = self.backup()
        before = (self.source / "var" / "blob.bin").stat().st_size
        with open(self.source / "var" / "blob.bin", "ab") as handle:
            handle.write(b"tail-bytes" * 40)
        second = self.backup()
        self.assertGreater(second["stats"]["chunks_new"], 0)
        self.assertLess(second["stats"]["chunks_new"], 5)
        self.assertGreater(second["stats"]["chunks_reused"], 0)
        self.assertGreater(second["stats"]["bytes_new"], 0)
        self.assertLess(second["stats"]["bytes_new"], second["stats"]["bytes_total"])
        manifest = self.repo.get_snapshot(second["snapshot"])
        target = self.tmp / "restore-incremental"
        outcome = self.restore(manifest, target)
        self.assertTrue(outcome["ok"], outcome["errors"])
        self.assert_tree_restored(target)
        self.assertEqual(
            (target / rel_prefix(self.source) / "var" / "blob.bin").stat().st_size, before + 400
        )

    def test_cache_hit_does_not_reupload_when_chunks_missing(self):
        self.backup()
        # Simulate a repository that lost its packs but kept the snapshots:
        # cached files must be re-read instead of committing a broken snapshot.
        packs = list((self.tmp / "repo" / "packs").glob("*.pack"))
        for pack in packs:
            pack.unlink()
        for index in (self.tmp / "repo" / "packs").glob("*.idx.json"):
            index.unlink()
        self.harness.repo.rebuild_index()
        second = self.backup()
        self.assertGreater(second["stats"]["chunks_new"], 0)
        manifest = self.repo.get_snapshot(second["snapshot"])
        target = self.tmp / "restore-after-loss"
        outcome = self.restore(manifest, target)
        self.assertTrue(outcome["ok"], outcome["errors"])
        self.assert_tree_restored(target)

    def test_overlapping_sources_are_not_duplicated(self):
        result = self.backup(sources=[str(self.source), str(self.source / "etc")])
        manifest = self.repo.get_snapshot(result["snapshot"])
        paths = [entry["p"] for entry in manifest["entries"]]
        self.assertEqual(len(paths), len(set(paths)))
        self.assertEqual(result["stats"]["files"], self.expected_files())

    def test_dry_run_writes_nothing(self):
        result = self.backup(dry_run=True)
        self.assertIsNone(result["snapshot"])
        self.assertEqual(self.repo.list_snapshots(), [])
        self.assertEqual(self.harness.repo.pack_ids(), [])

    def test_hooks_run(self):
        marker = self.tmp / "pre.ran"
        done = self.tmp / "post.ran"
        result = self.backup(
            pre_hook=f'echo pre > "{marker}"',
            post_hook=f'echo post > "{done}"',
        )
        self.assertIsNotNone(result["snapshot"])
        self.assertTrue(marker.exists())
        self.assertTrue(done.exists())

    def test_failing_pre_hook_aborts(self):
        with self.assertRaises(HookFailed):
            self.backup(pre_hook="exit 3")
        self.assertEqual(self.repo.list_snapshots(), [])

    def test_failing_hook_can_be_ignored(self):
        result = self.backup(pre_hook="exit 3", ignore_hook_failure=True)
        self.assertIsNotNone(result["snapshot"])

    def test_restore_filters(self):
        self.backup()
        manifest = self.repo.get_snapshot(self.repo.list_snapshots()[0]["id"])
        target = self.tmp / "restore-filtered"
        outcome = self.restore(manifest, target, include=["**/etc/hosts"])
        self.assertTrue(outcome["ok"], outcome["errors"])
        base = target / rel_prefix(self.source)
        self.assertTrue((base / "etc" / "hosts").is_file())
        self.assertFalse((base / "etc" / "nested").exists())

    def test_restore_does_not_overwrite_newer_files(self):
        self.backup()
        manifest = self.repo.get_snapshot(self.repo.list_snapshots()[0]["id"])
        target = self.tmp / "restore-existing"
        base = target / rel_prefix(self.source)
        (base / "etc").mkdir(parents=True)
        (base / "etc" / "hosts").write_text("local change\n", encoding="utf-8")
        outcome = self.restore(manifest, target)
        self.assertTrue(outcome["ok"], outcome["errors"])
        self.assertEqual((base / "etc" / "hosts").read_text(encoding="utf-8"), "local change\n")
        self.assertGreater(outcome["skipped"], 0)
        # ... and --overwrite always wins
        outcome = self.restore(manifest, target, overwrite="always")
        self.assertTrue(outcome["ok"], outcome["errors"])
        self.assertNotEqual((base / "etc" / "hosts").read_text(encoding="utf-8"), "local change\n")

    def test_restore_respects_overwrite_never_for_directories(self):
        self.backup()
        manifest = self.repo.get_snapshot(self.repo.list_snapshots()[0]["id"])
        target = self.tmp / "restore-dir-conflict"
        base = target / rel_prefix(self.source)
        base.mkdir(parents=True)
        (base / "etc").write_text("i am not a directory\n", encoding="utf-8")
        outcome = self.restore(manifest, target, overwrite="never")
        self.assertTrue(outcome["ok"], outcome["errors"])
        self.assertTrue((base / "etc").is_file())
        self.assertGreater(outcome["skipped"], 0)

    def test_restore_rejects_a_file_as_target(self):
        self.backup()
        manifest = self.repo.get_snapshot(self.repo.list_snapshots()[0]["id"])
        blocker = self.tmp / "not-a-dir"
        blocker.write_text("x", encoding="utf-8")
        with self.assertRaises(UsageError):
            self.restore(manifest, blocker)

    def test_backup_tolerates_a_file_growing_while_reading(self):
        # Larger than one read block, so the append lands mid-read.
        growing_file = self.source / "var" / "big.bin"
        growing_file.write_bytes(b"payload" * ((3 << 20) // 7))
        state = {"grown": False}

        def growing(handle, params, read_size=1 << 20):
            is_target = os.fstat(handle.fileno()).st_size > (1 << 20)
            for chunk in real_iter_chunks(handle, params, read_size):
                if is_target and not state["grown"]:
                    with open(growing_file, "ab") as extra:
                        extra.write(b"appended-while-reading\n" * 4)
                    state["grown"] = True
                yield chunk

        with unittest.mock.patch("haven.backup.iter_chunks", side_effect=growing):
            result = self.backup()
        manifest = self.repo.get_snapshot(result["snapshot"])
        entry = next(item for item in manifest["entries"] if item["p"].endswith("var/big.bin"))
        self.assertEqual(entry["s"], sum(length for _obj, length in entry["c"]))
        self.assertTrue(any("changed while reading" in warning for warning in result["warnings"]))

    def test_restore_verifies_every_chunk_before_writing(self):
        self.backup()
        manifest = self.repo.get_snapshot(self.repo.list_snapshots()[0]["id"])
        original = RemoteRepo.download_chunks

        def corrupting(repo_self, wanted):
            for obj_id, payload, flags in original(repo_self, wanted):
                damaged = payload[:-1] + bytes([payload[-1] ^ 0xFF]) if payload else payload
                yield obj_id, damaged, flags

        target = self.tmp / "restore-corrupt"
        with unittest.mock.patch.object(RemoteRepo, "download_chunks", corrupting):
            with self.assertRaises(IntegrityError):
                self.restore(manifest, target)
        written = [path for path in target.rglob("*") if path.is_file()]
        self.assertEqual(written, [])

    def test_restore_dry_run(self):
        self.backup()
        manifest = self.repo.get_snapshot(self.repo.list_snapshots()[0]["id"])
        target = self.tmp / "restore-dry"
        outcome = self.restore(manifest, target, dry_run=True)
        self.assertTrue(outcome["dry_run"])
        self.assertFalse(target.exists())
        self.assertGreater(outcome["planned_files"], 0)

    def test_prune_then_gc_then_restore(self):
        ids = []
        for index in range(3):
            extra = self.source / "etc" / f"unique-{index}.conf"
            extra.write_text(f"unique payload {index}\n" * 50, encoding="utf-8")
            ids.append(self.backup()["snapshot"])
            if index < 2:
                extra.unlink()
        outcome = self.repo.prune({"keep_last": 1, "keep_daily": 0, "keep_weekly": 0, "keep_monthly": 0}, apply=True)
        self.assertEqual(outcome["deleted"], sorted(ids[:2]))
        report = self.repo.gc(apply=True, min_age_hours=0)
        self.assertGreaterEqual(report["dead_packs"], 1)
        remaining = self.repo.list_snapshots()
        self.assertEqual(len(remaining), 1)
        manifest = self.repo.get_snapshot(remaining[0]["id"])
        target = self.tmp / "restore-after-prune"
        result = self.restore(manifest, target)
        self.assertTrue(result["ok"], result["errors"])
        self.assert_tree_restored(target)
        self.assertEqual(
            (target / rel_prefix(self.source) / "etc" / "unique-2.conf").read_text(encoding="utf-8"),
            "unique payload 2\n" * 50,
        )

    def test_survives_server_restart(self):
        snapshot = self.backup()["snapshot"]
        self.harness.stop()
        self.harness = Harness(self.tmp, fresh=False).start()
        self.client = self.harness.client(cache=self.tmp / "cache.sqlite")
        self.repo = RemoteRepo.from_config(self.client)
        manifest = self.repo.get_snapshot(snapshot)
        target = self.tmp / "restore-restarted"
        result = self.restore(manifest, target)
        self.assertTrue(result["ok"], result["errors"])
        self.assert_tree_restored(target)


class PackSplitTests(unittest.TestCase):
    """A first full backup must not fail because one pack exceeds the cap."""

    def test_backup_splits_into_several_packs(self):
        tmp = Path(tempfile.mkdtemp(prefix="haven-split-"))
        limit = 256 * 1024
        harness = Harness(tmp, max_pack_bytes=limit).start()
        try:
            client = harness.client(cache=tmp / "cache.sqlite")
            repo = RemoteRepo.from_config(client)
            source = make_tree(tmp / "source")
            # Incompressible data, so the upload really exceeds the cap.
            (source / "var" / "random.bin").write_bytes(os.urandom(400_000))
            runner = BackupRunner(repo, client, BackupOptions(sources=[str(source)]))
            result = runner.run()
            packs = result["upload"]["packs"]
            self.assertGreater(len(packs), 1, "expected the upload to be split")
            for pack_id in packs:
                size = (tmp / "repo" / "packs" / f"{pack_id}.pack").stat().st_size
                self.assertLessEqual(size, limit)
            manifest = repo.get_snapshot(result["snapshot"])
            target = tmp / "restore"
            outcome = RestoreRunner(repo, manifest, RestoreOptions(target=target)).run()
            self.assertTrue(outcome["ok"], outcome["errors"])
            self.assertEqual(
                (target / rel_prefix(source) / "var" / "blob.bin").read_bytes(),
                (source / "var" / "blob.bin").read_bytes(),
            )
        finally:
            harness.stop()
            shutil.rmtree(tmp, ignore_errors=True)


class CliTests(E2EBase):
    def test_check(self):
        code, out, _err = self.cli("--json", "check")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertTrue(payload["secret_matches"])
        self.assertEqual(payload["repo"]["name"], "test")

    def test_backup_list_show_verify_restore(self):
        code, out, _err = self.cli("--json", "backup", str(self.source), "--label", "cli")
        self.assertEqual(code, 0, out)
        snapshot = json.loads(out)["snapshot"]
        self.assertTrue(snapshot)

        code, out, _err = self.cli("--json", "snapshots")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["snapshots"][0]["id"], snapshot)

        code, out, _err = self.cli("--json", "show", snapshot)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["counts"]["f"], self.expected_files())

        code, out, _err = self.cli("--json", "verify", snapshot)
        self.assertEqual(code, 0, out)
        self.assertTrue(json.loads(out)["ok"])

        target = self.tmp / "cli-restore"
        code, out, _err = self.cli("--json", "restore", snapshot, "--to", str(target))
        self.assertEqual(code, 0, out)
        self.assertTrue(json.loads(out)["ok"])
        self.assert_tree_restored(target)

    def test_verify_detects_corruption(self):
        code, out, _err = self.cli("--json", "backup", str(self.source))
        self.assertEqual(code, 0)
        snapshot = json.loads(out)["snapshot"]
        pack = next((self.tmp / "repo" / "packs").glob("*.pack"))
        raw = bytearray(pack.read_bytes())
        raw[len(raw) // 2] ^= 0xFF
        pack.write_bytes(bytes(raw))
        code, out, _err = self.cli("--json", "verify", snapshot)
        self.assertEqual(code, 1)
        report = json.loads(out)
        self.assertFalse(report["ok"])
        self.assertTrue(report["reports"][0]["corrupt"] or report["reports"][0]["missing"])

    def test_diff(self):
        first = self.backup()["snapshot"]
        with open(self.source / "etc" / "nested" / "app.conf", "a", encoding="utf-8") as handle:
            handle.write("extra = 1\n")
        (self.source / "etc" / "new-file").write_text("new\n", encoding="utf-8")
        second = self.backup()["snapshot"]
        code, out, _err = self.cli("--json", "diff", first, second)
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertTrue(any(path.endswith("new-file") for path in payload["added"]))
        self.assertTrue(any(path.endswith("app.conf") for path in payload["changed"]))

    def test_prune_and_gc_commands(self):
        for index in range(3):
            extra = self.source / "etc" / f"unique-{index}.conf"
            extra.write_text(f"unique payload {index}\n" * 50, encoding="utf-8")
            self.backup()
            if index < 2:
                extra.unlink()
        code, out, _err = self.cli("--json", "prune", "--keep-last", "1", "--keep-daily", "0", "--keep-weekly", "0", "--keep-monthly", "0", "--apply")
        self.assertEqual(code, 0, out)
        self.assertEqual(len(json.loads(out)["deleted"]), 2)
        code, out, _err = self.cli("--json", "gc", "--apply", "--min-age-hours", "0")
        self.assertEqual(code, 0, out)
        self.assertGreaterEqual(json.loads(out)["dead_packs"], 1)
        code, out, _err = self.cli("--json", "verify", "--all")
        self.assertEqual(code, 0, out)

    def test_prune_uses_the_profile_policy(self):
        text = self.harness.client_config_path.read_text(encoding="utf-8")
        text = text.replace("keep_last = 3", "keep_last = 5").replace("keep_daily = 7", "keep_daily = 9")
        self.harness.client_config_path.write_text(text, encoding="utf-8")
        for _ in range(3):
            self.backup()
        code, out, err = self.cli("--json", "prune")
        self.assertEqual(code, 0, err)
        policy = json.loads(out)["policy"]
        self.assertEqual(policy["keep_last"], 5)
        self.assertEqual(policy["keep_daily"], 9)

    def test_prune_refuses_to_delete_everything(self):
        self.backup()
        code, _out, err = self.cli("prune", "--keep-last", "0", "--keep-daily", "0", "--keep-weekly", "0", "--keep-monthly", "0", "--apply")
        self.assertEqual(code, 2)
        self.assertIn("snapshot", err)


if __name__ == "__main__":
    unittest.main()
