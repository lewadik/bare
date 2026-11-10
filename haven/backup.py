"""Client-side snapshot creation.

Flow of one ``haven backup`` run::

    pre-hook -> walk sources (chunk new files into a spill file) -> ask the
    server which chunks it lacks -> write one pack with only those -> upload ->
    sign and commit the manifest -> update the chunk cache -> post-hook

The pack is written only after the existence check, so a nightly run over
100 GB of unchanged data transfers a few kilobytes (the manifest) instead of
the data. Files whose metadata is unchanged are not even opened.

Safety notes
------------
* Files are opened with ``O_NOFOLLOW`` and ``fstat`` is compared against the
  earlier ``lstat``: a file swapped for a symlink between the two calls is
  recorded as an error instead of being read (a root backup must not become a
  file-exfiltration primitive).
* A manifest is committed only after every chunk it references is durable on
  the server; the server enforces this again when the manifest arrives.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import __version__
from .cache import ChunkCache
from .chunker import ChunkParams, iter_chunks
from .codec import encode
from .errors import ConfigError, HavenError, IntegrityError, UsageError
from .manifest import make_manifest, new_snapshot_id
from .packfile import Spill
from .transport import RemoteRepo
from .util import GlobSet, human_bytes, to_rel_posix

O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_BINARY = getattr(os, "O_BINARY", 0)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
HOOK_TIMEOUT = 3600


class HookFailed(HavenError):
    code = "hook_failed"
    status = 500


@dataclass
class BackupOptions:
    sources: list[str]
    excludes: list[str] = field(default_factory=list)
    one_file_system: bool = False
    label: str = ""
    dry_run: bool = False
    use_cache: bool = True
    pre_hook: str | None = None
    post_hook: str | None = None
    ignore_hook_failure: bool = False
    work_dir: Path | None = None


class BackupRunner:
    def __init__(
        self,
        repo: RemoteRepo,
        config,
        options: BackupOptions,
        *,
        log: Callable[[str], None] | None = None,
        progress: Callable[[int, int], None] | None = None,
        hostname: str | None = None,
    ) -> None:
        self.repo = repo
        self.config = config
        self.options = options
        self.log = log or (lambda message: None)
        self.progress = progress
        self.hostname = hostname or socket.gethostname() or "unknown"
        self.globs = GlobSet(list(config.exclude) + list(options.excludes))
        self.params: ChunkParams = config.chunking
        self.codec, self.level = config.compress
        self.entries: list[dict] = []
        self.seen_paths: set[str] = set()
        self.sources: list[str] = []
        self.stats = {
            "files": 0,
            "dirs": 0,
            "symlinks": 0,
            "skipped": 0,
            "errors": 0,
            "bytes_total": 0,
        }
        self.warnings: list[str] = []
        self.spill: Spill | None = None
        self.cache: ChunkCache | None = None
        self._cached_files: dict[str, tuple[str, os.stat_result, list[tuple[str, int]]]] = {}
        self._cache_updates: list[tuple[str, os.stat_result, list[tuple[str, int]]]] = []
        self._workdir: Path | None = None
        self._hardlinks: dict[tuple[int, int], str] = {}
        self._pack_paths: list[Path] = []

    # -- setup ------------------------------------------------------------
    def _workdir_path(self) -> Path:
        if self._workdir is not None:
            return self._workdir
        candidates: list[Path] = []
        if self.options.work_dir:
            candidates.append(Path(self.options.work_dir))
        if self.config.work_dir:
            candidates.append(Path(self.config.work_dir))
        if self.config.cache_path:
            candidates.append(Path(self.config.cache_path).parent / "spill")
        candidates.append(Path(tempfile.gettempdir()))
        for candidate in candidates:
            try:
                candidate.mkdir(parents=True, exist_ok=True)
                free = shutil.disk_usage(candidate).free
            except OSError:
                continue
            if free > 64 * 1024 * 1024:
                self._workdir = Path(tempfile.mkdtemp(prefix="haven-", dir=str(candidate)))
                return self._workdir
        raise ConfigError("no writable work directory with free space for the chunk spill")

    def _run_hook(self, kind: str, command: str | None) -> None:
        if not command:
            return
        self.log(f"running {kind} hook: {command}")
        try:
            completed = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=HOOK_TIMEOUT
            )
        except (OSError, subprocess.SubprocessError) as exc:
            if self.options.ignore_hook_failure:
                self.log(f"warning: {kind} hook failed to start: {exc}")
                return
            raise HookFailed(f"{kind} hook failed to start: {exc}") from exc
        output = (completed.stdout or "").strip()
        if output:
            for line in output.splitlines()[-10:]:
                self.log(f"  {kind}: {line}")
        if completed.returncode != 0:
            message = f"{kind} hook exited with status {completed.returncode}"
            tail = [line for line in (completed.stderr or "").strip().splitlines() if line][-3:]
            if tail:
                message += ": " + " | ".join(tail)
            if self.options.ignore_hook_failure:
                self.log(f"warning: {message}")
                return
            raise HookFailed(message)

    # -- main -------------------------------------------------------------
    def run(self) -> dict:
        started = time.monotonic()
        if not self.options.sources:
            raise UsageError("no backup sources given")
        self.sources = [self._validate_source(item) for item in self.options.sources]
        self.spill = Spill(self._workdir_path())
        if self.options.use_cache:
            self.cache = ChunkCache(self.config.cache_path, self.params.identifier())
        try:
            self._run_hook("pre", self.options.pre_hook)
            for source in self.sources:
                self._scan_source(source)
            self.log(
                f"scanned {self.stats['files']} files, {self.stats['dirs']} dirs, "
                f"{self.stats['skipped']} skipped, {self.stats['errors']} errors "
                f"({human_bytes(self.stats['bytes_total'])})"
            )
            if self.cache is not None:
                self.log(f"chunk cache: {self.cache.hits} hits, {self.cache.misses} misses")
            result = self._commit(started)
        finally:
            # The post hook always runs (it is typically cleanup), but a failure
            # there must not hide the error that triggered it.
            pending = sys.exc_info()[1]
            try:
                self._run_hook("post", self.options.post_hook)
            except HavenError:
                if pending is None:
                    raise
                self.log("warning: post hook failed while another error was propagating")
            finally:
                self._cleanup()
        return {
            "snapshot": result.get("snapshot"),
            "host": self.hostname,
            "label": self.options.label,
            "sources": self.sources,
            "stats": self.stats,
            "upload": result.get("upload", {}),
            "duration_ms": int((time.monotonic() - started) * 1000),
            "warnings": self.warnings[:50],
            "dry_run": self.options.dry_run,
        }

    def _validate_source(self, source: str) -> str:
        absolute = os.path.abspath(os.path.expanduser(source))
        try:
            os.lstat(absolute)
        except OSError as exc:
            raise UsageError(f"source {source!r} is not accessible: {exc.strerror}") from exc
        return absolute

    # -- walking ----------------------------------------------------------
    def _anchor(self, absolute: str) -> str:
        if os.name == "nt":  # pragma: no cover - Windows test runs
            drive, _ = os.path.splitdrive(absolute)
            return (drive + os.sep) if drive else os.sep
        return os.sep

    def _scan_source(self, absolute: str) -> None:
        root_stat = os.lstat(absolute)
        self._walk(absolute, self._anchor(absolute), root_stat.st_dev, root_only=True)

    def _walk(self, path: str, anchor: str, root_dev: int, *, root_only: bool = False) -> None:
        try:
            st = os.lstat(path)
        except OSError as exc:
            self._record_error(path, anchor, f"cannot stat: {exc.strerror}")
            return
        rel = to_rel_posix(path, anchor)
        if rel in ("", "."):
            # Backing up "/" itself: never emit an entry for the root, only its
            # contents (restoring must not chmod the target root).
            if stat.S_ISDIR(st.st_mode):
                for name in sorted(os.listdir(path)):
                    self._walk(os.path.join(path, name), anchor, root_dev)
            return
        if rel in self.seen_paths:
            return
        mode = stat.S_IMODE(st.st_mode)
        if not root_only and self.globs.matches(rel, is_dir=stat.S_ISDIR(st.st_mode)):
            return
        if self.options.one_file_system and not root_only and st.st_dev != root_dev:
            self.log(f"skipping {rel} (different filesystem)")
            return
        if stat.S_ISDIR(st.st_mode):
            self._emit(
                {
                    "p": rel,
                    "t": "d",
                    "m": mode,
                    "u": getattr(st, "st_uid", 0),
                    "g": getattr(st, "st_gid", 0),
                    "mt": float(st.st_mtime),
                }
            )
            self.stats["dirs"] += 1
            try:
                names = sorted(os.listdir(path))
            except OSError as exc:
                self._record_error(path, anchor, f"cannot list directory: {exc.strerror}")
                return
            for name in names:
                self._walk(os.path.join(path, name), anchor, root_dev)
        elif stat.S_ISLNK(st.st_mode):
            try:
                target = os.readlink(path)
            except OSError as exc:
                self._record_error(path, anchor, f"cannot read symlink: {exc.strerror}")
                return
            self._emit(
                {
                    "p": rel,
                    "t": "l",
                    "m": mode,
                    "u": getattr(st, "st_uid", 0),
                    "g": getattr(st, "st_gid", 0),
                    "mt": float(st.st_mtime),
                    "tg": target,
                }
            )
            self.stats["symlinks"] += 1
        elif stat.S_ISREG(st.st_mode):
            self._add_file(path, rel, st, mode)
        else:
            self._emit(
                {
                    "p": rel,
                    "t": "x",
                    "e": "unsupported file type (socket, fifo or device)",
                    "m": mode,
                    "mt": float(st.st_mtime),
                }
            )
            self.stats["skipped"] += 1
            self.warnings.append(f"{rel}: unsupported file type, skipped")

    def _emit(self, entry: dict) -> None:
        rel = entry["p"]
        if rel in self.seen_paths:
            return
        self.seen_paths.add(rel)
        self.entries.append(entry)

    def _record_error(self, path: str, anchor: str, message: str) -> None:
        rel = to_rel_posix(path, anchor)
        self.stats["errors"] += 1
        self.warnings.append(f"{rel}: {message}")
        self.log(f"warning: {rel}: {message}")
        self._emit({"p": rel, "t": "x", "e": message, "m": 0, "mt": 0.0})

    def _add_file(self, path: str, rel: str, st: os.stat_result, mode: int) -> None:
        hardlink_key = (int(st.st_dev), int(st.st_ino))
        hardlink_target = self._hardlinks.get(hardlink_key) if getattr(st, "st_nlink", 1) > 1 else None
        entry: dict = {
            "p": rel,
            "t": "f",
            "m": mode,
            "u": getattr(st, "st_uid", 0),
            "g": getattr(st, "st_gid", 0),
            "mt": float(st.st_mtime),
            "s": int(st.st_size),
        }
        if hardlink_target is not None:
            entry["hl"] = hardlink_target
        blocks = getattr(st, "st_blocks", None)
        if blocks is not None and int(blocks) * 512 < int(st.st_size):
            entry["sp"] = True
        chunks = self.cache.get(rel, st) if self.cache is not None else None
        if chunks is not None:
            entry["c"] = [[obj_id, length] for obj_id, length in chunks]
            self._cached_files[rel] = (path, st, chunks)
        else:
            try:
                chunks, bytes_read = self._chunk_file(path, st)
            except (OSError, HavenError) as exc:
                message = getattr(exc, "strerror", None) or str(exc)
                self.stats["errors"] += 1
                self.warnings.append(f"{rel}: {message}")
                self.log(f"warning: {rel}: {message}")
                self._emit(
                    {
                        "p": rel,
                        "t": "x",
                        "e": f"cannot read file: {message}",
                        "m": mode,
                        "mt": float(st.st_mtime),
                    }
                )
                return
            if bytes_read != int(st.st_size):
                # A live log or database grew/shrank between lstat and read.
                # Record what we actually captured instead of failing the whole
                # snapshot on a size mismatch at the server.
                self.stats["changed_while_reading"] = self.stats.get("changed_while_reading", 0) + 1
                self.warnings.append(
                    f"{rel}: size changed while reading ({st.st_size} -> {bytes_read} bytes)"
                )
                self.log(f"warning: {rel}: changed while reading, captured {bytes_read} bytes")
                entry["s"] = bytes_read
            entry["c"] = [[obj_id, length] for obj_id, length in chunks]
            if self.cache is not None and bytes_read == int(st.st_size):
                self._cache_updates.append((rel, st, chunks))
        if hardlink_target is None and getattr(st, "st_nlink", 1) > 1:
            self._hardlinks[hardlink_key] = rel
        self.stats["files"] += 1
        self.stats["bytes_total"] += int(st.st_size)
        self._emit(entry)

    def _chunk_file(self, path: str, st: os.stat_result) -> tuple[list[tuple[str, int]], int]:
        assert self.spill is not None
        flags = os.O_RDONLY | O_NOFOLLOW | O_BINARY | O_CLOEXEC
        fd = os.open(path, flags)
        chunks: list[tuple[str, int]] = []
        total = 0
        try:
            current = os.fstat(fd)
            if (int(current.st_dev), int(current.st_ino)) != (int(st.st_dev), int(st.st_ino)):
                raise OSError(0, "file was replaced while the backup was running")
            if not stat.S_ISREG(current.st_mode):
                raise OSError(0, "file is no longer a regular file")
            with os.fdopen(fd, "rb") as handle:
                fd = -1
                for chunk in iter_chunks(handle, self.params):
                    obj_id = hashlib.sha256(chunk).hexdigest()
                    chunk_flags, payload = encode(chunk, self.codec, self.level)
                    self.spill.add(obj_id, chunk_flags, len(chunk), payload)
                    chunks.append((obj_id, len(chunk)))
                    total += len(chunk)
        finally:
            if fd >= 0:
                os.close(fd)
        return chunks, total

    def _collect_ids(self) -> list[str]:
        ids: list[str] = []
        for entry in self.entries:
            if entry.get("t") == "f":
                for obj_id, _length in entry.get("c", []):
                    ids.append(obj_id)
        return list(dict.fromkeys(ids))

    # -- upload / commit --------------------------------------------------
    def _commit(self, started: float) -> dict:
        assert self.spill is not None
        unique_ids = self._collect_ids()
        staged = set(self.spill.ids())
        self.log(f"{len(unique_ids)} chunk references, {len(staged)} distinct chunks staged")
        existing: set[str] = self.repo.objects_exists(unique_ids) if unique_ids else set()
        self.log(f"{len(existing)} chunks already stored on the server")
        missing = [obj for obj in unique_ids if obj not in existing]
        cached_only = [obj for obj in missing if obj not in staged]
        if cached_only:
            self._reread_cached(cached_only)
            unique_ids = self._collect_ids()
            missing = [obj for obj in unique_ids if obj not in existing]
            staged = set(self.spill.ids())
        unreachable = [obj for obj in unique_ids if obj not in existing and obj not in staged]
        if unreachable:
            raise IntegrityError(
                f"{len(unreachable)} chunks are neither stored on the server nor staged "
                "locally; refusing to commit an incomplete snapshot"
            )
        upload_ids = [obj for obj in unique_ids if obj not in existing and obj in staged]
        stats = {
            "chunks": len(unique_ids),
            "chunks_new": len(upload_ids),
            "chunks_reused": len(unique_ids) - len(upload_ids),
            "bytes_new": sum(self.spill.plainlen(obj) for obj in upload_ids),
        }
        upload_info = {
            "pack": "",
            "packs": [],
            "pack_bytes": 0,
            "objects": 0,
            "new_objects": 0,
            "stored_bytes": 0,
            "duplicate": False,
        }
        if upload_ids:
            groups = self._split_packs(upload_ids, self._pack_limit())
            self.log(
                f"uploading {len(upload_ids)} new chunks in {len(groups)} pack(s) "
                f"({human_bytes(stats['bytes_new'])} of new data)"
            )
            for index, group in enumerate(groups):
                pack_path = self._pack_path_for_upload(index)
                try:
                    pack_id, count, size = self.spill.write_pack(pack_path, set(group))
                    upload_info["packs"].append(pack_id)
                    upload_info["pack"] = upload_info["pack"] or pack_id
                    upload_info["pack_bytes"] += size
                    upload_info["objects"] += count
                    self.log(
                        f"pack {index + 1}/{len(groups)}: {count} objects, {human_bytes(size)}"
                    )
                    if not self.options.dry_run:
                        result = self.repo.upload_pack(
                            pack_path, expected_id=pack_id, progress=self.progress
                        )
                        upload_info["stored_bytes"] += int(result.get("stored_bytes", 0))
                        upload_info["new_objects"] += int(result.get("new_objects", 0))
                        upload_info["duplicate"] = upload_info["duplicate"] or bool(
                            result.get("duplicate", False)
                        )
                finally:
                    pack_path.unlink(missing_ok=True)
            self.log(
                f"uploaded {len(upload_info['packs'])} pack(s), "
                f"{human_bytes(upload_info['pack_bytes'])} on the wire"
            )
        else:
            self.log("nothing new to upload")
        self.stats.update(
            {
                "chunks": stats["chunks"],
                "chunks_new": stats["chunks_new"],
                "chunks_reused": stats["chunks_reused"],
                "bytes_new": stats["bytes_new"],
                "bytes_uploaded": upload_info.get("pack_bytes", 0),
            }
        )
        if self.options.dry_run:
            return {"stats": stats, "upload": upload_info}
        manifest = make_manifest(
            snapshot_id=new_snapshot_id(),
            host=self.hostname,
            paths=self.sources,
            entries=self.entries,
            chunker=self.params,
            codec=self.config.compress_spec,
            excludes=self.globs.patterns,
            stats=self.stats,
            label=self.options.label,
            duration_ms=int((time.monotonic() - started) * 1000),
            haven_version=__version__,
            secret=self.config.secret,
        )
        result = self.repo.put_snapshot(manifest)
        self.log(f"snapshot {result['id']} committed")
        if self.cache is not None:
            for rel, st, chunks in self._cache_updates:
                self.cache.put(rel, st, chunks)
            self.cache.commit()
        return {"snapshot": result["id"], "stats": stats, "upload": upload_info}

    def _reread_cached(self, missing_ids: list[str]) -> None:
        """A cached file references chunks the server lacks: read it again."""
        wanted = set(missing_ids)
        affected = [
            rel
            for rel, (_path, _st, chunks) in self._cached_files.items()
            if any(obj in wanted for obj, _length in chunks)
        ]
        if not affected:
            return
        self.log(f"re-reading {len(affected)} cached file(s) whose chunks are missing from the server")
        by_rel = {entry["p"]: entry for entry in self.entries}
        for rel in affected:
            path, st, old_chunks = self._cached_files[rel]
            try:
                chunks, bytes_read = self._chunk_file(path, st)
            except (OSError, HavenError) as exc:
                message = getattr(exc, "strerror", None) or str(exc)
                self.stats["errors"] += 1
                self.warnings.append(f"{rel}: {message} (re-read)")
                entry = by_rel.get(rel)
                if entry is not None:
                    entry.clear()
                    entry.update(
                        {"p": rel, "t": "x", "e": f"cannot re-read file: {message}", "m": 0, "mt": 0.0}
                    )
                continue
            entry = by_rel.get(rel)
            if entry is not None:
                entry["c"] = [[obj_id, length] for obj_id, length in chunks]
                if bytes_read != int(st.st_size):
                    entry["s"] = bytes_read
            if self.cache is not None:
                self._cache_updates.append((rel, st, chunks))
            if self.cache is not None and old_chunks != chunks:
                self.cache.forget(rel)

    def _pack_limit(self) -> int:
        """Server-side pack cap, so a first full backup can be split."""
        try:
            info = self.repo.repo_info()
            return int(info.get("max_pack_bytes") or 0)
        except (HavenError, TypeError, ValueError) as exc:
            self.log(f"warning: cannot read the server pack limit ({exc}); using one pack")
            return 0

    def _split_packs(self, ids: list[str], limit: int) -> list[list[str]]:
        assert self.spill is not None
        if limit <= 0:
            return [ids]
        budget = max(limit - (1 << 20), limit // 2)  # header, trailer and varint headroom
        groups: list[list[str]] = []
        current: list[str] = []
        size = 0
        for obj_id in ids:
            cost = self.spill.payload_size(obj_id) + 64
            if current and size + cost > budget:
                groups.append(current)
                current = []
                size = 0
            current.append(obj_id)
            size += cost
        if current:
            groups.append(current)
        return groups

    def _pack_path_for_upload(self, index: int = 0) -> Path:
        assert self._workdir is not None
        path = self._workdir / f"pack-{int(time.time())}-{os.getpid()}-{index}.pack"
        self._pack_paths.append(path)
        return path

    def _cleanup(self) -> None:
        if self.spill is not None:
            self.spill.cleanup()
            self.spill = None
        if self.cache is not None:
            self.cache.close()
            self.cache = None
        if self._pack_paths:
            for path in self._pack_paths:
                path.unlink(missing_ok=True)
            self._pack_paths.clear()
        if self._workdir is not None:
            shutil.rmtree(self._workdir, ignore_errors=True)
            self._workdir = None
