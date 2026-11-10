"""Restoring a snapshot to disk.

Restores are deliberately conservative:

* Every chunk is downloaded and SHA-256 verified *before* the first file is
  touched, so a restore either has all its data or writes nothing.
* Nothing is written outside the target directory: each path is resolved
  through ``realpath`` and refused if a symlink (from the manifest or from the
  live system) would redirect it. With ``--to /`` this check is trivially
  satisfied, which is the intended way to restore a server in place.
* Modes and timestamps are applied last (directories in reverse depth order),
  so a read-only directory tree restores correctly.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .codec import CODEC_RAW, decode
from .errors import HavenError, IntegrityError, ObjectMissing, UsageError
from .packfile import Spill
from .transport import RemoteRepo
from .util import GlobSet, human_bytes, safe_rel_parts

O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_BINARY = getattr(os, "O_BINARY", 0)
OVERWRITE_POLICIES = ("never", "if-newer", "always")


@dataclass
class RestoreOptions:
    target: Path
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    overwrite: str = "if-newer"
    dry_run: bool = False
    preserve_owner: bool = False
    work_dir: Path | None = None


@dataclass
class _Plan:
    entry: dict
    action: str  # write | skip | link | skip-type
    reason: str = ""


class RestoreRunner:
    def __init__(
        self,
        repo: RemoteRepo,
        manifest: dict,
        options: RestoreOptions,
        *,
        log: Callable[[str], None] | None = None,
        progress: Callable[[int, int], None] | None = None,
    ) -> None:
        self.repo = repo
        self.manifest = manifest
        self.options = options
        self.log = log or (lambda message: None)
        self.progress = progress
        if options.overwrite not in OVERWRITE_POLICIES:
            raise UsageError(f"overwrite policy must be one of {', '.join(OVERWRITE_POLICIES)}")
        self.include = GlobSet(options.include)
        self.exclude = GlobSet(options.exclude)
        self.errors: list[str] = []
        self.stats = {
            "files": 0,
            "dirs": 0,
            "symlinks": 0,
            "hardlinks": 0,
            "skipped": 0,
            "bytes_written": 0,
        }
        self._spill: Spill | None = None
        self._workdir: Path | None = None

    # -- selection --------------------------------------------------------
    def _select_entries(self) -> list[dict]:
        entries = self.manifest.get("entries", [])
        selected: list[dict] = []
        for entry in sorted(entries, key=lambda item: (item["p"].count("/"), item["p"])):
            rel = entry["p"]
            if self.include and not self.include.matches(rel, is_dir=entry.get("t") == "d"):
                continue
            if self.exclude and self.exclude.matches(rel, is_dir=entry.get("t") == "d"):
                continue
            selected.append(entry)
        return selected

    def _plan(self, entries: list[dict]) -> list[_Plan]:
        plans: list[_Plan] = []
        for entry in entries:
            kind = entry.get("t")
            if kind == "x":
                plans.append(_Plan(entry, "skip-type", entry.get("e", "not captured")))
                continue
            blocked = self._blocked_parent(entry["p"])
            if blocked is not None and self.options.overwrite != "always":
                plans.append(_Plan(entry, "skip", f"parent {blocked!r} is not a directory"))
                continue
            path = self._join(entry["p"])
            exists = os.path.lexists(path)
            if kind == "d":
                if exists and not os.path.isdir(path):
                    if self.options.overwrite == "always":
                        plans.append(_Plan(entry, "write"))
                    else:
                        plans.append(_Plan(entry, "skip", "a file exists where a directory belongs"))
                else:
                    plans.append(_Plan(entry, "write"))
                continue
            if not exists:
                plans.append(_Plan(entry, "write"))
                continue
            policy = self.options.overwrite
            if policy == "never":
                plans.append(_Plan(entry, "skip", "already exists"))
                continue
            if policy == "if-newer":
                try:
                    current = os.lstat(path)
                except OSError:
                    current = None
                if current is not None and current.st_mtime >= float(entry.get("mt", 0.0)):
                    plans.append(_Plan(entry, "skip", "existing file is newer"))
                    continue
            if kind == "f" and entry.get("hl"):
                plans.append(_Plan(entry, "link"))
            else:
                plans.append(_Plan(entry, "write"))
        return plans

    def _blocked_parent(self, rel: str) -> str | None:
        """Name of the first ancestor that exists but is not a directory."""
        current = str(self.options.target)
        for part in safe_rel_parts(rel)[:-1]:
            current = os.path.join(current, part)
            if os.path.lexists(current) and not os.path.isdir(current):
                return part
        return None

    def _join(self, rel: str) -> str:
        parts = safe_rel_parts(rel)
        return os.path.join(str(self.options.target), *parts)

    # -- safety -----------------------------------------------------------
    def _real_target(self) -> str:
        return os.path.realpath(str(self.options.target))

    def _check_contained(self, path: str) -> None:
        target = self._real_target()
        resolved = os.path.realpath(path)
        if resolved == target:
            return
        if not resolved.startswith(target.rstrip(os.sep) + os.sep):
            raise IntegrityError(
                f"refusing to write {path!r}: it resolves outside the restore target "
                f"({resolved!r}); a symlink in the snapshot or on disk redirects it"
            )

    def _prepare_dir(self, path: str) -> None:
        if os.path.isdir(path):
            self._check_contained(path)
            return
        if os.path.lexists(path):
            if not os.path.isfile(path) or os.path.islink(path):
                raise IntegrityError(f"{path!r} exists and is not a directory")
            os.unlink(path)
        os.makedirs(path, mode=0o755, exist_ok=True)
        self._check_contained(path)

    def _prepare_parents(self, path: str) -> None:
        """Create missing parents, replacing non-directories only when allowed."""
        parent = os.path.dirname(path)
        if not parent:
            return
        root = str(self.options.target)
        relative = os.path.relpath(parent, root)
        current = root
        if relative not in (".", "", os.curdir):
            for part in relative.split(os.sep):
                current = os.path.join(current, part)
                # Check *before* creating: an existing symlinked ancestor must
                # not be turned into a directory tree outside the target.
                self._check_contained(current)
                if os.path.lexists(current) and not os.path.isdir(current):
                    if self.options.overwrite != "always":
                        raise IntegrityError(f"{part!r} is not a directory")
                    os.unlink(current)
                os.makedirs(current, mode=0o755, exist_ok=True)
        self._check_contained(parent)

    # -- main -------------------------------------------------------------
    def run(self) -> dict:
        started = time.monotonic()
        entries = self._select_entries()
        if not entries:
            raise UsageError("no files matched the given filters")
        target = str(self.options.target)
        if not self.options.dry_run:
            try:
                os.makedirs(target, exist_ok=True)
            except OSError as exc:
                raise UsageError(
                    f"cannot create the restore target {target!r}: {exc.strerror or exc}"
                ) from exc
            if not os.path.isdir(target):
                raise UsageError(f"restore target {target!r} is not a directory")
        plans = self._plan(entries)
        wanted: list[str] = []
        for plan in plans:
            if plan.action == "write" and plan.entry.get("t") == "f":
                wanted.extend(obj for obj, _length in plan.entry.get("c", []))
        unique_ids = list(dict.fromkeys(wanted))
        summary = {
            "snapshot": self.manifest.get("id"),
            "target": os.path.abspath(target),
            "entries": len(entries),
            "planned_files": sum(1 for plan in plans if plan.action in ("write", "link") and plan.entry.get("t") == "f"),
            "planned_bytes": sum(
                int(plan.entry.get("s", 0))
                for plan in plans
                if plan.action in ("write", "link") and plan.entry.get("t") == "f"
            ),
            "chunks": len(unique_ids),
        }
        if self.options.dry_run:
            summary["dry_run"] = True
            summary["skipped"] = [
                {"path": plan.entry["p"], "reason": plan.reason}
                for plan in plans
                if plan.action in ("skip", "skip-type")
            ][:200]
            return summary
        if unique_ids:
            self._fetch(unique_ids)
        try:
            for plan in plans:
                self._apply(plan)
            self._apply_directory_metadata(plans)
        finally:
            self._cleanup()
        summary.update(self.stats)
        summary["errors"] = self.errors[:100]
        summary["duration_ms"] = int((time.monotonic() - started) * 1000)
        if self.errors:
            summary["ok"] = False
        else:
            summary["ok"] = True
        return summary

    # -- data -------------------------------------------------------------
    def _workdir_path(self) -> Path:
        candidates: list[Path] = []
        if self.options.work_dir:
            candidates.append(Path(self.options.work_dir))
        candidates.append(Path(tempfile.gettempdir()))
        for candidate in candidates:
            try:
                candidate.mkdir(parents=True, exist_ok=True)
                if shutil.disk_usage(candidate).free > 64 * 1024 * 1024:
                    self._workdir = Path(tempfile.mkdtemp(prefix="haven-restore-", dir=str(candidate)))
                    return self._workdir
            except OSError:
                continue
        raise HavenError("no work directory with free space for the restore buffer")

    def _fetch(self, ids: list[str]) -> None:
        located, missing = self.repo.objects_locate(ids)
        if missing:
            raise ObjectMissing(
                f"{len(missing)} chunks referenced by this snapshot are missing from the repository",
                detail=", ".join(missing[:5]),
            )
        self._spill = Spill(self._workdir_path())
        self.log(f"downloading {len(ids)} chunks ({human_bytes(sum(item[4] for item in located.values()))})")
        done = 0
        for obj_id, payload, flags in self.repo.download_chunks(located):
            plainlen = located[obj_id][4]
            # Verify *before* anything is written to the target: a corrupt pack
            # must not be able to truncate files it cannot replace.
            data = decode(flags, payload, plainlen)
            if hashlib.sha256(data).hexdigest() != obj_id:
                raise IntegrityError(
                    f"chunk {obj_id} failed verification; nothing was restored"
                )
            self._spill.add(obj_id, CODEC_RAW, len(data), data)
            done += 1
            if self.progress:
                self.progress(done, len(ids))

    def _payload(self, obj_id: str) -> bytes:
        assert self._spill is not None
        flags, plainlen, payload = self._spill.read(obj_id)
        return decode(flags, payload, plainlen)
    # -- writing ----------------------------------------------------------
    def _apply(self, plan: _Plan) -> None:
        entry = plan.entry
        kind = entry.get("t")
        path = self._join(entry["p"])
        if plan.action == "skip-type":
            self.stats["skipped"] += 1
            self.log(f"skipped {entry['p']}: {plan.reason}")
            return
        if plan.action == "skip":
            self.stats["skipped"] += 1
            self.log(f"skipped {entry['p']}: {plan.reason}")
            return
        if kind == "d":
            try:
                self._prepare_dir(path)
                self.stats["dirs"] += 1
            except (OSError, HavenError) as exc:
                self._fail(entry, exc)
            return
        try:
            self._prepare_parents(path)
            if os.path.lexists(path) and (os.path.islink(path) or not os.path.isdir(path)):
                os.unlink(path)
            if kind == "f":
                if plan.action == "link" and self._try_hardlink(entry, path):
                    return
                self._write_file(entry, path)
            elif kind == "l":
                self._write_symlink(entry, path)
        except (OSError, HavenError) as exc:
            self._fail(entry, exc)

    def _write_file(self, entry: dict, path: str) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | O_NOFOLLOW | O_BINARY, 0o600)
        written = 0
        try:
            with os.fdopen(fd, "wb") as handle:
                fd = -1
                for obj_id, length in entry.get("c", []):
                    data = self._payload(obj_id)
                    if hashlib.sha256(data).hexdigest() != obj_id:
                        raise IntegrityError(f"chunk {obj_id} in {entry['p']!r} failed verification")
                    if len(data) != length:
                        raise IntegrityError(f"chunk {obj_id} has unexpected length")
                    if entry.get("sp") and data.count(0) == len(data):
                        handle.seek(len(data), os.SEEK_CUR)
                    else:
                        handle.write(data)
                    written += len(data)
                expected = int(entry.get("s", written))
                if written != expected:
                    raise IntegrityError(
                        f"{entry['p']!r}: restored {written} bytes but the snapshot says {expected}"
                    )
                handle.truncate(expected)
            self._apply_metadata(path, entry)
            self.stats["files"] += 1
            self.stats["bytes_written"] += written
        finally:
            if fd >= 0:
                os.close(fd)

    def _write_symlink(self, entry: dict, path: str) -> None:
        target = entry["tg"]
        try:
            os.symlink(target, path)
        except (OSError, NotImplementedError) as exc:
            raise HavenError(f"cannot create symlink {entry['p']!r} -> {target!r}: {exc}") from exc
        try:
            os.utime(path, (float(entry.get("mt", 0.0)), float(entry.get("mt", 0.0))), follow_symlinks=False)
        except (OSError, NotImplementedError):
            pass
        if self.options.preserve_owner:
            self._chown(path, entry, follow_symlinks=False)
        self.stats["symlinks"] += 1

    def _try_hardlink(self, entry: dict, path: str) -> bool:
        target_rel = entry.get("hl")
        if not target_rel:
            return False
        try:
            source = self._join(target_rel)
        except HavenError:
            return False
        self._check_contained(source)
        try:
            info = os.lstat(source)
        except OSError:
            return False
        if not stat.S_ISREG(info.st_mode):
            return False
        try:
            os.link(source, path)
        except OSError:
            return False
        self.stats["hardlinks"] += 1
        self.stats["files"] += 1
        return True

    def _apply_metadata(self, path: str, entry: dict) -> None:
        mode = int(entry.get("m", 0o600))
        try:
            os.chmod(path, mode)
        except OSError as exc:
            self.errors.append(f"{entry['p']}: cannot set mode {oct(mode)}: {exc.strerror}")
        mtime = float(entry.get("mt", 0.0))
        if mtime:
            try:
                os.utime(path, (mtime, mtime))
            except OSError as exc:
                self.errors.append(f"{entry['p']}: cannot set mtime: {exc.strerror}")
        if self.options.preserve_owner:
            self._chown(path, entry)

    def _chown(self, path: str, entry: dict, *, follow_symlinks: bool = True) -> None:
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            return
        try:
            os.chown(
                path,
                int(entry.get("u", 0)),
                int(entry.get("g", 0)),
                follow_symlinks=follow_symlinks,
            )
        except (OSError, NotImplementedError) as exc:
            self.errors.append(f"{entry['p']}: cannot set owner: {exc}")

    def _apply_directory_metadata(self, plans: list[_Plan]) -> None:
        dirs = [plan.entry for plan in plans if plan.entry.get("t") == "d"]
        for entry in sorted(dirs, key=lambda item: item["p"].count("/"), reverse=True):
            path = self._join(entry["p"])
            if not os.path.isdir(path):
                continue
            mode = int(entry.get("m", 0o755))
            try:
                os.chmod(path, mode)
            except OSError as exc:
                self.errors.append(f"{entry['p']}: cannot set mode {oct(mode)}: {exc.strerror}")
            mtime = float(entry.get("mt", 0.0))
            if mtime:
                try:
                    os.utime(path, (mtime, mtime))
                except OSError as exc:
                    self.errors.append(f"{entry['p']}: cannot set mtime: {exc.strerror}")
            if self.options.preserve_owner:
                self._chown(path, entry)

    def _fail(self, entry: dict, exc: Exception) -> None:
        message = getattr(exc, "strerror", None) or str(exc)
        self.errors.append(f"{entry['p']}: {message}")
        self.log(f"error: {entry['p']}: {message}")

    def _cleanup(self) -> None:
        if self._spill is not None:
            self._spill.cleanup()
            self._spill = None
        if self._workdir is not None:
            shutil.rmtree(self._workdir, ignore_errors=True)
            self._workdir = None
