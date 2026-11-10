"""On-disk repository: packs, snapshots, garbage collection, verification.

Layout::

    <root>/repo.json                 repository identity and format
    <root>/packs/<pack-id>.pack      immutable pack files (content addressed)
    <root>/packs/<pack-id>.idx.json  index, rebuildable from the pack
    <root>/snapshots/<id>.json       signed manifests
    <root>/snapshots/<id>.meta.json  cached summary used by `snapshot list`
    <root>/state/index.sqlite        object index (pack, offset, flags, ...)
    <root>/tmp/                      upload staging
    <root>/lock                      cross-process maintenance lock

The SQLite index is a cache of the pack indexes: it can be rebuilt at any time
with :meth:`Repository.rebuild_index`, which is also what happens when a pack
was installed but the process died before the index commit.
"""

from __future__ import annotations

import contextlib
import json
import logging
import math
import os
import re
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .. import __version__
from ..codec import decode
from ..errors import (
    ConflictError,
    ConfigError,
    HavenError,
    IntegrityError,
    NotFoundError,
    ObjectMissing,
    RepositoryError,
    UsageError,
)
from ..manifest import (
    entry_chunks,
    referenced_objects,
    summarize,
    validate_manifest,
    verify_manifest,
)
from ..packfile import Location, read_pack_file, scan_pack, write_pack_file
from ..retention import RetentionPolicy, select_keep
from ..util import (
    FileLock,
    atomic_write_bytes,
    canonical_json,
    ensure_dir,
    fsync_dir,
    human_bytes,
    read_json,
    sha256_file,
    utc_iso,
    write_json,
)

REPO_FILE = "repo.json"
REPO_FORMAT = 1
PACK_ID_RE = re.compile(r"^[0-9a-f]{64}$")
SNAPSHOT_FILE_RE = re.compile(r"^([0-9]{8}T[0-9]{6}Z-[0-9a-f]{8})\.json$")
META_SUFFIX = ".meta.json"
# Restores fetch coalesced byte ranges; this cap is independent of
# max_pack_bytes (a repository may accept small packs but must serve ranges
# that span several objects).
MAX_RANGE_BYTES = 64 * 1024 * 1024

LOG = logging.getLogger("haven.server.store")

SCHEMA = """
CREATE TABLE IF NOT EXISTS objects (
    obj_id   TEXT PRIMARY KEY,
    pack_id  TEXT NOT NULL,
    offset   INTEGER NOT NULL,
    length   INTEGER NOT NULL,
    flags    INTEGER NOT NULL,
    plainlen INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS objects_by_pack ON objects(pack_id);
CREATE TABLE IF NOT EXISTS packs (
    pack_id   TEXT PRIMARY KEY,
    size      INTEGER NOT NULL,
    n_objects INTEGER NOT NULL,
    created   REAL NOT NULL
) WITHOUT ROWID;
"""


@dataclass
class RepoMeta:
    repo_id: str
    name: str
    created: str
    format: int = REPO_FORMAT
    haven_version: str = __version__

    def to_json(self) -> dict:
        return {
            "format": self.format,
            "repo_id": self.repo_id,
            "name": self.name,
            "created": self.created,
            "haven_version": self.haven_version,
        }


class Repository:
    """Thread-safe (single process) repository access."""

    def __init__(
        self,
        root: Path,
        secret: bytes | None,
        *,
        max_pack_bytes: int = 512 * 1024 * 1024,
    ) -> None:
        self.root = Path(root)
        self.secret = secret
        self.max_pack_bytes = max_pack_bytes
        self._lock = threading.RLock()
        self.packs_dir = self.root / "packs"
        self.snapshots_dir = self.root / "snapshots"
        self.tmp_dir = self.root / "tmp"
        self.state_dir = self.root / "state"
        self.lock_path = self.root / "lock"
        self.meta = self._load_meta()
        for directory in (self.packs_dir, self.snapshots_dir, self.tmp_dir, self.state_dir):
            ensure_dir(directory)
        self._db = self._open_db()
        self._ensure_index()

    # -- lifecycle --------------------------------------------------------
    @classmethod
    def create(cls, root: Path, *, name: str, secret: bytes, max_pack_bytes: int = 512 * 1024 * 1024) -> "Repository":
        root = Path(root)
        if (root / REPO_FILE).exists():
            raise ConflictError(f"repository already exists at {root}")
        ensure_dir(root, 0o700)
        meta = RepoMeta(repo_id=uuid.uuid4().hex, name=name, created=utc_iso())
        write_json(root / REPO_FILE, meta.to_json(), mode=0o600)
        return cls(root, secret, max_pack_bytes=max_pack_bytes)

    def _load_meta(self) -> RepoMeta:
        path = self.root / REPO_FILE
        if not path.is_file():
            raise ConfigError(f"{self.root} is not a Haven repository (missing {REPO_FILE})")
        data = read_json(path)
        if data.get("format") != REPO_FORMAT:
            raise ConfigError(f"unsupported repository format {data.get('format')!r}")
        return RepoMeta(
            repo_id=str(data["repo_id"]),
            name=str(data.get("name", "haven")),
            created=str(data.get("created", utc_iso())),
            haven_version=str(data.get("haven_version", __version__)),
        )

    def _open_db(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self.state_dir / "index.sqlite"), check_same_thread=False, timeout=30.0, isolation_level=None
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.execute("PRAGMA busy_timeout=30000")
        connection.executescript(SCHEMA)
        return connection

    @contextlib.contextmanager
    def _tx(self):
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield self._db
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            else:
                self._db.execute("COMMIT")

    @property
    def key_id(self) -> str:
        import hashlib

        return hashlib.sha256(self.secret or b"").hexdigest()[:16]

    # -- info -------------------------------------------------------------
    def info(self) -> dict:
        stats = self.stats()
        return {
            "repo_id": self.meta.repo_id,
            "name": self.meta.name,
            "created": self.meta.created,
            "format": self.meta.format,
            "key_id": self.key_id,
            "haven_version": __version__,
            "max_pack_bytes": self.max_pack_bytes,
            **stats,
        }

    def stats(self) -> dict:
        with self._lock:
            packs = self._db.execute("SELECT COUNT(*) AS n, COALESCE(SUM(size),0) AS b FROM packs").fetchone()
            objects = self._db.execute("SELECT COUNT(*) AS n FROM objects").fetchone()
        metas = self._snapshot_metas()
        logical = sum(int(meta.get("stats", {}).get("bytes_total", 0)) for meta in metas)
        stored = int(packs["b"])
        return {
            "packs": int(packs["n"]),
            "objects": int(objects["n"]),
            "stored_bytes": stored,
            "logical_bytes": logical,
            "snapshots": len(metas),
            "hosts": sorted({meta.get("host", "") for meta in metas}),
            "dedup_ratio": round(1.0 - (stored / logical), 4) if logical else 0.0,
        }

    # -- packs ------------------------------------------------------------
    def _pack_path(self, pack_id: str) -> Path:
        return self.packs_dir / f"{pack_id}.pack"

    def _index_path(self, pack_id: str) -> Path:
        return self.packs_dir / f"{pack_id}.idx.json"

    def _require_pack_id(self, pack_id: str) -> str:
        if not isinstance(pack_id, str) or not PACK_ID_RE.match(pack_id):
            raise UsageError("invalid pack id")
        return pack_id

    def install_pack(self, temp_path: Path, *, expected_id: str | None = None, prefer_new: bool = False) -> dict:
        """Validate an uploaded pack and move it into the repository.

        The upload is read once: the deep scan that verifies every object also
        yields the SHA-256 of the whole file, which *is* the pack id. A duplicate
        upload is detected before that scan (it only needs the declared id), so
        re-sending an existing pack stays cheap.
        """
        temp_path = Path(temp_path)
        try:
            size = temp_path.stat().st_size
            if size == 0:
                raise IntegrityError("empty pack upload")
            if expected_id is not None and not PACK_ID_RE.match(expected_id):
                raise IntegrityError("client declared an invalid pack id")
            if expected_id is not None:
                with self._lock:
                    existing = self._db.execute(
                        "SELECT n_objects FROM packs WHERE pack_id = ?", (expected_id,)
                    ).fetchone()
                if existing is not None:
                    actual = sha256_file(temp_path)
                    if actual != expected_id:
                        raise IntegrityError(
                            f"pack checksum mismatch: client declared {expected_id}, received {actual}"
                        )
                    return {
                        "pack": expected_id,
                        "objects": int(existing["n_objects"]),
                        "new_objects": 0,
                        "stored_bytes": 0,
                        "duplicate": True,
                    }
            with open(temp_path, "rb") as handle:
                scan = scan_pack(handle, deep=True, check_objects=True, decoder=decode)
            if scan.bad_objects:
                raise IntegrityError(
                    "pack contains corrupt objects: " + ", ".join(scan.bad_objects[:5])
                )
            pack_id = scan.file_digest
            if expected_id is not None and expected_id != pack_id:
                raise IntegrityError(
                    f"pack checksum mismatch: client declared {expected_id}, received {pack_id}"
                )
            with self._lock:
                existing = self._db.execute(
                    "SELECT n_objects FROM packs WHERE pack_id = ?", (pack_id,)
                ).fetchone()
            if existing is not None:
                return {
                    "pack": pack_id,
                    "objects": int(existing["n_objects"]),
                    "new_objects": 0,
                    "stored_bytes": 0,
                    "duplicate": True,
                }
            final = self._pack_path(pack_id)
            os.replace(temp_path, final)
            fsync_dir(self.packs_dir)
            self._write_pack_index(pack_id, scan.records, size)
            new_objects = self._register_pack(pack_id, scan.records, size, replace=prefer_new)
            return {
                "pack": pack_id,
                "objects": scan.count,
                "new_objects": new_objects,
                "stored_bytes": size,
                "duplicate": False,
            }
        finally:
            temp_path.unlink(missing_ok=True)

    def _write_pack_index(self, pack_id: str, records: dict[str, Location], size: int) -> None:
        payload = {
            "pack": pack_id,
            "size": size,
            "count": len(records),
            "created": utc_iso(),
            "objects": {obj_id: loc.to_json() for obj_id, loc in records.items()},
        }
        write_json(self._index_path(pack_id), payload, mode=0o600)

    def _register_pack(
        self, pack_id: str, records: dict[str, Location], size: int, *, replace: bool = False
    ) -> int:
        """Insert pack metadata; with ``replace`` existing object rows are repointed.

        Client uploads use ``INSERT OR IGNORE``: an object already stored stays
        pointing at the pack that owns it. Repacking must use ``replace`` so the
        live objects move to the new pack before the old one is dropped.
        """
        created = time.time()
        verb = "INSERT OR REPLACE" if replace else "INSERT OR IGNORE"
        rows = [
            (obj_id, pack_id, loc.offset, loc.length, loc.flags, loc.plainlen)
            for obj_id, loc in records.items()
        ]
        with self._tx() as cursor:
            cursor.execute(
                "INSERT OR REPLACE INTO packs (pack_id, size, n_objects, created) VALUES (?,?,?,?)",
                (pack_id, size, len(records), created),
            )
            before = self._db.total_changes
            cursor.executemany(
                f"{verb} INTO objects (obj_id, pack_id, offset, length, flags, plainlen)"
                " VALUES (?,?,?,?,?,?)",
                rows,
            )
            inserted = self._db.total_changes - before
        return int(inserted)

    def pack_ids(self) -> list[str]:
        with self._lock:
            rows = self._db.execute("SELECT pack_id FROM packs ORDER BY pack_id").fetchall()
        return [row["pack_id"] for row in rows]

    def object_exists(self, ids: Iterable[str]) -> list[str]:
        wanted = [item for item in ids if isinstance(item, str)]
        present: list[str] = []
        with self._lock:
            for start in range(0, len(wanted), 500):
                batch = wanted[start : start + 500]
                marks = ",".join("?" * len(batch))
                rows = self._db.execute(
                    f"SELECT obj_id FROM objects WHERE obj_id IN ({marks})", batch
                ).fetchall()
                present.extend(row["obj_id"] for row in rows)
        return present

    def locate(self, ids: Iterable[str]) -> tuple[dict[str, list], list[str]]:
        wanted = [item for item in ids if isinstance(item, str)]
        found: dict[str, list] = {}
        with self._lock:
            for start in range(0, len(wanted), 400):
                batch = wanted[start : start + 400]
                marks = ",".join("?" * len(batch))
                rows = self._db.execute(
                    "SELECT obj_id, pack_id, offset, length, flags, plainlen FROM objects"
                    f" WHERE obj_id IN ({marks})",
                    batch,
                ).fetchall()
                for row in rows:
                    found[row["obj_id"]] = [
                        row["pack_id"],
                        row["offset"],
                        row["length"],
                        row["flags"],
                        row["plainlen"],
                    ]
        missing = [item for item in wanted if item not in found]
        return found, missing

    def read_range(self, pack_id: str, offset: int, length: int) -> bytes:
        self._require_pack_id(pack_id)
        if offset < 0 or length <= 0 or length > MAX_RANGE_BYTES:
            raise UsageError("invalid byte range")
        path = self._pack_path(pack_id)
        try:
            size = path.stat().st_size
        except FileNotFoundError as exc:
            raise NotFoundError(f"pack {pack_id} not found") from exc
        if offset + length > size:
            raise UsageError(
                f"range {offset}+{length} exceeds pack size {size} for {pack_id}"
            )
        with open(path, "rb") as handle:
            handle.seek(offset)
            data = handle.read(length)
        if len(data) != length:
            raise IntegrityError(f"short read from pack {pack_id}")
        return data

    # -- snapshots --------------------------------------------------------
    def _snapshot_path(self, snapshot_id: str) -> Path:
        if not isinstance(snapshot_id, str) or not SNAPSHOT_FILE_RE.match(f"{snapshot_id}.json"):
            raise UsageError("invalid snapshot id")
        return self.snapshots_dir / f"{snapshot_id}.json"

    def put_snapshot(self, manifest: dict) -> dict:
        validate_manifest(manifest, secret=self.secret, require_signature=True)
        snapshot_id = manifest["id"]
        path = self._snapshot_path(snapshot_id)
        body = canonical_json(manifest) + b"\n"
        wanted = referenced_objects(manifest["entries"])
        missing = sorted(set(wanted) - set(self.object_exists(wanted)))
        if missing:
            raise ObjectMissing(
                f"snapshot references {len(missing)} objects the repository does not have",
                detail=", ".join(missing[:5]),
            )
        with self._lock:
            if path.exists():
                existing = path.read_bytes()
                if existing != body:
                    raise ConflictError(
                        f"snapshot {snapshot_id} already exists with different content"
                    )
                return {"id": snapshot_id, "existing": True, "entries": len(manifest["entries"])}
            atomic_write_bytes(path, body, mode=0o600)
            write_json(self._meta_path(snapshot_id), summarize(manifest), mode=0o600)
        return {
            "id": snapshot_id,
            "existing": False,
            "entries": len(manifest["entries"]),
            "objects": len(wanted),
        }

    def _meta_path(self, snapshot_id: str) -> Path:
        return self.snapshots_dir / f"{snapshot_id}{META_SUFFIX}"

    def _snapshot_metas(self) -> list[dict]:
        metas: list[dict] = []
        if not self.snapshots_dir.is_dir():
            return metas
        for name in os.listdir(self.snapshots_dir):
            if not name.endswith(META_SUFFIX) or name.startswith("."):
                continue
            try:
                data = read_json(self.snapshots_dir / name)
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(data, dict) and data.get("id"):
                metas.append(data)
        metas.sort(key=lambda item: (str(item.get("created", "")), str(item["id"])), reverse=True)
        return metas

    def list_snapshots(self, *, host: str | None = None, limit: int | None = None) -> list[dict]:
        metas = self._snapshot_metas()
        if host:
            metas = [meta for meta in metas if meta.get("host") == host]
        if limit:
            metas = metas[:limit]
        return metas

    def get_snapshot(self, snapshot_id: str) -> dict:
        path = self._snapshot_path(snapshot_id)
        if not path.is_file():
            raise NotFoundError(f"snapshot {snapshot_id} not found")
        try:
            manifest = read_json(path)
        except json.JSONDecodeError as exc:
            raise IntegrityError(f"snapshot {snapshot_id} is not valid JSON: {exc}") from exc
        validate_manifest(manifest, secret=self.secret, require_signature=True)
        return manifest

    def delete_snapshot(self, snapshot_id: str, *, missing_ok: bool = False) -> dict:
        path = self._snapshot_path(snapshot_id)
        with self._lock:
            if not path.is_file():
                if missing_ok:
                    return {"id": snapshot_id, "deleted": False}
                raise NotFoundError(f"snapshot {snapshot_id} not found")
            meta = self._meta_path(snapshot_id)
            payload = path.read_bytes()
            path.unlink()
            meta.unlink(missing_ok=True)
        return {
            "id": snapshot_id,
            "deleted": True,
            "bytes": len(payload),
        }

    # -- key management ---------------------------------------------------
    def rotate_secret(self, new_secret: bytes) -> dict:
        """Re-sign every manifest with a new repository secret.

        Run this with the daemon stopped: between the two passes a client racing
        the rotation can see a mix of old and new signatures. Manifests are
        staged as ``.json.new`` and only renamed into place once every signature
        has been checked against the *old* secret, so an interrupted run leaves
        the repository readable.
        """
        from ..manifest import sign_manifest

        if len(new_secret) < 16:
            raise ConfigError("the repository secret must be at least 16 bytes")
        if new_secret == self.secret:
            raise UsageError("the new secret is identical to the current one")
        staged: list[tuple[Path, Path]] = []
        resigned = 0
        already = 0
        try:
            names = sorted(os.listdir(self.snapshots_dir)) if self.snapshots_dir.is_dir() else []
            for name in names:
                if not SNAPSHOT_FILE_RE.match(name):
                    continue
                path = self.snapshots_dir / name
                manifest = read_json(path)
                if verify_manifest(manifest, new_secret):
                    # An interrupted earlier run already re-signed this one; the
                    # algorithm is resumable on purpose (pass 2 is just renames).
                    already += 1
                    write_json(self._meta_path(manifest["id"]), summarize(manifest), mode=0o600)
                    continue
                validate_manifest(manifest, secret=self.secret, require_signature=True)
                body = {key: value for key, value in manifest.items() if key != "signature"}
                renewed = sign_manifest(body, new_secret)
                staged_path = path.with_name(path.name + ".new")
                atomic_write_bytes(staged_path, canonical_json(renewed) + b"\n", mode=0o600)
                meta_path = self._meta_path(manifest["id"])
                meta_staged = meta_path.with_name(meta_path.name + ".new")
                atomic_write_bytes(meta_staged, canonical_json(summarize(renewed)) + b"\n", mode=0o600)
                staged.append((staged_path, path))
                staged.append((meta_staged, meta_path))
                resigned += 1
            for source, target in staged:
                os.replace(source, target)
        except BaseException as exc:
            for staged_path, _target in staged:
                staged_path.unlink(missing_ok=True)
            raise RepositoryError(
                "secret rotation did not complete. Re-run the same command with the same "
                "new secret: manifests signed by the interrupted run are recognised and "
                "skipped."
            ) from exc
        self.secret = new_secret
        return {"resigned": resigned, "already_signed": already}

    # -- retention --------------------------------------------------------
    def _snapshot_facts(self) -> list[dict]:
        """Read and verify every manifest; used by retention decisions.

        The `.meta.json` sidecars are unsigned convenience files, so a policy
        decision may not be based on them alone: a tampered sidecar could make
        `prune` delete the wrong snapshot.
        """
        facts: list[dict] = []
        directory = self.snapshots_dir if self.snapshots_dir.is_dir() else None
        for name in sorted(os.listdir(directory)) if directory else []:
            if not SNAPSHOT_FILE_RE.match(name):
                continue
            try:
                manifest = read_json(self.snapshots_dir / name)
                validate_manifest(manifest, secret=self.secret, require_signature=True)
            except (OSError, json.JSONDecodeError, HavenError) as exc:
                raise RepositoryError(
                    f"cannot verify snapshot {name}; refusing to prune", detail=str(exc)
                ) from exc
            facts.append(
                {"id": manifest["id"], "created": manifest["created"], "host": manifest["host"]}
            )
        return facts

    def prune(
        self,
        policy: RetentionPolicy,
        *,
        apply: bool,
        host: str | None = None,
        now: float | None = None,
    ) -> dict:
        metas = self._snapshot_facts()
        if host:
            metas = [meta for meta in metas if meta.get("host") == host]
        groups: dict[str, list[dict]] = {}
        for meta in metas:
            groups.setdefault(str(meta.get("host", "")), []).append(
                {"id": meta["id"], "created": meta.get("created")}
            )
        keep: set[str] = set()
        drop: set[str] = set()
        for _host, items in groups.items():
            group_keep, group_drop = select_keep(items, policy, now=now)
            keep |= group_keep
            drop |= group_drop
        deleted = []
        if apply:
            for snapshot_id in sorted(drop):
                try:
                    self.delete_snapshot(snapshot_id)
                    deleted.append(snapshot_id)
                except NotFoundError:
                    continue
        return {
            "policy": policy.to_json(),
            "evaluated": len(metas),
            "keep": sorted(keep),
            "delete": sorted(drop),
            "deleted": deleted,
            "applied": bool(apply),
        }

    # -- garbage collection ----------------------------------------------
    def referenced_objects(self) -> set[str]:
        """Union of every object referenced by any *verified* manifest.

        The signature check is the whole point here: GC deletes objects that no
        manifest references, so an unauthenticated (tampered) manifest would
        silently drop references and destroy the only copy of those chunks.
        """
        referenced: set[str] = set()
        directory = self.snapshots_dir if self.snapshots_dir.is_dir() else None
        for name in sorted(os.listdir(directory)) if directory else []:
            if not SNAPSHOT_FILE_RE.match(name):
                continue
            path = self.snapshots_dir / name
            try:
                manifest = read_json(path)
                validate_manifest(manifest, secret=self.secret, require_signature=True)
            except (OSError, json.JSONDecodeError, HavenError) as exc:
                raise RepositoryError(
                    f"cannot verify snapshot {name}; refusing to collect garbage",
                    detail=str(exc),
                ) from exc
            referenced |= referenced_objects(manifest.get("entries", []))
        return referenced

    def gc(self, *, apply: bool, min_age_hours: float = 1.0) -> dict:
        if not math.isfinite(min_age_hours) or min_age_hours < 0:
            raise UsageError("min_age_hours must be a finite number >= 0")
        if apply:
            with FileLock(self.lock_path, exclusive=True, timeout=300):
                return self._gc_locked(apply=True, min_age_hours=min_age_hours)
        return self._gc_locked(apply=False, min_age_hours=min_age_hours)

    def _gc_locked(self, *, apply: bool, min_age_hours: float) -> dict:
        cutoff = time.time() - min_age_hours * 3600.0
        referenced = self.referenced_objects()
        dead: list[tuple[str, int]] = []
        partial: list[tuple[str, int, int]] = []
        total_reclaimable = 0
        with self._lock:
            pack_rows = self._db.execute(
                "SELECT pack_id, size, n_objects, created FROM packs ORDER BY created"
            ).fetchall()
        for row in pack_rows:
            pack_id = row["pack_id"]
            path = self._pack_path(pack_id)
            if not path.exists():
                # Index says the pack exists; drop the stale rows.
                if apply:
                    with self._tx() as cursor:
                        cursor.execute("DELETE FROM objects WHERE pack_id = ?", (pack_id,))
                        cursor.execute("DELETE FROM packs WHERE pack_id = ?", (pack_id,))
                    self._index_path(pack_id).unlink(missing_ok=True)
                continue
            if float(row["created"]) > cutoff:
                continue  # too young: a client may still be committing its snapshot
            with self._lock:
                obj_rows = self._db.execute(
                    "SELECT obj_id FROM objects WHERE pack_id = ?", (pack_id,)
                ).fetchall()
            live = [item["obj_id"] for item in obj_rows if item["obj_id"] in referenced]
            if not live:
                total_reclaimable += int(row["size"])
                dead.append((pack_id, int(row["size"])))
            elif len(live) < len(obj_rows):
                partial.append((pack_id, int(row["size"]), len(obj_rows) - len(live)))
        repacked = []
        if apply:
            for pack_id, _size in dead:
                self._drop_pack(pack_id)
            for pack_id, _size, _dead_count in partial:
                repacked.append(self._repack(pack_id, referenced))
        return {
            "applied": bool(apply),
            "packs": len(pack_rows),
            "dead_packs": len(dead),
            "partial_packs": len(partial),
            "reclaimable_bytes": total_reclaimable,
            "reclaimable_human": human_bytes(total_reclaimable),
            "deleted": [item[0] for item in dead] if apply else [],
            "repacked": repacked,
            "referenced_objects": len(referenced),
        }

    def _drop_pack(self, pack_id: str) -> None:
        with self._tx() as cursor:
            cursor.execute("DELETE FROM objects WHERE pack_id = ?", (pack_id,))
            cursor.execute("DELETE FROM packs WHERE pack_id = ?", (pack_id,))
        self._pack_path(pack_id).unlink(missing_ok=True)
        self._index_path(pack_id).unlink(missing_ok=True)

    def _repack(self, pack_id: str, referenced: set[str]) -> str:
        """Rewrite the live objects of ``pack_id`` into a fresh pack."""
        records = self._load_pack_index(pack_id)
        live = {obj_id: loc for obj_id, loc in records.items() if obj_id in referenced}
        if not live:
            self._drop_pack(pack_id)
            return ""
        tmp = self.tmp_dir / f"repack-{uuid.uuid4().hex}.pack"
        # Preserve object payloads byte for byte; flags are carried over.
        with open(self._pack_path(pack_id), "rb") as source:
            entries = []
            for obj_id, loc in live.items():
                source.seek(loc.offset)
                payload = source.read(loc.length)
                if len(payload) != loc.length:
                    raise IntegrityError(f"pack {pack_id} is truncated")
                entries.append((obj_id, loc.flags, loc.plainlen, payload))
            del source
        new_id, count, size = write_pack_file(tmp, entries)
        if new_id == pack_id:  # nothing to gain
            tmp.unlink(missing_ok=True)
            return pack_id
        result = self.install_pack(tmp, expected_id=new_id, prefer_new=True)
        self._drop_pack(pack_id)
        return str(result["pack"])

    # -- verification -----------------------------------------------------
    def verify(self, *, deep: bool = True, collect_limit: int = 50) -> dict:
        errors: list[str] = []
        checked_objects = 0
        packs = self.pack_ids()
        for pack_id in packs:
            path = self._pack_path(pack_id)
            if not path.exists():
                errors.append(f"pack {pack_id}: index entry without file")
                continue
            try:
                if deep:
                    scan = read_pack_file(path, deep=True, check_objects=True, decoder=decode)
                else:
                    with open(path, "rb") as handle:
                        scan = scan_pack(handle, pack_id=pack_id, deep=False)
                checked_objects += scan.count
                if scan.bad_objects:
                    errors.append(
                        f"pack {pack_id}: {len(scan.bad_objects)} corrupt objects"
                    )
                if scan.file_digest and scan.file_digest != pack_id:
                    errors.append(
                        f"pack {pack_id}: file digest {scan.file_digest[:12]}… does not "
                        "match the pack name"
                    )
            except (IntegrityError, OSError) as exc:
                errors.append(f"pack {pack_id}: {exc}")
            if len(errors) >= collect_limit:
                break
        snapshots_ok = 0
        for name in sorted(os.listdir(self.snapshots_dir)) if self.snapshots_dir.is_dir() else []:
            if not SNAPSHOT_FILE_RE.match(name):
                continue
            snapshot_id = name[: -len(".json")]
            try:
                manifest = read_json(self.snapshots_dir / name)
                validate_manifest(manifest, secret=self.secret, require_signature=True)
                wanted = referenced_objects(manifest["entries"])
                missing = sorted(set(wanted) - set(self.object_exists(wanted)))
                if missing:
                    errors.append(
                        f"snapshot {snapshot_id}: {len(missing)} missing objects"
                    )
                else:
                    snapshots_ok += 1
                errors.extend(self._chunk_length_problems(manifest, limit=collect_limit))
            except Exception as exc:  # noqa: BLE001 - report, never abort a verify run
                errors.append(f"snapshot {snapshot_id}: {exc}")
        return {
            "ok": not errors,
            "deep": bool(deep),
            "packs": len(packs),
            "objects": checked_objects,
            "snapshots": snapshots_ok,
            "errors": errors[:collect_limit],
        }

    def _chunk_length_problems(self, manifest: dict, limit: int = 20) -> list[str]:
        """Compare the length each manifest claims with what is stored.

        A manifest that references a chunk of the wrong size is restorable in
        principle but fails on write; catching it here turns a failed restore
        into a verification finding.
        """
        problems: list[str] = []
        pending: dict[str, int] = {}

        def flush() -> None:
            if not pending:
                return
            found, _missing = self.locate(list(pending))
            for obj_id, expected in pending.items():
                location = found.get(obj_id)
                if location is not None and int(location[4]) != int(expected):
                    problems.append(
                        f"snapshot {manifest['id']}: chunk {obj_id[:12]}… is "
                        f"{location[4]} bytes but the manifest says {expected}"
                    )
            pending.clear()

        for entry in manifest.get("entries", []):
            if entry.get("t") != "f":
                continue
            for obj_id, length in entry_chunks(entry):
                pending[obj_id] = int(length)
                if len(pending) >= 1000:
                    flush()
        flush()
        return problems[:limit]

    # -- index maintenance ------------------------------------------------
    def _ensure_index(self) -> None:
        with self._lock:
            packed = self._db.execute("SELECT COUNT(*) AS n FROM packs").fetchone()["n"]
        on_disk = [name for name in os.listdir(self.packs_dir) if name.endswith(".pack")]
        if packed != len(on_disk):
            # A crash between the pack rename and the index commit (or a first
            # start on an existing repository) leaves them out of sync.
            self.rebuild_index()

    def rebuild_index(self) -> dict:
        """Rebuild the SQLite object index from the pack files on disk."""
        pack_ids: set[str] = set()
        for name in os.listdir(self.packs_dir):
            if name.endswith(".idx.json"):
                pack_ids.add(name[: -len(".idx.json")])
            elif name.endswith(".pack"):
                pack_ids.add(name[: -len(".pack")])
        with self._tx() as cursor:
            cursor.execute("DELETE FROM objects")
            cursor.execute("DELETE FROM packs")
        rebuilt = 0
        objects = 0
        for pack_id in sorted(pack_ids):
            if not PACK_ID_RE.match(pack_id):
                continue
            path = self._pack_path(pack_id)
            if not path.exists():
                self._index_path(pack_id).unlink(missing_ok=True)
                continue
            records = self._load_pack_index(pack_id)
            objects += self._register_pack(pack_id, records, path.stat().st_size, replace=True)
            rebuilt += 1
        if rebuilt:
            LOG.info("rebuilt the object index from %d pack(s), %d object rows", rebuilt, objects)
        return {"packs": rebuilt, "objects": objects}

    def _load_pack_index(self, pack_id: str, *, force: bool = False) -> dict[str, Location]:
        index_path = self._index_path(pack_id)
        if not force and index_path.is_file():
            try:
                data = read_json(index_path)
                records = {
                    obj_id: Location.from_json(pack_id, loc)
                    for obj_id, loc in data["objects"].items()
                }
                if int(data.get("count", -1)) == len(records):
                    return records
            except (OSError, KeyError, ValueError, json.JSONDecodeError):
                pass
        scan = read_pack_file(self._pack_path(pack_id), deep=True, check_objects=True, decoder=decode)
        self._write_pack_index(pack_id, scan.records, self._pack_path(pack_id).stat().st_size)
        return scan.records

    def metrics_text(self) -> str:
        stats = self.stats()
        metas = self._snapshot_metas()
        lines = [
            "# HELP haven_repo_packs Number of pack files.",
            "# TYPE haven_repo_packs gauge",
            f"haven_repo_packs {stats['packs']}",
            "# HELP haven_repo_objects Number of distinct chunks stored.",
            "# TYPE haven_repo_objects gauge",
            f"haven_repo_objects {stats['objects']}",
            "# HELP haven_repo_stored_bytes Physical size of stored packs.",
            "# TYPE haven_repo_stored_bytes gauge",
            f"haven_repo_stored_bytes {stats['stored_bytes']}",
            "# HELP haven_repo_logical_bytes Sum of snapshot payload sizes.",
            "# TYPE haven_repo_logical_bytes gauge",
            f"haven_repo_logical_bytes {stats['logical_bytes']}",
            "# HELP haven_snapshots Number of snapshots per host.",
            "# TYPE haven_snapshots gauge",
        ]
        per_host: dict[str, int] = {}
        for meta in metas:
            per_host[str(meta.get("host", ""))] = per_host.get(str(meta.get("host", "")), 0) + 1
        for host, count in sorted(per_host.items()):
            lines.append(f'haven_snapshots{{host="{host}"}} {count}')
        newest = {}
        for meta in metas:
            stamp = str(meta.get("created", ""))
            if stamp and (meta.get("host") not in newest or stamp > newest[meta.get("host")]):
                newest[meta.get("host")] = stamp
        lines += [
            "# HELP haven_snapshot_last_created_seconds Unix time of the newest snapshot per host.",
            "# TYPE haven_snapshot_last_created_seconds gauge",
        ]
        from ..util import parse_iso

        for host, stamp in sorted(newest.items()):
            try:
                lines.append(f'haven_snapshot_last_created_seconds{{host="{host}"}} {parse_iso(stamp):.0f}')
            except Exception:  # noqa: BLE001 - metrics must never fail a scrape
                continue
        return "\n".join(lines) + "\n"

    def close(self) -> None:
        with self._lock:
            try:
                self._db.close()
            except sqlite3.Error:  # pragma: no cover
                pass
