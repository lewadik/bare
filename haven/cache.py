"""Per-file chunk cache.

Re-reading every file on every run is the dominant cost of a nightly backup.
When ``(size, mtime_ns, ctime_ns)`` are unchanged the file's chunk list from
the previous run is still valid, so the file is never opened. This is the same
trade-off rsync and Borg make: a file whose content changed while its mtime and
ctime were restored by hand will be missed until it is touched again — use
``--no-cache`` for a byte-exact pass.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    path      TEXT PRIMARY KEY,
    size      INTEGER NOT NULL,
    mtime_ns  INTEGER NOT NULL,
    ctime_ns  INTEGER NOT NULL,
    chunker   TEXT NOT NULL,
    chunks    TEXT NOT NULL
) WITHOUT ROWID;
"""


class ChunkCache:
    def __init__(self, path: Path | None, chunker_id: str) -> None:
        self.path = Path(path) if path else None
        self.chunker_id = chunker_id
        self._db: sqlite3.Connection | None = None
        self.hits = 0
        self.misses = 0

    def _connect(self) -> sqlite3.Connection | None:
        if self.path is None:
            return None
        if self._db is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(str(self.path), timeout=30.0)
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=NORMAL")
            self._db.executescript(SCHEMA)
        return self._db

    def get(self, rel_path: str, stat_result: os.stat_result) -> list[tuple[str, int]] | None:
        db = self._connect()
        if db is None:
            return None
        row = db.execute(
            "SELECT size, mtime_ns, ctime_ns, chunker, chunks FROM files WHERE path = ?",
            (rel_path,),
        ).fetchone()
        if row is None:
            self.misses += 1
            return None
        size, mtime_ns, ctime_ns, chunker, chunks_json = row
        if (
            int(size) != int(stat_result.st_size)
            or int(mtime_ns) != int(stat_result.st_mtime_ns)
            or int(ctime_ns) != int(getattr(stat_result, "st_ctime_ns", 0))
            or chunker != self.chunker_id
        ):
            self.misses += 1
            return None
        try:
            raw = json.loads(chunks_json)
            chunks = [(str(item[0]), int(item[1])) for item in raw]
        except (TypeError, ValueError, json.JSONDecodeError):
            self.misses += 1
            return None
        total = sum(length for _obj, length in chunks)
        if total != int(stat_result.st_size):
            self.misses += 1
            return None
        self.hits += 1
        return chunks

    def put(self, rel_path: str, stat_result: os.stat_result, chunks: list[tuple[str, int]]) -> None:
        db = self._connect()
        if db is None:
            return
        db.execute(
            "INSERT OR REPLACE INTO files (path, size, mtime_ns, ctime_ns, chunker, chunks)"
            " VALUES (?,?,?,?,?,?)",
            (
                rel_path,
                int(stat_result.st_size),
                int(stat_result.st_mtime_ns),
                int(getattr(stat_result, "st_ctime_ns", 0)),
                self.chunker_id,
                json.dumps(chunks, separators=(",", ":")),
            ),
        )

    def commit(self) -> None:
        if self._db is not None:
            self._db.commit()

    def forget(self, rel_path: str) -> None:
        db = self._connect()
        if db is not None:
            db.execute("DELETE FROM files WHERE path = ?", (rel_path,))

    def clear(self) -> int:
        db = self._connect()
        if db is None:
            return 0
        count = db.execute("SELECT COUNT(*) FROM files").fetchone()[0]
        db.execute("DELETE FROM files")
        db.commit()
        return int(count)

    def close(self) -> None:
        if self._db is not None:
            self._db.commit()
            self._db.close()
            self._db = None
