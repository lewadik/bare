"""Small, dependency-free helpers: sizes, varints, atomic files, locks, globs."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Iterator

from .errors import ConfigError, UsageError

READ_BLOCK = 1 << 20


# --------------------------------------------------------------------------
# time / formatting
# --------------------------------------------------------------------------
def utc_iso(ts: float | None = None) -> str:
    """ISO-8601 UTC timestamp with millisecond precision and a ``Z`` suffix."""
    moment = datetime.datetime.fromtimestamp(
        time.time() if ts is None else ts, datetime.timezone.utc
    )
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_iso(text: str) -> float:
    """Parse an ISO-8601 timestamp produced by :func:`utc_iso` (or compatible)."""
    try:
        return datetime.datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError as exc:  # pragma: no cover - defensive
        raise UsageError(f"invalid timestamp {text!r}") from exc


def human_bytes(num: float) -> str:
    """Format a byte count with binary units, e.g. ``1.5 GiB``."""
    step = float(num)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(step) < 1024.0 or unit == "PiB":
            if unit == "B":
                return f"{int(step)} B"
            return f"{step:.1f} {unit}"
        step /= 1024.0
    return f"{step:.1f} PiB"  # pragma: no cover - unreachable


def human_duration(seconds: float) -> str:
    seconds = max(0.0, float(seconds))
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, secs = divmod(int(round(seconds)), 60)
    if minutes < 60:
        return f"{minutes}m{secs:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m"


_SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([kmgtpe]?i?b?)?\s*$", re.IGNORECASE)
_SIZE_UNITS = {
    "": 1,
    "b": 1,
    "k": 1024,
    "kb": 1024,
    "ki": 1024,
    "kib": 1024,
    "m": 1024**2,
    "mb": 1024**2,
    "mi": 1024**2,
    "mib": 1024**2,
    "g": 1024**3,
    "gb": 1024**3,
    "gi": 1024**3,
    "gib": 1024**3,
    "t": 1024**4,
    "tb": 1024**4,
    "ti": 1024**4,
    "tib": 1024**4,
    "p": 1024**5,
    "pb": 1024**5,
    "pi": 1024**5,
    "pib": 1024**5,
}


def parse_size(text: str | int) -> int:
    """Parse ``"8M"`` / ``"4 MiB"`` / ``"1048576"`` into a byte count."""
    if isinstance(text, int):
        return text
    match = _SIZE_RE.match(str(text))
    if not match:
        raise UsageError(f"invalid size value {text!r}")
    number, unit = match.group(1), (match.group(2) or "").lower()
    if unit not in _SIZE_UNITS:
        raise UsageError(f"unknown size unit {unit!r}")
    return int(float(number) * _SIZE_UNITS[unit])


# --------------------------------------------------------------------------
# hashing / encoding
# --------------------------------------------------------------------------
def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: os.PathLike[str] | str, block: int = READ_BLOCK) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(block)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON used for signatures and on-disk metadata.

    Non-ASCII names are kept readable. Filenames that are not valid UTF-8
    arrive as lone surrogates, which cannot be encoded; in that case the
    escaped form is used. The choice depends only on the content, so client
    and server always agree on the bytes that were signed.
    """
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def encode_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("varint must be non-negative")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def decode_varint(buf: bytes | bytearray | memoryview, pos: int = 0) -> tuple[int, int]:
    """Decode a LEB128 varint from ``buf``; returns ``(value, next_pos)``."""
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated varint")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


def read_varint(handle) -> int:
    """Decode a varint from a binary stream."""
    result = 0
    shift = 0
    while True:
        raw = handle.read(1)
        if not raw:
            raise ValueError("truncated varint")
        byte = raw[0]
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


# --------------------------------------------------------------------------
# filesystem
# --------------------------------------------------------------------------
def ensure_dir(path: os.PathLike[str] | str, mode: int = 0o700) -> Path:
    target = Path(path)
    target.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(target, mode)
    except OSError:  # pragma: no cover - exotic filesystems
        pass
    return target


def fsync_dir(path: os.PathLike[str] | str) -> None:
    """Flush a directory entry to disk (POSIX). Silently skipped elsewhere."""
    if os.name != "posix":  # pragma: no cover - Windows has no directory fsync
        return
    fd = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write_bytes(path: os.PathLike[str] | str, data: bytes, mode: int = 0o600) -> None:
    """Write ``data`` to ``path`` atomically (temp file + rename + fsync)."""
    target = Path(path)
    ensure_dir(target.parent)
    tmp = target.with_name(f".{target.name}.tmp-{os.getpid()}-{int(time.time() * 1000) % 100000}")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, target)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    fsync_dir(target.parent)


def write_json(path: os.PathLike[str] | str, obj: Any, mode: int = 0o600) -> None:
    atomic_write_bytes(path, canonical_json(obj) + b"\n", mode=mode)


def read_json(path: os.PathLike[str] | str) -> Any:
    with open(path, "rb") as handle:
        return json.loads(handle.read().decode("utf-8"))


class FileLock:
    """Advisory exclusive/shared lock with a timeout, on POSIX and Windows."""

    def __init__(self, path: os.PathLike[str] | str, *, exclusive: bool = True, timeout: float = 120.0) -> None:
        self.path = Path(path)
        self.exclusive = exclusive
        self.timeout = timeout
        self._handle = None

    def acquire(self) -> "FileLock":
        ensure_dir(self.path.parent)
        handle = open(self.path, "a+b")
        if os.fstat(handle.fileno()).st_size == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        deadline = time.monotonic() + self.timeout
        delay = 0.01
        while True:
            try:
                self._lock(handle)
                self._handle = handle
                return self
            except OSError:
                if time.monotonic() >= deadline:
                    handle.close()
                    raise ConfigError(f"timed out waiting for lock {self.path}")
                time.sleep(delay)
                delay = min(delay * 1.5, 0.25)

    def _lock(self, handle) -> None:
        if os.name == "nt":  # pragma: no cover - exercised on Windows only
            import msvcrt

            mode = msvcrt.LK_NBLCK
            msvcrt.locking(handle.fileno(), mode, 1)
        else:
            import fcntl

            flags = fcntl.LOCK_EX if self.exclusive else fcntl.LOCK_SH
            fcntl.flock(handle.fileno(), flags | fcntl.LOCK_NB)

    def release(self) -> None:
        handle = self._handle
        if handle is None:
            return
        self._handle = None
        try:
            if os.name == "nt":  # pragma: no cover
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()

    def __enter__(self) -> "FileLock":
        return self.acquire()

    def __exit__(self, *_exc) -> None:
        self.release()


def listdir_sorted(path: os.PathLike[str] | str) -> list[os.DirEntry]:
    """Directory entries sorted by name for deterministic snapshots."""
    with os.scandir(path) as scan:
        return sorted(scan, key=lambda item: item.name)


def to_rel_posix(abs_path: os.PathLike[str] | str, anchor: os.PathLike[str] | str) -> str:
    """Path relative to ``anchor`` (a filesystem root), normalised to POSIX form."""
    rel = os.path.relpath(str(abs_path), str(anchor))
    return PurePosixPath(rel.replace(os.sep, "/")).as_posix()


def safe_rel_parts(rel: str) -> tuple[str, ...]:
    """Split a manifest path, rejecting absolute paths and traversal.

    Manifests are untrusted input on restore: a snapshot must never be able to
    write outside the restore target.
    """
    if not isinstance(rel, str) or not rel:
        raise ConfigError("empty path in snapshot")
    if "\x00" in rel:
        raise ConfigError("NUL byte in snapshot path")
    text = rel.replace("\\", "/")
    if text.startswith("/") or re.match(r"^[A-Za-z]:", text):
        raise ConfigError(f"absolute path in snapshot: {rel!r}")
    parts: list[str] = []
    for part in text.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            raise ConfigError(f"path traversal in snapshot: {rel!r}")
        parts.append(part)
    if not parts:
        raise ConfigError(f"invalid empty path in snapshot: {rel!r}")
    return tuple(parts)


# --------------------------------------------------------------------------
# glob matching (workspace-relative paths, POSIX separators)
# --------------------------------------------------------------------------
def glob_to_regex(pattern: str) -> str:
    """Translate a glob into a regex body with ``**`` semantics.

    ``a/**`` matches both ``a`` and everything below it, which is what an
    exclude rule needs (excluding the directory itself, not only its content).
    """
    if pattern.endswith("/**"):
        base = pattern[:-3]
        inner = glob_to_regex(base) if base else "."
        return f"(?:{inner}(?:/.*)?)"
    out: list[str] = []
    i = 0
    length = len(pattern)
    while i < length:
        char = pattern[i]
        if char == "*":
            j = i
            while j < length and pattern[j] == "*":
                j += 1
            if j - i >= 2:  # '**'
                if j < length and pattern[j] == "/":
                    out.append("(?:.*/)?")
                    j += 1
                else:
                    out.append(".*")
            else:
                out.append("[^/]*")
            i = j
        elif char == "?":
            out.append("[^/]")
            i += 1
        elif char == "[":
            j = pattern.find("]", i + 1)
            if j == -1:
                out.append(r"\[")
                i += 1
                continue
            body = pattern[i + 1 : j]
            if body.startswith("!"):
                body = "^" + body[1:]
            out.append("[" + body.replace("\\", "\\\\") + "]")
            i = j + 1
        else:
            out.append(re.escape(char))
            i += 1
    return "".join(out)


class GlobSet:
    """Ordered glob rules; a later rule wins, ``!pattern`` re-includes.

    Patterns without ``/`` match the basename at any depth (gitignore style);
    patterns with ``/`` match the whole relative path. A trailing ``/`` makes
    the rule apply to directories only.
    """

    def __init__(self, patterns: Iterable[str] = ()) -> None:
        self.rules: list[tuple[re.Pattern[str], bool, bool]] = []  # (regex, negated, dir_only)
        self.patterns: list[str] = []
        for raw in patterns:
            raw = str(raw).strip()
            if not raw or raw.startswith("#"):
                continue
            negated = raw.startswith("!")
            if negated:
                raw = raw[1:].strip()
            raw = raw.lstrip("./") if raw.startswith("./") else raw
            anchored = raw.startswith("/")
            raw = raw.lstrip("/")
            dir_only = raw.endswith("/")
            raw = raw.rstrip("/")
            if not raw:
                continue
            body = glob_to_regex(raw)
            # A pattern without a separator matches at any depth.
            if "/" not in raw and not anchored:
                body = "(?:.*/)?" + body
            self.rules.append((re.compile(body + r"\Z", re.S), negated, dir_only))
            self.patterns.append(("!" if negated else "") + raw + ("/" if dir_only else ""))

    def __bool__(self) -> bool:
        return bool(self.rules)

    def matches(self, rel_path: str, *, is_dir: bool = False) -> bool:
        """True when the path is selected (last matching rule wins)."""
        decision = False
        for regex, negated, dir_only in self.rules:
            if dir_only and not is_dir:
                continue
            if regex.match(rel_path):
                decision = not negated
        return decision

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"GlobSet({self.patterns!r})"


def unique(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def die(message: str, code: int = 1) -> None:  # pragma: no cover - CLI helper
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(code)


def chunks_of(seq: list, size: int) -> Iterator[list]:
    for start in range(0, len(seq), size):
        yield seq[start : start + size]
