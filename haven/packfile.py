"""Pack files: the immutable container that stores chunk payloads.

Layout::

    b"HAVENPACK1\\n"
    record*        b"O" | objid[32] | flags[1] | varint(plainlen) | varint(len) | payload
    trailer        b"E" | varint(object_count) | sha256(everything above)[32]

The pack id is the SHA-256 of the whole file, so a pack is content addressed:
re-uploading the same bytes yields the same id and is a no-op. The trailer
makes truncation detectable without an external index; the server rebuilds a
JSON index from the trailer at ingest time and verifies every object hash.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterable, Iterator

from .errors import IntegrityError
from .util import encode_varint, fsync_dir, read_varint

PACK_MAGIC = b"HAVENPACK1\n"
TAG_OBJECT = b"O"
TAG_END = b"E"
ID_SIZE = 32
TRAILER_DIGEST_SIZE = 32


@dataclass(frozen=True)
class Location:
    """Where one object lives inside a pack."""

    pack_id: str
    offset: int
    length: int
    flags: int
    plainlen: int

    def to_json(self) -> list[int]:
        return [self.offset, self.length, self.flags, self.plainlen]

    @classmethod
    def from_json(cls, pack_id: str, data: list[int]) -> "Location":
        offset, length, flags, plainlen = (int(value) for value in data)
        return cls(pack_id, offset, length, flags, plainlen)


@dataclass
class PackScan:
    records: dict[str, Location]
    count: int
    digest_ok: bool
    bad_objects: list[str]
    file_digest: str = ""


class _Writer:
    """File wrapper that hashes everything written through it."""

    def __init__(self, handle: BinaryIO) -> None:
        self.handle = handle
        self.hasher = hashlib.sha256()
        self.written = 0

    def write(self, data: bytes) -> int:
        if data:
            self.hasher.update(data)
        count = self.handle.write(data)
        self.written += count
        return count

    def tell(self) -> int:
        return self.handle.tell()

    def flush(self) -> None:
        self.handle.flush()

    def fileno(self) -> int:
        return self.handle.fileno()

    def digest(self) -> str:
        return self.hasher.hexdigest()


class PackWriter:
    """Builds one pack file. Object order is caller-controlled (stable order
    means identical input produces an identical pack id)."""

    def __init__(self, handle, pack_id: str = "") -> None:
        self._sink = _Writer(handle) if not isinstance(handle, _Writer) else handle
        self.pack_id = pack_id
        self.count = 0
        self.size = 0
        if self._sink.tell() != 0:
            raise ValueError("pack output must start at offset 0")
        self._sink.write(PACK_MAGIC)

    def add(self, obj_id: str, flags: int, plainlen: int, payload: bytes) -> Location:
        raw_id = bytes.fromhex(obj_id)
        if len(raw_id) != ID_SIZE:
            raise ValueError(f"object id must be 32 bytes, got {len(raw_id)}")
        header = (
            TAG_OBJECT
            + raw_id
            + bytes((flags & 0xFF,))
            + encode_varint(plainlen)
            + encode_varint(len(payload))
        )
        self._sink.write(header)
        offset = self._sink.tell()
        self._sink.write(payload)
        self.count += 1
        return Location(self.pack_id, offset, len(payload), flags, plainlen)

    def close(self) -> str:
        """Write the trailer and return the pack id (SHA-256 of the whole file).

        The trailer digest covers every preceding byte, including the ``E``
        tag and the object count; the pack id covers the trailer as well, so
        it equals ``sha256sum <pack>`` and can be checked by any tool.
        """
        count_bytes = encode_varint(self.count)
        self._sink.write(TAG_END + count_bytes)
        state = self._sink.hasher.copy()
        trailer_digest = state.digest()
        self._sink.handle.write(trailer_digest)
        state.update(trailer_digest)
        self._sink.handle.flush()
        self.size = self._sink.tell()
        self.pack_id = state.hexdigest()
        return self.pack_id


def write_pack_file(
    path: os.PathLike[str] | str,
    objects: Iterable[tuple[str, int, int, bytes]],
) -> tuple[str, int, int]:
    """Write ``objects`` (id, flags, plainlen, payload) into a new pack file.

    Returns ``(pack_id, object_count, size)``. The file is written to a
    temporary name and renamed into place so a crash never leaves a partial
    pack under its final name.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(f".{target.name}.tmp-{os.getpid()}")
    digest: str
    count = 0
    try:
        with open(tmp, "wb") as handle:
            writer = PackWriter(handle)
            for obj_id, flags, plainlen, payload in objects:
                writer.add(obj_id, flags, plainlen, payload)
                count += 1
            digest = writer.close()
            size = writer.size
            os.fsync(handle.fileno())
        os.replace(tmp, target)
        fsync_dir(target.parent)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    return digest, count, size


class _Reader:
    """Reads through a hasher when ``hashing`` is set (deep verification)."""

    def __init__(self, handle: BinaryIO, hashing: bool) -> None:
        self.handle = handle
        self.hashing = hashing
        self.hasher = hashlib.sha256() if hashing else None

    def read(self, size: int) -> bytes:
        data = self.handle.read(size)
        if self.hashing and data:
            self.hasher.update(data)
        return data

    def skip(self, size: int) -> None:
        if size < 0:
            raise IntegrityError("negative object length in pack")
        if self.hashing:
            remaining = size
            while remaining:
                block = self.read(min(remaining, 1 << 20))
                if not block:
                    raise IntegrityError("truncated pack payload")
                remaining -= len(block)
        else:
            self.handle.seek(size, os.SEEK_CUR)

    def tell(self) -> int:
        return self.handle.tell()

    def digest(self) -> bytes:
        assert self.hasher is not None
        return self.hasher.digest()

    def state_digest(self) -> bytes | None:
        """Digest of the bytes read so far (``None`` when not hashing)."""
        return self.hasher.digest() if self.hasher is not None else None


def scan_pack(
    handle: BinaryIO,
    *,
    pack_id: str = "",
    deep: bool = False,
    check_objects: bool = False,
    decoder=None,
) -> PackScan:
    """Parse a pack, optionally verifying its trailer and every object hash.

    ``check_objects`` requires ``decoder(flags, payload, plainlen) -> bytes``
    and is only meaningful for unencrypted repositories.
    """
    reader = _Reader(handle, deep or check_objects)
    size_total = os.fstat(handle.fileno()).st_size if _has_fileno(handle) else None
    magic = reader.read(len(PACK_MAGIC))
    if magic != PACK_MAGIC:
        raise IntegrityError("not a Haven pack file (bad magic)")
    records: dict[str, Location] = {}
    bad: list[str] = []
    order: list[str] = []
    while True:
        tag = reader.read(1)
        if not tag:
            raise IntegrityError("truncated pack: missing trailer")
        if tag == TAG_OBJECT:
            raw_id = reader.read(ID_SIZE)
            if len(raw_id) != ID_SIZE:
                raise IntegrityError("truncated object header")
            flag_byte = reader.read(1)
            if not flag_byte:
                raise IntegrityError("truncated object header")
            try:
                plainlen = read_varint(reader)
                length = read_varint(reader)
            except ValueError as exc:
                raise IntegrityError(f"corrupt object header in pack: {exc}") from exc
            offset = reader.tell()
            obj_id = raw_id.hex()
            if size_total is not None and offset + length > size_total:
                # Check before reading: a header claiming a huge length must not
                # make the scanner allocate anything.
                raise IntegrityError("object payload runs past end of pack")
            if check_objects and decoder is not None:
                payload = reader.read(length)
                if len(payload) != length:
                    raise IntegrityError("truncated object payload")
                data = decoder(flag_byte[0], payload, plainlen)
                if hashlib.sha256(data).hexdigest() != obj_id:
                    bad.append(obj_id)
            else:
                reader.skip(length)
            if size_total is not None and reader.tell() > size_total:
                raise IntegrityError("object payload runs past end of pack")
            records[obj_id] = Location(pack_id, offset, length, flag_byte[0], plainlen)
            order.append(obj_id)
        elif tag == TAG_END:
            try:
                count = read_varint(reader)
            except ValueError as exc:
                raise IntegrityError(f"corrupt pack trailer: {exc}") from exc
            computed = reader.state_digest()
            digest = reader.read(TRAILER_DIGEST_SIZE)
            if len(digest) != TRAILER_DIGEST_SIZE:
                raise IntegrityError("truncated pack trailer")
            digest_ok = True
            if computed is not None:
                digest_ok = digest == computed
            if count != len(records):
                raise IntegrityError(
                    f"pack trailer claims {count} objects but {len(records)} were found"
                )
            if not digest_ok:
                raise IntegrityError("pack checksum mismatch (file is corrupt)")
            return PackScan(
                records,
                len(records),
                digest_ok,
                bad,
                reader.digest().hex() if reader.hashing else "",
            )
        else:
            raise IntegrityError(f"unknown pack record tag {tag!r}")


def _has_fileno(handle) -> bool:
    try:
        handle.fileno()
        return True
    except (AttributeError, OSError, ValueError):  # pragma: no cover
        return False


def read_pack_index(path: os.PathLike[str] | str, *, deep: bool = False, check_objects: bool = False) -> dict[str, Location]:
    with open(path, "rb") as handle:
        scan = scan_pack(handle, pack_id=Path(path).stem, deep=deep, check_objects=check_objects)
    return scan.records


def read_pack_file(
    path: os.PathLike[str] | str,
    *,
    deep: bool = True,
    check_objects: bool = False,
    decoder=None,
) -> PackScan:
    with open(path, "rb") as handle:
        return scan_pack(
            handle,
            pack_id=Path(path).stem,
            deep=deep,
            check_objects=check_objects,
            decoder=decoder,
        )


def iter_objects(path: os.PathLike[str] | str) -> Iterator[tuple[str, int, int, bytes]]:
    """Stream ``(obj_id, flags, plainlen, payload)`` from a pack file."""
    with open(path, "rb") as handle:
        if handle.read(len(PACK_MAGIC)) != PACK_MAGIC:
            raise IntegrityError("not a Haven pack file (bad magic)")
        while True:
            tag = handle.read(1)
            if not tag:
                raise IntegrityError("truncated pack: missing trailer")
            if tag == TAG_END:
                return
            if tag != TAG_OBJECT:
                raise IntegrityError(f"unknown pack record tag {tag!r}")
            raw_id = handle.read(ID_SIZE)
            flag_byte = handle.read(1)
            plainlen = read_varint(handle)
            length = read_varint(handle)
            payload = handle.read(length)
            if len(payload) != length:
                raise IntegrityError("truncated object payload")
            yield raw_id.hex(), flag_byte[0], plainlen, payload


def extract_objects(path: os.PathLike[str] | str, locations: dict[str, Location]) -> dict[str, tuple[int, int, bytes]]:
    """Read selected objects from a pack by offset (server-side repack/restore)."""
    out: dict[str, tuple[int, int, bytes]] = {}
    with open(path, "rb") as handle:
        for obj_id, loc in locations.items():
            handle.seek(loc.offset)
            payload = handle.read(loc.length)
            if len(payload) != loc.length:
                raise IntegrityError(f"truncated object {obj_id} in {path}")
            out[obj_id] = (loc.flags, loc.plainlen, payload)
    return out


class Spill:
    """Disk-backed staging area for compressed chunks.

    Backup walks a filesystem and may see hundreds of gigabytes of new data.
    Holding chunk payloads in memory is not an option, so payloads go into a
    temporary file and only metadata stays resident; the final pack is written
    from the spill once the server told us which chunks it already has.
    """

    def __init__(self, workdir: os.PathLike[str] | str) -> None:
        directory = Path(workdir)
        directory.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix="spill-", suffix=".bin", dir=directory)
        self._handle = os.fdopen(fd, "w+b")
        self._path = Path(name)
        # obj_id -> (flags, plainlen, offset, length)
        self._index: dict[str, tuple[int, int, int, int]] = {}
        self._order: list[str] = []
        self.added_bytes = 0

    def __len__(self) -> int:
        return len(self._index)

    def __contains__(self, obj_id: str) -> bool:
        return obj_id in self._index

    def ids(self) -> list[str]:
        return list(self._order)

    def add(self, obj_id: str, flags: int, plainlen: int, payload: bytes) -> bool:
        """Stage one object; returns False when it was already staged."""
        if obj_id in self._index:
            return False
        offset = self.added_bytes
        self._handle.seek(offset)
        self._handle.write(payload)
        self.added_bytes += len(payload)
        self._index[obj_id] = (flags, plainlen, offset, len(payload))
        self._order.append(obj_id)
        return True

    def read(self, obj_id: str) -> tuple[int, int, bytes]:
        """Return ``(flags, plainlen, payload)`` for a staged object."""
        flags, plainlen, offset, length = self._index[obj_id]
        self._handle.flush()
        self._handle.seek(offset)
        payload = self._handle.read(length)
        if len(payload) != length:
            raise IntegrityError(f"spill file truncated for object {obj_id}")
        return flags, plainlen, payload

    def plainlen(self, obj_id: str) -> int:
        """Uncompressed size of a staged object (no I/O)."""
        return self._index[obj_id][1]

    def payload_size(self, obj_id: str) -> int:
        """Stored (compressed) size of a staged object, used for pack splitting."""
        return self._index[obj_id][3]

    def write_pack(self, target: os.PathLike[str] | str, wanted: set[str] | None = None) -> tuple[str, int, int]:
        """Materialise a pack containing ``wanted`` objects (all by default)."""
        selected = [obj for obj in self._order if wanted is None or obj in wanted]
        return write_pack_file(target, ((obj, *self.read(obj)) for obj in selected))

    def cleanup(self) -> None:
        try:
            self._handle.close()
        finally:
            try:
                self._path.unlink()
            except OSError:
                pass
