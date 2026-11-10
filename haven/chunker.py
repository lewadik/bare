"""Content-defined chunking.

Boundaries are chosen with a gear rolling hash (the scheme used by FastCDC):
``h = (h << 1) + gear[byte]`` and a cut whenever the low ``bits`` of ``h`` are
zero. Only the trailing ~64 bytes influence ``h``, so an insertion or deletion
changes boundaries only until the next cut, after which chunking re-syncs.
That is what keeps deduplication working across edits of large files.

``fixed`` mode is also provided: it is ~50x faster (it only hashes aligned
blocks) but loses most deduplication after an insertion, so it is meant for
media/VM volumes where files rarely change in place.

The hash table is generated from a fixed seed, so every client and server
version derives identical boundaries: a snapshot's chunk list is portable.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import BinaryIO, Iterator

from .errors import ConfigError, UsageError

MASK64 = (1 << 64) - 1
GEAR_VERSION = 1


def _gear_table(seed: int, size: int = 256) -> tuple[int, ...]:
    """splitmix64-derived gear table (identical on every platform/Python)."""
    values: list[int] = []
    state = seed
    for _ in range(size):
        state = (state + 0x9E3779B97F4A7C15) & MASK64
        z = state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
        values.append(z ^ (z >> 31))
    return tuple(values)


GEAR = _gear_table(0x5AFEB10C)


@dataclass(frozen=True)
class ChunkParams:
    """Chunk-size parameters. ``average`` drives the cut probability."""

    minimum: int = 64 * 1024
    average: int = 1024 * 1024
    maximum: int = 8 * 1024 * 1024
    version: int = GEAR_VERSION
    mode: str = "gear"

    def __post_init__(self) -> None:
        if self.mode not in ("gear", "fixed"):
            raise UsageError(f"unknown chunking mode {self.mode!r}")
        if self.minimum < 1:
            raise UsageError("chunk minimum must be > 0")
        if self.maximum < self.minimum:
            raise UsageError("chunk maximum must be >= minimum")
        if self.mode == "gear" and not (self.minimum < self.average <= self.maximum):
            raise UsageError("chunk average must be between minimum and maximum")
        if self.maximum > 128 * 1024 * 1024:
            raise UsageError("chunk maximum is limited to 128 MiB")

    @property
    def bits(self) -> int:
        return max(4, int(round(math.log2(max(16, self.average)))))

    @property
    def mask(self) -> int:
        return (1 << self.bits) - 1

    def identifier(self) -> str:
        """Stable id; a change here invalidates the per-file chunk cache."""
        return f"{self.mode}{self.version}:{self.minimum}:{self.average}:{self.maximum}"

    def to_json(self) -> dict:
        return {
            "algo": self.mode,
            "version": self.version,
            "min": self.minimum,
            "avg": self.average,
            "max": self.maximum,
        }

    @classmethod
    def from_json(cls, data: dict) -> "ChunkParams":
        try:
            return cls(
                minimum=int(data["min"]),
                average=int(data["avg"]),
                maximum=int(data["max"]),
                version=int(data.get("version", GEAR_VERSION)),
                mode=str(data.get("algo", "gear")),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ConfigError(f"invalid chunker description in manifest: {data!r}") from exc


def parse_chunking_spec(spec: str) -> ChunkParams:
    """``"average=1M"`` style spec, or ``"fixed=8M"``."""
    text = str(spec).strip()
    if text.startswith("fixed"):
        size_text = text.split("=", 1)[1] if "=" in text else "4M"
        from .util import parse_size  # local import keeps module import cheap

        size = parse_size(size_text)
        return ChunkParams(minimum=size, average=size, maximum=size, mode="fixed")
    from .util import parse_size

    params = text.split(",")
    values = {}
    for item in params:
        if not item:
            continue
        key, _, value = item.partition("=")
        values[key.strip().lower()] = parse_size(value.strip())
    minimum = values.get("min", 64 * 1024)
    average = values.get("avg", values.get("average", 1024 * 1024))
    maximum = values.get("max", max(8 * 1024 * 1024, average * 8))
    return ChunkParams(minimum=minimum, average=average, maximum=maximum)


def _find_cut(buf: bytes, start: int, limit: int, mask: int) -> int:
    """Return the offset just past the next boundary, or ``limit``."""
    h = 0
    gear = GEAR
    i = start
    while i < limit:
        h = ((h << 1) + gear[buf[i]]) & MASK64
        if not (h & mask):
            return i + 1
        i += 1
    return limit


def iter_chunks(handle: BinaryIO, params: ChunkParams, read_size: int = 1 << 20) -> Iterator[bytes]:
    """Yield chunks of ``handle`` according to ``params``."""
    min_size, max_size = params.minimum, params.maximum
    if params.mode == "fixed":
        while True:
            block = handle.read(min_size)
            if not block:
                return
            yield block
            if len(block) < min_size:
                return

    buffer = b""
    eof = False
    mask = params.mask
    while True:
        while len(buffer) < max_size and not eof:
            block = handle.read(read_size)
            if block:
                buffer += block
                if len(buffer) >= max_size:
                    break
            else:
                eof = True
        if not buffer:
            return
        if len(buffer) <= min_size:
            # Only reachable at EOF: the tail is smaller than the minimum.
            yield buffer
            return
        limit = min(len(buffer), max_size)
        cut = _find_cut(buffer, min_size, limit, mask)
        yield buffer[:cut]
        buffer = buffer[cut:]


def chunk_bytes(data: bytes, params: ChunkParams) -> list[bytes]:
    """Convenience wrapper for tests and small buffers."""
    if params.mode == "fixed":
        return [data[i : i + params.minimum] for i in range(0, len(data), params.minimum)]
    out: list[bytes] = []
    start = 0
    length = len(data)
    while start < length:
        limit = min(start + params.maximum, length)
        if limit - start <= params.minimum:
            out.append(data[start:limit])
            break
        cut = _find_cut(data, start + params.minimum, limit, params.mask)
        out.append(data[start:cut])
        start = cut
    return out


def chunk_hashes(data: bytes, params: ChunkParams) -> list[tuple[str, int]]:
    return [
        (hashlib.sha256(chunk).hexdigest(), len(chunk))
        for chunk in chunk_bytes(data, params)
    ]
