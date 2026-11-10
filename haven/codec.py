"""Per-chunk compression.

Each stored object carries a codec flag, so a repository can mix codecs (a
future client may compress better without rewriting old packs) and so a pack
with an unreadable codec fails loudly instead of returning wrong bytes.
"""

from __future__ import annotations

import zlib

from .errors import IntegrityError, UsageError

CODEC_RAW = 0
CODEC_ZLIB = 1

CODEC_NAMES = {CODEC_RAW: "raw", CODEC_ZLIB: "zlib"}

# A chunk never exceeds the chunker's maximum (128 MiB). Refusing larger
# declared sizes keeps a hostile pack header from turning into an allocation.
MAX_PLAINTEXT = 128 * 1024 * 1024


def parse_compress_spec(spec: str | None) -> tuple[int, int]:
    """``"none"`` -> raw, ``"zlib"``/``"zlib:9"`` -> (codec, level)."""
    if not spec:
        return CODEC_ZLIB, 6
    text = str(spec).strip().lower()
    if text in ("none", "off", "raw", "0"):
        return CODEC_RAW, 0
    name, _, level_text = text.partition(":")
    if name != "zlib":
        raise UsageError(f"unsupported compression {spec!r} (use none or zlib[:1-9])")
    level = 6
    if level_text:
        try:
            level = int(level_text)
        except ValueError as exc:
            raise UsageError(f"invalid zlib level {level_text!r}") from exc
    if not 0 <= level <= 9:
        raise UsageError("zlib level must be between 0 and 9")
    return CODEC_ZLIB, level


def compress_spec_name(codec: int, level: int) -> str:
    if codec == CODEC_RAW:
        return "none"
    return f"zlib:{level}"


def encode(data: bytes, codec: int, level: int = 6) -> tuple[int, bytes]:
    """Compress ``data``; falls back to raw when compression does not help."""
    if codec == CODEC_RAW or not data:
        return CODEC_RAW, data
    packed = zlib.compress(data, level)
    if len(packed) >= len(data):
        return CODEC_RAW, data
    return CODEC_ZLIB, packed


def decode(flags: int, payload: bytes, plainlen: int) -> bytes:
    """Inverse of :func:`encode`, with length and codec validation.

    Decompression is bounded by ``plainlen``: a zlib payload that expands far
    beyond its declared size raises instead of consuming memory (a 200 KiB
    payload can expand to gigabytes).
    """
    if not isinstance(plainlen, int) or plainlen < 0 or plainlen > MAX_PLAINTEXT:
        raise IntegrityError(f"declared object size {plainlen!r} is out of range")
    if flags == CODEC_RAW:
        if len(payload) != plainlen:
            raise IntegrityError(
                f"raw object length mismatch: got {len(payload)} bytes, expected {plainlen}"
            )
        return payload
    if flags == CODEC_ZLIB:
        engine = zlib.decompressobj()
        try:
            data = engine.decompress(payload, plainlen + 1)
            if len(data) > plainlen or engine.unconsumed_tail:
                raise IntegrityError("object expands beyond its declared size")
            data += engine.flush()
        except zlib.error as exc:
            raise IntegrityError(f"corrupt zlib object: {exc}") from exc
        if len(data) != plainlen:
            raise IntegrityError(
                f"object length mismatch: got {len(data)} bytes, expected {plainlen}"
            )
        return data
    raise IntegrityError(f"unknown codec flag {flags}")
