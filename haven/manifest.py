"""Snapshot manifests: the signed description of one backup.

A manifest is the unit of trust on restore. It is plain JSON (reviewable with
``zless``/``jq``), HMAC-signed with the repository secret, and validated
strictly before use: an untrusted manifest must never be able to write outside
the restore target or make the client read arbitrary files.

Schema (format 1)::

    {
      "format": 1,
      "id": "20261110T130000Z-1a2b3c4d",
      "created": "2026-11-10T13:00:00.123Z",
      "host": "web-01",
      "label": "nightly",
      "paths": ["/etc", "/srv/www"],
      "chunker": {"algo": "gear", "version": 1, "min": 65536, "avg": 1048576, "max": 8388608},
      "codec": "zlib:6",
      "excludes": ["/proc", "*.tmp"],
      "stats": {"files": 12, "dirs": 3, "symlinks": 1, "errors": 0,
                "bytes_total": 4096, "bytes_new": 1024, "chunks": 7, "chunks_new": 2},
      "entries": [
        {"p": "etc", "t": "d", "m": 493, "mt": 1762776000.0, "u": 0, "g": 0},
        {"p": "etc/hosts", "t": "f", "m": 420, "mt": 1762776000.0, "s": 300,
         "c": [["<sha256>", 300]]},
        {"p": "etc/localtime", "t": "l", "m": 511, "tg": "/usr/share/zoneinfo/UTC"}
      ],
      "duration_ms": 812,
      "haven_version": "1.0.0",
      "signature": "hmac-sha256:<hex>"
    }
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import re
import secrets
import time
from typing import Any, Iterable

from .chunker import ChunkParams
from .errors import ConfigError, IntegrityError
from .util import canonical_json, parse_iso, safe_rel_parts, utc_iso

FORMAT = 1
SIGNATURE_PREFIX = "hmac-sha256:"
SNAPSHOT_ID_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$")
OBJECT_ID_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_ENTRIES = 5_000_000
ENTRY_TYPES = ("f", "d", "l", "x")  # file, directory, symlink, skipped/error


def mac_key(secret: bytes) -> bytes:
    """Domain-separated key, so the repo secret is never used directly."""
    return hmac.new(secret, b"haven-manifest-v1", hashlib.sha256).digest()


def sign_manifest(manifest: dict, secret: bytes) -> dict:
    body = {key: value for key, value in manifest.items() if key != "signature"}
    digest = hmac.new(mac_key(secret), canonical_json(body), hashlib.sha256).hexdigest()
    signed = dict(manifest)
    signed["signature"] = SIGNATURE_PREFIX + digest
    return signed


def verify_manifest(manifest: dict, secret: bytes) -> bool:
    signature = manifest.get("signature")
    if not isinstance(signature, str) or not signature.startswith(SIGNATURE_PREFIX):
        return False
    body = {key: value for key, value in manifest.items() if key != "signature"}
    expected = hmac.new(mac_key(secret), canonical_json(body), hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature[len(SIGNATURE_PREFIX) :], expected)


def new_snapshot_id(now: float | None = None) -> str:
    moment = datetime.datetime.fromtimestamp(
        time.time() if now is None else now, datetime.timezone.utc
    )
    return moment.strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)


def snapshot_created(snapshot_id: str) -> float:
    """Timestamp encoded in a snapshot id (used for retention bucketing)."""
    try:
        moment = datetime.datetime.strptime(snapshot_id[:16], "%Y%m%dT%H%M%SZ")
    except ValueError as exc:
        raise ConfigError(f"invalid snapshot id {snapshot_id!r}") from exc
    return moment.replace(tzinfo=datetime.timezone.utc).timestamp()


def summarize(manifest: dict) -> dict:
    """Compact representation used by ``snapshot list`` and the API."""
    return {
        "id": manifest.get("id"),
        "created": manifest.get("created"),
        "host": manifest.get("host"),
        "label": manifest.get("label") or "",
        "paths": manifest.get("paths") or [],
        "stats": manifest.get("stats") or {},
        "duration_ms": manifest.get("duration_ms"),
        "size": _manifest_size(manifest),
    }


def _manifest_size(manifest: dict) -> int:
    existing = manifest.get("manifest_bytes")
    if isinstance(existing, int):
        return existing
    try:
        return len(canonical_json(manifest))
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return 0


def validate_manifest(
    manifest: Any,
    *,
    secret: bytes | None = None,
    require_signature: bool = True,
) -> dict:
    """Validate structure and signature; returns the manifest unchanged.

    Raises :class:`ConfigError` for bad structure and :class:`IntegrityError`
    for a bad signature.
    """
    if not isinstance(manifest, dict):
        raise ConfigError("manifest must be a JSON object")
    if manifest.get("format") != FORMAT:
        raise ConfigError(f"unsupported manifest format {manifest.get('format')!r}")
    snapshot_id = manifest.get("id")
    if not isinstance(snapshot_id, str) or not SNAPSHOT_ID_RE.match(snapshot_id):
        raise ConfigError(f"invalid snapshot id {snapshot_id!r}")
    created = manifest.get("created")
    if not isinstance(created, str):
        raise ConfigError("manifest is missing 'created'")
    parse_iso(created)
    host = manifest.get("host")
    if not isinstance(host, str) or not host or len(host) > 255:
        raise ConfigError("manifest is missing a valid 'host'")
    paths = manifest.get("paths")
    if not isinstance(paths, list) or not all(isinstance(item, str) for item in paths):
        raise ConfigError("manifest 'paths' must be a list of strings")
    chunker = manifest.get("chunker")
    if not isinstance(chunker, dict):
        raise ConfigError("manifest is missing 'chunker'")
    ChunkParams.from_json(chunker)
    entries = manifest.get("entries")
    if not isinstance(entries, list):
        raise ConfigError("manifest 'entries' must be a list")
    if len(entries) > MAX_ENTRIES:
        raise ConfigError(f"manifest has too many entries ({len(entries)})")
    seen: dict[str, str] = {}
    for entry in entries:
        _validate_entry(entry)
        rel = entry["p"]
        if rel in seen:
            raise ConfigError(f"duplicate path in manifest: {rel!r}")
        hardlink = entry.get("hl")
        if hardlink is not None:
            # A hardlink entry must point at a file that was already described,
            # otherwise restore would link to whatever happens to be on disk.
            if hardlink not in seen:
                raise ConfigError(
                    f"entry {rel!r} links to {hardlink!r}, which is not an earlier entry"
                )
            if seen[hardlink] != "f":
                raise ConfigError(
                    f"entry {rel!r} links to {hardlink!r}, which is not a regular file"
                )
        seen[rel] = entry["t"]
    if require_signature:
        if secret is None:
            raise ConfigError("repository secret is required to validate manifests")
        if not verify_manifest(manifest, secret):
            raise IntegrityError(
                f"manifest {snapshot_id} signature is invalid "
                "(wrong repository secret or tampered metadata)"
            )
    return manifest


def _validate_entry(entry: Any) -> None:
    if not isinstance(entry, dict):
        raise ConfigError("manifest entries must be objects")
    rel = entry.get("p")
    if not isinstance(rel, str):
        raise ConfigError("entry is missing a path")
    safe_rel_parts(rel)
    kind = entry.get("t")
    if kind not in ENTRY_TYPES:
        raise ConfigError(f"entry {rel!r} has unknown type {kind!r}")
    mode = entry.get("m", 0o600)
    if not isinstance(mode, int) or mode < 0 or mode > 0o7777:
        raise ConfigError(f"entry {rel!r} has an invalid mode")
    mtime = entry.get("mt", 0.0)
    if not isinstance(mtime, (int, float)):
        raise ConfigError(f"entry {rel!r} has an invalid mtime")
    if kind == "f":
        size = entry.get("s")
        if not isinstance(size, int) or size < 0:
            raise ConfigError(f"file entry {rel!r} has an invalid size")
        chunks = entry.get("c")
        if not isinstance(chunks, list):
            raise ConfigError(f"file entry {rel!r} is missing its chunk list")
        total = 0
        for item in chunks:
            if (
                not isinstance(item, (list, tuple))
                or len(item) != 2
                or not isinstance(item[0], str)
                or not OBJECT_ID_RE.match(item[0])
                or not isinstance(item[1], int)
                or item[1] <= 0
            ):
                raise ConfigError(f"file entry {rel!r} has an invalid chunk reference")
            total += item[1]
        if total != size:
            raise ConfigError(
                f"file entry {rel!r}: chunk lengths sum to {total} but size is {size}"
            )
    elif kind == "l":
        target = entry.get("tg")
        if not isinstance(target, str) or not target:
            raise ConfigError(f"symlink entry {rel!r} is missing its target")
    if entry.get("hl") is not None:
        hardlink = entry.get("hl")
        if kind != "f":
            raise ConfigError(f"only file entries may be hardlinks ({rel!r})")
        if not isinstance(hardlink, str):
            raise ConfigError(f"hardlink target of {rel!r} must be a string")
        safe_rel_parts(hardlink)
    elif kind == "x":
        if not isinstance(entry.get("e"), str):
            raise ConfigError(f"skipped entry {rel!r} is missing its error message")


def entry_chunks(entry: dict) -> list[tuple[str, int]]:
    return [(item[0], int(item[1])) for item in entry.get("c", [])]


def referenced_objects(entries: Iterable[dict]) -> set[str]:
    out: set[str] = set()
    for entry in entries:
        if entry.get("t") == "f":
            for obj_id, _length in entry_chunks(entry):
                out.add(obj_id)
    return out


def make_manifest(
    *,
    snapshot_id: str,
    host: str,
    paths: list[str],
    entries: list[dict],
    chunker: ChunkParams,
    codec: str,
    excludes: list[str],
    stats: dict,
    label: str = "",
    created: float | None = None,
    duration_ms: int = 0,
    haven_version: str = "1.0.0",
    secret: bytes | None = None,
) -> dict:
    """Assemble (and optionally sign) a manifest."""
    manifest: dict[str, Any] = {
        "format": FORMAT,
        "id": snapshot_id,
        "created": utc_iso(created if created is not None else time.time()),
        "host": host,
        "label": label,
        "paths": paths,
        "chunker": chunker.to_json(),
        "codec": codec,
        "excludes": excludes,
        "stats": stats,
        "entries": entries,
        "duration_ms": duration_ms,
        "haven_version": haven_version,
    }
    if secret is not None:
        manifest = sign_manifest(manifest, secret)
    return manifest
