"""HTTP transport and the typed client API for the repository daemon.

Only the standard library is used (``http.client`` + ``ssl``), so the client
runs on any Linux box with ``python3`` and no site-packages. All write
operations are idempotent (content-addressed packs, snapshot ids), which is
what makes retrying a dropped upload safe.
"""

from __future__ import annotations

import http.client
import json
import os
import random
import ssl
import time
from dataclasses import dataclass
from typing import Callable, Iterator
from urllib.parse import quote, urlsplit

from . import PROTOCOL_VERSION, __version__
from .errors import (
    ErrorFactory,
    HavenError,
    ProtocolError,
    UsageError,
)
from .manifest import validate_manifest

RETRY_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})
JSON_LIMIT = 64 * 1024 * 1024


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> dict:
        if not self.body:
            return {}
        try:
            return json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProtocolError(f"server returned invalid JSON: {exc}") from exc


class _ProgressReader:
    """File wrapper that reports upload progress through http.client."""

    def __init__(self, handle, total: int, callback: Callable[[int, int], None] | None) -> None:
        self.handle = handle
        self.total = total
        self.sent = 0
        self.callback = callback
        self._last_report = 0.0

    def read(self, size: int = -1) -> bytes:
        data = self.handle.read(size)
        if data:
            self.sent += len(data)
            now = time.monotonic()
            if self.callback and (now - self._last_report > 1.0 or self.sent >= self.total):
                self._last_report = now
                self.callback(self.sent, self.total)
        return data

    def tell(self) -> int:
        return self.handle.tell()

    def seek(self, offset: int, whence: int = 0) -> int:
        self.sent = 0
        return self.handle.seek(offset, whence)


class Transport:
    """One HTTP(S) endpoint with bearer auth, retries and error mapping."""

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout: float = 60.0,
        retries: int = 3,
        ca_file: str | None = None,
        insecure: bool = False,
    ) -> None:
        parts = urlsplit(base_url)
        if parts.scheme not in ("http", "https"):
            raise UsageError(f"unsupported URL scheme {parts.scheme!r}")
        self.scheme = parts.scheme
        self.host = parts.hostname or "127.0.0.1"
        self.port = parts.port or (443 if self.scheme == "https" else 80)
        self.prefix = parts.path.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.retries = retries
        self.ca_file = ca_file
        self.insecure = insecure
        self._ssl_context: ssl.SSLContext | None = None

    # -- plumbing ---------------------------------------------------------
    def _context(self) -> ssl.SSLContext:
        if self._ssl_context is None:
            if self.insecure:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            else:
                context = ssl.create_default_context(cafile=self.ca_file)
            self._ssl_context = context
        return self._ssl_context

    def _connect(self, timeout: float) -> http.client.HTTPConnection:
        if self.scheme == "https":
            connection: http.client.HTTPConnection = http.client.HTTPSConnection(
                self.host, self.port, timeout=timeout, context=self._context()
            )
        else:
            connection = http.client.HTTPConnection(self.host, self.port, timeout=timeout)
        connection.blocksize = 1 << 20
        return connection

    def url_for(self, path: str) -> str:
        return f"{self.prefix}{path}"

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        body_file=None,
        content_length: int | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        retries: int | None = None,
    ) -> Response:
        attempts = self.retries if retries is None else retries
        request_headers = {
            "Authorization": f"Bearer {self.token}",
            "User-Agent": f"haven/{__version__}",
            "X-Haven-Protocol": str(PROTOCOL_VERSION),
            "Accept": "application/json",
        }
        if headers:
            request_headers.update(headers)
        if body is not None:
            request_headers["Content-Length"] = str(len(body))
        elif content_length is not None:
            request_headers["Content-Length"] = str(content_length)
        last_error: Exception | None = None
        for attempt in range(attempts + 1):
            if attempt:
                delay = min(8.0, 0.4 * (2 ** (attempt - 1))) * (0.7 + random.random() * 0.6)
                time.sleep(delay)
                if body_file is not None:
                    body_file.seek(0)
            connection = None
            try:
                connection = self._connect(timeout or self.timeout)
                payload = body if body is not None else body_file
                connection.request(method, self.url_for(path), body=payload, headers=request_headers)
                raw = connection.getresponse()
                data = raw.read()
                response = Response(raw.status, {k.lower(): v for k, v in raw.getheaders()}, data)
                if response.status in RETRY_STATUS and attempt < attempts:
                    last_error = ProtocolError(
                        f"server busy ({response.status}) on {method} {path}"
                    )
                    continue
                self._raise_for_status(response, method, path)
                return response
            except (OSError, http.client.HTTPException) as exc:
                last_error = ProtocolError(f"{method} {path} failed: {exc}")
                if attempt >= attempts:
                    raise last_error from exc
            finally:
                if connection is not None:
                    connection.close()
        assert last_error is not None
        raise last_error

    def _raise_for_status(self, response: Response, method: str, path: str) -> None:
        if 200 <= response.status < 300:
            return
        message = f"{method} {path} -> HTTP {response.status}"
        code = None
        detail = None
        if response.body:
            try:
                payload = json.loads(response.body.decode("utf-8"))
                error = payload.get("error") if isinstance(payload, dict) else None
                if isinstance(error, dict):
                    code = error.get("code")
                    message = error.get("message") or message
                    detail = error.get("detail")
            except (UnicodeDecodeError, json.JSONDecodeError):
                detail = response.body[:200].decode("utf-8", "replace")
        error_type = ErrorFactory.get(code or "", HavenError)
        raise error_type(message, detail=detail)

    def get_json(self, path: str, **kwargs) -> dict:
        return self.request("GET", path, **kwargs).json()

    def post_json(self, path: str, payload: dict | None = None, **kwargs) -> dict:
        body = b"" if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        headers.update(kwargs.pop("headers", {}) or {})
        return self.request("POST", path, body=body, headers=headers, **kwargs).json()

    def put_json(self, path: str, payload: dict, **kwargs) -> dict:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        return self.request(
            "PUT", path, body=body, headers={"Content-Type": "application/json"}, **kwargs
        ).json()

    def delete_json(self, path: str, **kwargs) -> dict:
        return self.request("DELETE", path, **kwargs).json()


class RemoteRepo:
    """The repository API as used by backup/restore/prune.

    With a repository secret, manifested snapshots are validated locally as
    well: a compromised or buggy server cannot hand the client metadata that
    the signature does not cover.
    """

    def __init__(self, transport: Transport, secret: bytes | None = None) -> None:
        self.transport = transport
        self.secret = secret

    @classmethod
    def from_config(cls, config) -> "RemoteRepo":
        return cls(
            Transport(
                config.url,
                config.token,
                timeout=config.timeout,
                retries=config.retries,
                ca_file=config.ca_file,
                insecure=config.insecure,
            ),
            secret=config.secret,
        )

    # -- discovery --------------------------------------------------------
    def health(self) -> dict:
        return self.transport.get_json("/v1/health", retries=0)

    def repo_info(self) -> dict:
        return self.transport.get_json("/v1/repo")

    def metrics(self) -> str:
        return self.transport.request("GET", "/v1/metrics").body.decode("utf-8", "replace")

    # -- objects ----------------------------------------------------------
    def objects_exists(self, ids: list[str]) -> set[str]:
        present: set[str] = set()
        for batch in _batched(ids, 5000):
            payload = self.transport.post_json("/v1/objects/exists", {"ids": batch})
            present.update(payload.get("present", []))
        return present

    def objects_locate(self, ids: list[str]) -> tuple[dict[str, tuple], list[str]]:
        found: dict[str, tuple] = {}
        missing: list[str] = []
        for batch in _batched(ids, 2000):
            payload = self.transport.post_json("/v1/objects/locate", {"ids": batch})
            for obj_id, loc in (payload.get("objects") or {}).items():
                pack_id, offset, length, flags, plainlen = loc
                found[obj_id] = (pack_id, int(offset), int(length), int(flags), int(plainlen))
            missing.extend(payload.get("missing") or [])
        return found, missing

    def upload_pack(
        self,
        path: os.PathLike[str] | str,
        *,
        expected_id: str,
        progress: Callable[[int, int], None] | None = None,
    ) -> dict:
        size = os.path.getsize(path)
        with open(path, "rb") as handle:
            reader = _ProgressReader(handle, size, progress)
            response = self.transport.request(
                "POST",
                "/v1/packs",
                body_file=reader,
                content_length=size,
                headers={
                    "Content-Type": "application/octet-stream",
                    "X-Haven-Pack-Id": expected_id,
                },
                timeout=max(self.transport.timeout, 3600.0),
            )
        return response.json()

    def download_chunks(self, wanted: dict[str, tuple]) -> Iterator[tuple[str, bytes, int]]:
        """Yield ``(obj_id, payload, flags)``, coalescing byte ranges per pack.

        Ranges that are close together are fetched as one request; the caller
        decompresses each object separately.
        """
        by_pack: dict[str, list[tuple[int, int, str, int]]] = {}
        for obj_id, (pack_id, offset, length, flags, _plainlen) in wanted.items():
            by_pack.setdefault(pack_id, []).append((offset, length, obj_id, flags))
        for pack_id, entries in by_pack.items():
            entries.sort()
            coalesced = _coalesce(entries, max_span=8 * 1024 * 1024)
            for span_start, span_len, members in coalesced:
                data = self.download_range(pack_id, span_start, span_len)
                for offset, length, obj_id, flags in members:
                    begin = offset - span_start
                    yield obj_id, data[begin : begin + length], flags

    def download_range(self, pack_id: str, offset: int, length: int) -> bytes:
        path = f"/v1/packs/{quote(pack_id)}?offset={offset}&length={length}"
        response = self.transport.request("GET", path, timeout=max(self.transport.timeout, 300.0))
        if len(response.body) != length:
            raise ProtocolError(
                f"short read from pack {pack_id}: expected {length} bytes, got {len(response.body)}"
            )
        return response.body

    # -- snapshots --------------------------------------------------------
    def put_snapshot(self, manifest: dict) -> dict:
        return self.transport.put_json("/v1/snapshots", manifest)

    def list_snapshots(self, *, host: str | None = None, limit: int | None = None) -> list[dict]:
        query = []
        if host:
            query.append(f"host={quote(host)}")
        if limit:
            query.append(f"limit={int(limit)}")
        suffix = ("?" + "&".join(query)) if query else ""
        payload = self.transport.get_json(f"/v1/snapshots{suffix}")
        return payload.get("snapshots", [])

    def get_snapshot(self, snapshot_id: str) -> dict:
        manifest = self.transport.get_json(f"/v1/snapshots/{quote(snapshot_id)}")
        validate_manifest(
            manifest, secret=self.secret, require_signature=self.secret is not None
        )
        return manifest

    def delete_snapshot(self, snapshot_id: str) -> dict:
        return self.transport.delete_json(f"/v1/snapshots/{quote(snapshot_id)}")

    # -- maintenance ------------------------------------------------------
    def prune(self, policy: dict, *, apply: bool, host: str | None = None) -> dict:
        payload = {"policy": policy, "apply": bool(apply)}
        if host:
            payload["host"] = host
        return self.transport.post_json("/v1/prune", payload)

    def gc(self, *, apply: bool, min_age_hours: float = 1.0) -> dict:
        return self.transport.post_json("/v1/gc", {"apply": bool(apply), "min_age_hours": min_age_hours})

    def verify(self, *, deep: bool = True) -> dict:
        return self.transport.post_json("/v1/verify", {"deep": bool(deep)})


def _batched(items: list[str], size: int) -> Iterator[list[str]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


def _coalesce(
    entries: list[tuple[int, int, str, int]], *, max_span: int
) -> Iterator[tuple[int, int, list[tuple[int, int, str, int]]]]:
    """Group sorted ranges into spans of at most ``max_span`` bytes."""
    current: list[tuple[int, int, str, int]] = []
    span_start = 0
    span_end = 0
    for entry in entries:
        offset, length = entry[0], entry[1]
        if not current:
            current = [entry]
            span_start, span_end = offset, offset + length
            continue
        if offset + length - span_start <= max_span:
            current.append(entry)
            span_end = max(span_end, offset + length)
            continue
        yield span_start, span_end - span_start, current
        current = [entry]
        span_start, span_end = offset, offset + length
    if current:
        yield span_start, span_end - span_start, current
