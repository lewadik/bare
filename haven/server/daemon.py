"""The ``havend`` repository daemon: a small hardened HTTP(S) server.

Deliberately built on :mod:`http.server` rather than a web framework: the
service has nine endpoints, runs behind a firewall on a private network, and
must be auditable by whoever is on call at 3 a.m.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import signal
import socket
import ssl
import sys
import time
import uuid

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlsplit

from .. import PROTOCOL_VERSION, __version__
from ..config import ServerConfig, load_server_config, read_secret_file
from ..errors import AuthError, ConfigError, HavenError, TooLargeError, UsageError
from ..util import human_bytes, utc_iso
from .auth import TokenRecord, TokenStore
from .store import Repository

LOG = logging.getLogger("haven.server")

MAX_JSON_BYTES = 128 * 1024 * 1024  # manifests of ~1M files
BODY_BLOCK = 1 << 20


# --------------------------------------------------------------------------
# routing
# --------------------------------------------------------------------------
Route = tuple[str, re.Pattern[str], str | None]  # method, pattern, required scope


class Router:
    def __init__(self) -> None:
        self._routes: list[tuple[str, re.Pattern[str], str | None, Callable]] = []

    def add(self, method: str, pattern: str, scope: str | None):
        compiled = re.compile(pattern + r"\Z")

        def register(func: Callable) -> Callable:
            self._routes.append((method, compiled, scope, func))
            return func

        return register

    def resolve(self, method: str, path: str) -> tuple[Callable, re.Match[str], str | None]:
        allowed: set[str] = set()
        for route_method, compiled, scope, func in self._routes:
            match = compiled.match(path)
            if not match:
                continue
            if route_method != method:
                allowed.add(route_method)
                continue
            return func, match, scope
        if allowed:
            raise MethodNotAllowed(", ".join(sorted(allowed)))
        raise NotFoundRoute(path)


class NotFoundRoute(HavenError):
    code = "not_found"
    status = 404


class MethodNotAllowed(HavenError):
    code = "method_not_allowed"
    status = 405

    def __init__(self, allow: str) -> None:
        super().__init__("method not allowed")
        self.allow = allow


ROUTER = Router()


# --------------------------------------------------------------------------
# handlers
# --------------------------------------------------------------------------
@ROUTER.add("GET", r"/v1/health", None)
def health(handler: "HavenHandler", match, query) -> dict:
    return {"status": "ok", "version": __version__, "protocol": PROTOCOL_VERSION, "time": utc_iso()}


@ROUTER.add("GET", r"/v1/repo", "backup")
def repo_info(handler: "HavenHandler", match, query) -> dict:
    return handler.server.repo.info()


@ROUTER.add("GET", r"/v1/metrics", "admin")
def metrics(handler: "HavenHandler", match, query) -> tuple[bytes, str]:
    return handler.server.repo.metrics_text().encode("utf-8"), "text/plain; version=0.0.4"


@ROUTER.add("POST", r"/v1/objects/exists", "backup")
def objects_exists(handler: "HavenHandler", match, query) -> dict:
    payload = handler.read_json()
    ids = payload.get("ids")
    if not isinstance(ids, list) or len(ids) > 5000:
        raise UsageError("'ids' must be a list of at most 5000 object ids")
    return {"present": handler.server.repo.object_exists(ids)}


@ROUTER.add("POST", r"/v1/objects/locate", "backup")
def objects_locate(handler: "HavenHandler", match, query) -> dict:
    payload = handler.read_json()
    ids = payload.get("ids")
    if not isinstance(ids, list) or len(ids) > 2000:
        raise UsageError("'ids' must be a list of at most 2000 object ids")
    found, missing = handler.server.repo.locate(ids)
    return {"objects": found, "missing": missing}


@ROUTER.add("POST", r"/v1/packs", "backup")
def upload_pack(handler: "HavenHandler", match, query) -> dict:
    expected = handler.headers.get("X-Haven-Pack-Id")
    temp_path = handler.receive_body_to_file(handler.server.config.max_pack_bytes)
    try:
        result = handler.server.repo.install_pack(temp_path, expected_id=expected)
    finally:
        temp_path.unlink(missing_ok=True)
    LOG.info(
        "pack %s installed: %s objects (%s new), %s",
        result["pack"][:12],
        result["objects"],
        result["new_objects"],
        human_bytes(result["stored_bytes"]),
    )
    return result


@ROUTER.add("GET", r"/v1/packs/(?P<pack_id>[0-9a-f]{64})", "backup")
def download_pack(handler: "HavenHandler", match, query) -> tuple[bytes, str]:
    try:
        offset = int(query.get("offset", ["0"])[0])
        length = int(query.get("length", ["0"])[0])
    except ValueError as exc:
        raise UsageError("offset and length must be integers") from exc
    if length <= 0:
        raise UsageError("length is required and must be positive")
    data = handler.server.repo.read_range(match.group("pack_id"), offset, length)
    return data, "application/octet-stream"


@ROUTER.add("PUT", r"/v1/snapshots", "backup")
def put_snapshot(handler: "HavenHandler", match, query) -> dict:
    manifest = handler.read_json(limit=MAX_JSON_BYTES)
    result = handler.server.repo.put_snapshot(manifest)
    LOG.info(
        "snapshot %s stored (%s entries, %s objects)",
        result["id"],
        result["entries"],
        result.get("objects", 0),
    )
    return result


@ROUTER.add("GET", r"/v1/snapshots", "backup")
def list_snapshots(handler: "HavenHandler", match, query) -> dict:
    host = query.get("host", [None])[0]
    limit_text = query.get("limit", [None])[0]
    limit = int(limit_text) if limit_text else None
    if limit is not None and (limit <= 0 or limit > 10000):
        raise UsageError("limit must be between 1 and 10000")
    return {"snapshots": handler.server.repo.list_snapshots(host=host, limit=limit)}


@ROUTER.add("GET", r"/v1/snapshots/(?P<snapshot_id>[^/]+)", "backup")
def get_snapshot(handler: "HavenHandler", match, query) -> dict:
    return handler.server.repo.get_snapshot(match.group("snapshot_id"))


@ROUTER.add("DELETE", r"/v1/snapshots/(?P<snapshot_id>[^/]+)", "admin")
def delete_snapshot(handler: "HavenHandler", match, query) -> dict:
    return handler.server.repo.delete_snapshot(match.group("snapshot_id"))


@ROUTER.add("POST", r"/v1/prune", "admin")
def prune(handler: "HavenHandler", match, query) -> dict:
    payload = handler.read_json()
    policy_data = payload.get("policy") or {}
    from ..retention import RetentionPolicy

    try:
        policy = RetentionPolicy.from_json(policy_data)
    except (TypeError, ValueError) as exc:
        raise UsageError(f"invalid retention policy: {exc}") from exc
    return handler.server.repo.prune(
        policy, apply=bool(payload.get("apply", False)), host=payload.get("host")
    )


@ROUTER.add("POST", r"/v1/gc", "admin")
def gc(handler: "HavenHandler", match, query) -> dict:
    payload = handler.read_json()
    return handler.server.repo.gc(
        apply=bool(payload.get("apply", False)),
        min_age_hours=float(payload.get("min_age_hours", 1.0)),
    )


@ROUTER.add("POST", r"/v1/verify", "admin")
def verify(handler: "HavenHandler", match, query) -> dict:
    payload = handler.read_json()
    return handler.server.repo.verify(deep=bool(payload.get("deep", True)))


# --------------------------------------------------------------------------
# HTTP plumbing
# --------------------------------------------------------------------------
class HavenHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, address, handler_class, repo: Repository, tokens: TokenStore, config: ServerConfig):
        self.repo = repo
        self.tokens = tokens
        self.config = config
        super().__init__(address, handler_class)


class HavenHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"Haven/{__version__}"
    sys_version = ""
    timeout = 300

    server: HavenHTTPServer

    # -- entry points -----------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def do_PUT(self) -> None:  # noqa: N802
        self._dispatch("PUT")

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
        started = time.perf_counter()
        request_id = self.headers.get("X-Request-Id") or uuid.uuid4().hex[:12]
        status = 500
        try:
            parts = urlsplit(self.path)
            query = parse_qs(parts.query, keep_blank_values=True)
            handler, match, scope = ROUTER.resolve(method, parts.path)
            record: TokenRecord | None = None
            if scope is not None:
                record = self._authenticate()
                self.server.tokens.require(record, scope)
            result = handler(self, match, query)
            if isinstance(result, tuple):
                body, content_type = result
                status = 200
                self._respond(status, body, content_type, request_id)
            else:
                status = 200
                self._respond_json(status, result, request_id)
        except HavenError as exc:
            status = exc.status
            headers = {}
            if isinstance(exc, MethodNotAllowed):
                headers["Allow"] = exc.allow
            if isinstance(exc, AuthError):
                headers["WWW-Authenticate"] = 'Bearer realm="haven"'
            LOG.warning(
                "request failed %s %s -> %s %s (%s)",
                method,
                self.path,
                status,
                exc.code,
                exc.message,
            )
            self._respond_json(status, {"error": exc.as_dict()}, request_id, headers)
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as exc:  # noqa: BLE001 - never leak a traceback to a client
            LOG.exception("unhandled error on %s %s: %s", method, self.path, exc)
            status = 500
            self._respond_json(
                500,
                {"error": {"code": "internal_error", "message": "internal server error"}},
                request_id,
            )
        finally:
            duration = (time.perf_counter() - started) * 1000
            LOG.info(
                "%s %s %s %.1fms request_id=%s client=%s",
                method,
                self.path,
                status,
                duration,
                request_id,
                self.client_address[0] if self.client_address else "-",
            )

    # -- auth / body ------------------------------------------------------
    def _authenticate(self) -> TokenRecord:
        header = self.headers.get("Authorization", "")
        if not header.lower().startswith("bearer "):
            raise AuthError("missing bearer token")
        return self.server.tokens.authenticate(header[7:].strip())

    def _content_length(self) -> int:
        raw = self.headers.get("Content-Length")
        if raw is None:
            raise UsageError("Content-Length is required")
        try:
            length = int(raw)
        except ValueError as exc:
            raise UsageError("invalid Content-Length") from exc
        if length < 0:
            raise UsageError("invalid Content-Length")
        return length

    def read_json(self, limit: int = 32 * 1024 * 1024) -> dict:
        length = self._content_length()
        if length > limit:
            raise TooLargeError(f"request body exceeds {limit} bytes")
        body = self.rfile.read(length) if length else b""
        if not body:
            return {}
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UsageError(f"invalid JSON body: {exc}") from exc
        if not isinstance(payload, dict):
            raise UsageError("JSON body must be an object")
        return payload

    def receive_body_to_file(self, limit: int) -> Path:
        length = self._content_length()
        if length <= 0:
            raise UsageError("empty request body")
        if length > limit:
            raise TooLargeError(f"upload exceeds the configured limit of {limit} bytes")
        tmp = self.server.repo.tmp_dir / f"upload-{uuid.uuid4().hex}.part"
        remaining = length
        try:
            with open(tmp, "wb") as handle:
                while remaining:
                    block = self.rfile.read(min(BODY_BLOCK, remaining))
                    if not block:
                        raise UsageError("client closed the connection mid-upload")
                    handle.write(block)
                    remaining -= len(block)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        return tmp

    # -- responses --------------------------------------------------------
    def _respond_json(self, status: int, payload: dict, request_id: str, headers: dict | None = None) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self._respond(status, body, "application/json", request_id, headers)

    def _respond(
        self,
        status: int,
        body: bytes,
        content_type: str,
        request_id: str,
        headers: dict | None = None,
    ) -> None:
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Request-Id", request_id)
            self.send_header("X-Haven-Version", __version__)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if self.command != "HEAD" and body:
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            return

    def log_message(self, fmt: str, *args) -> None:  # route through logging
        LOG.debug("%s - %s", self.address_string(), fmt % args)


# --------------------------------------------------------------------------
# daemon lifecycle
# --------------------------------------------------------------------------
def build_server(config: ServerConfig, repo: Repository, tokens: TokenStore) -> HavenHTTPServer:
    server = HavenHTTPServer((config.bind_host, config.bind_port), HavenHandler, repo, tokens, config)
    if config.tls_cert and config.tls_key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(config.tls_cert, config.tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def serve(config: ServerConfig) -> int:
    if config.secret_file is None:
        raise ConfigError("server.secret_file is required (the repository secret signs manifests)")
    secret = read_secret_file(config.secret_file)
    repo = Repository(config.storage, secret, max_pack_bytes=config.max_pack_bytes)
    tokens = TokenStore(config.tokens_file)
    if not tokens.list():
        LOG.warning(
            "no tokens configured in %s; no client can authenticate until you run "
            "'havend token add --name <client>'",
            config.tokens_file,
        )
    server = build_server(config, repo, tokens)
    scheme = "https" if config.tls_cert else "http"
    LOG.info(
        "havend %s listening on %s://%s:%d (repo %s, %s objects)",
        __version__,
        scheme,
        config.bind_host,
        server.server_address[1],
        config.storage,
        repo.stats()["objects"],
    )
    stopping = {"flag": False}

    def _stop(signum, _frame):
        if stopping["flag"]:
            return
        stopping["flag"] = True
        LOG.info("received signal %s, shutting down", signum)
        # shutdown() must run outside the serve_forever thread.
        import threading

        threading.Thread(target=server.shutdown, daemon=True).start()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _stop)
        except (ValueError, OSError):  # pragma: no cover - non-main thread / Windows
            pass

    # `systemctl reload havend` -> add or revoke a token without downtime.
    if hasattr(signal, "SIGHUP"):

        def _reload(_signum, _frame):
            try:
                tokens.reload()
                LOG.info("reloaded tokens from %s (%d active)", config.tokens_file, len(tokens.list()))
            except HavenError as exc:
                LOG.error("token reload failed, keeping the previous tokens: %s", exc.message)

        try:
            signal.signal(signal.SIGHUP, _reload)
        except (ValueError, OSError):  # pragma: no cover
            pass
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        repo.close()
    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def _cmd_init(config: ServerConfig, args: argparse.Namespace) -> int:
    from ..util import atomic_write_bytes
    import secrets as _secrets

    secret_path = config.secret_file or (config.config_path.parent / "repo.secret" if config.config_path else None)
    if secret_path is None:
        raise ConfigError("configure [server] secret_file first")
    if (config.storage / "repo.json").exists():
        raise ConfigError(f"repository already exists at {config.storage}")
    if secret_path.exists() and secret_path.read_text(encoding="utf-8").strip():
        secret = read_secret_file(secret_path)
        created_secret = False
    else:
        secret = _secrets.token_bytes(32)
        atomic_write_bytes(secret_path, (secret.hex() + "\n").encode("utf-8"), mode=0o600)
        created_secret = True
    repo = Repository.create(
        config.storage,
        name=args.name,
        secret=secret,
        max_pack_bytes=config.max_pack_bytes,
    )
    TokenStore(config.tokens_file).ensure_file()  # create an empty, mode-0600 token file
    print(f"repository created: {config.storage}")
    print(f"  repo id   : {repo.meta.repo_id}")
    print(f"  key id    : {repo.key_id}   (clients can compare this)")
    print(f"  secret    : {secret_path} (mode 0600)")
    if created_secret:
        print()
        print("Repository secret (provision to every client, keep it secret):")
        print(f"  {secret.hex()}")
    print()
    print("Next: havend token add --name <client-host> --scope backup")
    repo.close()
    return 0


def _cmd_token(config: ServerConfig, args: argparse.Namespace) -> int:
    store = TokenStore(config.tokens_file)
    if args.action == "add":
        if not args.name:
            raise UsageError("--name is required for 'token add'")
        scopes = [part.strip() for part in (args.scope or "backup").split(",") if part.strip()]
        token = store.add(args.name, scopes)
        print(f"token for {args.name!r} (scopes: {', '.join(scopes)}) — shown once:")
        print()
        print(f"  {token}")
        print()
        print("Add it to the client profile as:  token = \"<value>\"")
    elif args.action == "list":
        rows = store.list()
        if not rows:
            print("no tokens")
        for row in rows:
            print(f"{row['name']:<24} {','.join(row['scopes']):<12} {row['created']:<26} {row['fingerprint']}")
    else:
        if not args.name:
            raise UsageError("--name is required for 'token revoke'")
        count = store.revoke(args.name)
        print(f"revoked {count} token(s) named {args.name!r}")
    return 0


def _cmd_verify(config: ServerConfig, args: argparse.Namespace) -> int:
    if config.secret_file is None:
        raise ConfigError("server.secret_file is required")
    repo = Repository(config.storage, read_secret_file(config.secret_file), max_pack_bytes=config.max_pack_bytes)
    try:
        report = repo.verify(deep=not args.quick)
    finally:
        repo.close()
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


def _cmd_rotate(config: ServerConfig, args: argparse.Namespace) -> int:
    if config.secret_file is None:
        raise ConfigError("server.secret_file is required")
    from ..config import expand_path
    from ..util import atomic_write_bytes

    old_secret = read_secret_file(config.secret_file)
    new_secret = read_secret_file(expand_path(args.new_secret_file))
    repo = Repository(config.storage, old_secret, max_pack_bytes=config.max_pack_bytes)
    try:
        report = repo.rotate_secret(new_secret)
    finally:
        repo.close()
    backup_path = config.secret_file.with_name(config.secret_file.name + ".bak")
    atomic_write_bytes(backup_path, (old_secret.hex() + "\n").encode("utf-8"), mode=0o600)
    atomic_write_bytes(config.secret_file, (new_secret.hex() + "\n").encode("utf-8"), mode=0o600)
    print(f"re-signed {report['resigned']} snapshot(s) with the new secret")
    if report.get("already_signed"):
        print(f"  {report['already_signed']} snapshot(s) were already signed by an earlier run")
    print(f"  previous secret kept at {backup_path} (mode 0600)")
    print("  update every client profile, then restart the daemon")
    return 0


def _cmd_repair(config: ServerConfig, args: argparse.Namespace) -> int:
    if config.secret_file is None:
        raise ConfigError("server.secret_file is required")
    repo = Repository(config.storage, read_secret_file(config.secret_file), max_pack_bytes=config.max_pack_bytes)
    try:
        report = repo.rebuild_index()
    finally:
        repo.close()
    print(json.dumps(report, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="havend", description="Haven repository daemon")
    parser.add_argument("--config", default=os.environ.get("HAVEN_SERVER_CONFIG", "/etc/haven/server.toml"))
    parser.add_argument("--version", action="version", version=f"havend {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", help="run the daemon (default)")
    init = sub.add_parser("init", help="create a new repository")
    init.add_argument("--name", default="primary")
    token = sub.add_parser("token", help="manage client tokens")
    token.add_argument("action", choices=["add", "list", "revoke"])
    token.add_argument("--name")
    token.add_argument("--scope", default="backup", help="comma separated: backup,admin")
    verify = sub.add_parser("verify", help="verify packs and snapshots")
    verify.add_argument("--quick", action="store_true", help="skip deep pack checks")
    sub.add_parser("repair-index", help="rebuild the object index from pack files")
    rotate = sub.add_parser("rotate-secret", help="re-sign every manifest with a new secret")
    rotate.add_argument("--new-secret-file", required=True, help="file containing the new secret")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        stream=sys.stderr,
    )
    try:
        config = load_server_config(args.config)
        if args.command in (None, "serve"):
            return serve(config)
        if args.command == "init":
            return _cmd_init(config, args)
        if args.command == "token":
            return _cmd_token(config, args)
        if args.command == "verify":
            return _cmd_verify(config, args)
        if args.command == "repair-index":
            return _cmd_repair(config, args)
        if args.command == "rotate-secret":
            return _cmd_rotate(config, args)
        raise UsageError(f"unknown command {args.command}")
    except HavenError as exc:
        print(f"error: {exc.message}", file=sys.stderr)
        if exc.detail:
            print(f"       {exc.detail}", file=sys.stderr)
        return 2 if isinstance(exc, (UsageError, ConfigError)) else 1
    except KeyboardInterrupt:  # pragma: no cover
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
