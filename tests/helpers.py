"""Shared helpers: run a real daemon on an ephemeral port for tests."""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from haven.chunker import ChunkParams  # noqa: E402
from haven.config import ClientConfig, ServerConfig, write_client_config  # noqa: E402
from haven.server.auth import TokenStore  # noqa: E402
from haven.server.daemon import build_server  # noqa: E402
from haven.server.store import Repository  # noqa: E402
from haven.transport import RemoteRepo, Transport  # noqa: E402

SECRET = bytes.fromhex("00112233445566778899aabbccddeeff" * 2)
# Small chunks keep the tests fast while exercising real content-defined cuts.
TEST_CHUNKING = ChunkParams(minimum=1024, average=4096, maximum=16384)


def rel_prefix(path: Path) -> Path:
    """Where a source tree appears inside a restore target."""
    anchor = path.anchor if path.anchor else os.sep
    return Path(os.path.relpath(str(path), anchor))


class Harness:
    """A repository + daemon + credentials, ready for a client.

    ``fresh=False`` opens an existing repository, which is how tests simulate a
    server restart.
    """

    def __init__(self, tmp: Path, *, fresh: bool = True, max_pack_bytes: int = 512 * 1024 * 1024) -> None:
        self.tmp = Path(tmp)
        self.secret = SECRET
        self.repo_root = self.tmp / "repo"
        self.secret_file = self.tmp / "repo.secret"
        if fresh and not self.secret_file.exists():
            self.secret_file.write_text(SECRET.hex() + "\n", encoding="utf-8")
        self.tokens_file = self.tmp / "tokens.json"
        self.token_store = TokenStore(self.tokens_file)
        if fresh:
            self.token_store.ensure_file()
            self.token = self.token_store.add("test-host", ["backup", "admin"])
            self.backup_token = self.token_store.add("backup-only", ["backup"])
            self.repo = Repository.create(
                self.repo_root, name="test", secret=self.secret, max_pack_bytes=max_pack_bytes
            )
        else:
            self.token = self.token_store.add(
                f"test-host-{os.getpid()}-{len(self.token_store.list())}", ["backup", "admin"]
            )
            self.backup_token = self.token_store.add(
                f"backup-only-{os.getpid()}-{len(self.token_store.list())}", ["backup"]
            )
            self.repo = Repository(self.repo_root, self.secret, max_pack_bytes=max_pack_bytes)
        self.config = ServerConfig(
            storage=self.repo_root,
            bind_host="127.0.0.1",
            bind_port=0,
            tokens_file=self.tokens_file,
            secret_file=self.secret_file,
            max_pack_bytes=max_pack_bytes,
        )
        self.server = build_server(self.config, self.repo, TokenStore(self.tokens_file))
        self.url = ""
        self._thread: threading.Thread | None = None
        self.client_config_path = self.tmp / "client.toml"

    # -- lifecycle --------------------------------------------------------
    def start(self) -> "Harness":
        self._thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self._thread.start()
        host, port = self.server.server_address[:2]
        self.url = f"http://{host}:{port}"
        write_client_config(
            self.client_config_path,
            profile="test",
            url=self.url,
            token=self.token,
            secret_hex=self.secret.hex(),
            chunking=f"min={TEST_CHUNKING.minimum},avg={TEST_CHUNKING.average},max={TEST_CHUNKING.maximum}",
            compress="zlib:6",
            exclude=[],
        )
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=10)
        self.repo.close()

    def __enter__(self) -> "Harness":
        return self.start()

    def __exit__(self, *_exc) -> None:
        self.stop()

    # -- clients ----------------------------------------------------------
    def client(self, *, cache: Path | None = None, chunking: ChunkParams | None = None, token: str | None = None) -> ClientConfig:
        return ClientConfig(
            profile="test",
            config_path=self.client_config_path,
            url=self.url,
            token=token or self.token,
            secret=self.secret,
            chunking=chunking or TEST_CHUNKING,
            compress=(1, 6),
            exclude=[],
            cache_path=cache,
            timeout=30.0,
            retries=1,
        )

    def api(self, token: str | None = None) -> RemoteRepo:
        return RemoteRepo(Transport(self.url, token or self.token, timeout=30.0, retries=1))

    def cli_args(self) -> list[str]:
        return ["--config", str(self.client_config_path), "--profile", "test"]


def make_tree(root: Path) -> Path:
    """A small but varied source tree: text, binary, empty, symlink, hardlink."""
    root = Path(root)
    (root / "etc").mkdir(parents=True, exist_ok=True)
    (root / "etc" / "hosts").write_text("127.0.0.1 localhost\n::1 localhost\n", encoding="utf-8")
    (root / "etc" / "nested").mkdir()
    (root / "etc" / "nested" / "app.conf").write_text("port = 8080\n" * 40, encoding="utf-8")
    (root / "etc" / "empty").write_bytes(b"")
    (root / "var").mkdir()
    (root / "var" / "blob.bin").write_bytes(bytes(range(256)) * 800)  # 204800 bytes
    (root / "unicode-\u00e9\u4e2d.txt").write_text("na\u00efve caf\u00e9\n", encoding="utf-8")
    try:
        os.link(root / "etc" / "hosts", root / "etc" / "hosts-hardlink")
    except (OSError, NotImplementedError):
        pass
    try:
        os.symlink("etc/hosts", root / "current")
    except (OSError, NotImplementedError):
        pass
    return root
