"""Configuration loading for the client (``haven``) and server (``havend``).

Client config is TOML with one table per profile::

    [profiles.nightly]
    url = "https://backup.example.com:8443"
    token = "hvn_..."
    secret = "<64 hex chars>"
    chunking = "min=64K,avg=1M,max=8M"
    compress = "zlib:6"
    exclude = ["/proc", "/sys", "/dev", "*.tmp"]
    cache = "~/.cache/haven/index.sqlite"

    [profiles.nightly.retention]
    keep_last = 3
    keep_daily = 7
    keep_weekly = 4
    keep_monthly = 12

Server config::

    [server]
    bind = "0.0.0.0:8443"
    storage = "/var/lib/haven/repo"
    secret_file = "/etc/haven/repo.secret"
    tokens_file = "/etc/haven/tokens.json"
    tls_cert = "/etc/haven/tls/server.crt"
    tls_key = "/etc/haven/tls/server.key"
    max_pack_bytes = 536870912
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .chunker import ChunkParams, parse_chunking_spec
from .codec import parse_compress_spec
from .errors import ConfigError
from .retention import RetentionPolicy
from .util import parse_size

DEFAULT_CACHE = "~/.cache/haven/index.sqlite"
DEFAULT_EXCLUDES = (
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/tmp",
    "lost+found",
    "*.sock",
    "*.tmp",
    "*.swp",
)


def expand_path(value: str | os.PathLike[str]) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(str(value))))


def client_config_paths() -> list[Path]:
    paths: list[Path] = []
    env = os.environ.get("HAVEN_CONFIG")
    if env:
        paths.append(expand_path(env))
    paths.append(Path("/etc/haven/client.toml"))
    paths.append(expand_path("~/.config/haven/client.toml"))
    return paths


def find_client_config(explicit: str | None = None) -> Path:
    if explicit:
        path = expand_path(explicit)
        if not path.is_file():
            raise ConfigError(f"configuration file not found: {path}")
        return path
    for candidate in client_config_paths():
        if candidate.is_file():
            return candidate
    searched = ", ".join(str(path) for path in client_config_paths())
    raise ConfigError(
        f"no client configuration found (looked in {searched}); "
        "run 'haven init' or pass --config"
    )


def read_toml(path: Path) -> dict:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"{path}: cannot read configuration: {exc}") from exc
    # Editors on Windows like to add a BOM; TOML parsers reject it.
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    try:
        return tomllib.loads(raw.decode("utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise ConfigError(f"{path}: configuration is not valid UTF-8: {exc}") from exc


@dataclass
class ClientConfig:
    profile: str
    config_path: Path | None
    url: str
    token: str
    secret: bytes
    chunking: ChunkParams = field(default_factory=ChunkParams)
    compress: tuple[int, int] = (1, 6)
    exclude: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    cache_path: Path | None = None
    work_dir: Path | None = None
    timeout: float = 60.0
    retries: int = 3
    ca_file: str | None = None
    insecure: bool = False
    retention: RetentionPolicy = field(default_factory=RetentionPolicy)

    @property
    def compress_spec(self) -> str:
        codec, level = self.compress
        return "none" if codec == 0 else f"zlib:{level}"


def _secret_from_text(text: str, where: str) -> bytes:
    cleaned = text.strip().lstrip("\ufeff").strip()
    try:
        raw = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ConfigError(f"{where}: secret must be hex encoded") from exc
    if len(raw) < 16:
        raise ConfigError(f"{where}: secret must be at least 16 bytes (32 hex chars)")
    return raw


def load_client_config(config_path: str | None = None, profile: str | None = None) -> ClientConfig:
    path = find_client_config(config_path)
    document = read_toml(path)
    profiles = document.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        raise ConfigError(f"{path}: missing [profiles.<name>] table")
    wanted = profile or os.environ.get("HAVEN_PROFILE") or "default"
    if wanted not in profiles:
        if len(profiles) == 1 and not profile:
            wanted = next(iter(profiles))
        else:
            raise ConfigError(
                f"{path}: profile {wanted!r} not found (available: {', '.join(sorted(profiles))})"
            )
    table = profiles[wanted]
    if not isinstance(table, dict):
        raise ConfigError(f"{path}: profile {wanted!r} must be a table")
    url = os.environ.get("HAVEN_URL") or table.get("url")
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        raise ConfigError(f"{path}: profile {wanted!r} needs an http(s) 'url'")
    token = os.environ.get("HAVEN_TOKEN") or table.get("token")
    if not isinstance(token, str) or len(token) < 8:
        raise ConfigError(f"{path}: profile {wanted!r} needs a 'token'")
    secret_text = os.environ.get("HAVEN_SECRET") or table.get("secret")
    if not isinstance(secret_text, str):
        raise ConfigError(f"{path}: profile {wanted!r} needs a hex 'secret'")
    secret = _secret_from_text(secret_text, f"{path} profile {wanted!r}")
    chunking_spec = os.environ.get("HAVEN_CHUNKING") or table.get("chunking") or "min=64K,avg=1M,max=8M"
    chunking = parse_chunking_spec(chunking_spec)
    compress = parse_compress_spec(str(table.get("compress", "zlib:6")))
    excludes = list(DEFAULT_EXCLUDES)
    configured = table.get("exclude")
    if configured is not None:
        if not isinstance(configured, list) or not all(isinstance(item, str) for item in configured):
            raise ConfigError(f"{path}: 'exclude' must be a list of strings")
        excludes.extend(configured)
    configured_paths = table.get("paths") or []
    if not isinstance(configured_paths, list) or not all(isinstance(item, str) for item in configured_paths):
        raise ConfigError(f"{path}: 'paths' must be a list of strings")
    cache_value = table.get("cache", DEFAULT_CACHE)
    cache_path = expand_path(str(cache_value)) if cache_value else None
    work_value = table.get("work_dir")
    work_dir = expand_path(str(work_value)) if work_value else None
    try:
        retention = RetentionPolicy.from_json(table.get("retention") or {})
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{path}: invalid [retention]: {exc}") from exc
    timeout = float(table.get("timeout", 60.0))
    if timeout <= 0:
        raise ConfigError(f"{path}: timeout must be positive")
    retries = int(table.get("retries", 3))
    if retries < 0 or retries > 20:
        raise ConfigError(f"{path}: retries must be between 0 and 20")
    ca_file = table.get("ca_file")
    return ClientConfig(
        profile=wanted,
        config_path=path,
        url=url.rstrip("/"),
        token=token,
        secret=secret,
        chunking=chunking,
        compress=compress,
        exclude=excludes,
        paths=list(configured_paths),
        cache_path=cache_path,
        work_dir=work_dir,
        timeout=timeout,
        retries=retries,
        ca_file=expand_path(ca_file).as_posix() if ca_file else None,
        insecure=bool(table.get("insecure", False)),
        retention=retention,
    )


@dataclass
class ServerConfig:
    storage: Path
    bind_host: str = "127.0.0.1"
    bind_port: int = 8443
    tls_cert: str | None = None
    tls_key: str | None = None
    max_pack_bytes: int = 512 * 1024 * 1024
    tokens_file: Path = Path("/etc/haven/tokens.json")
    secret_file: Path | None = None
    log_level: str = "INFO"
    trust_proxy: bool = False
    config_path: Path | None = None


def _parse_bind(value: str) -> tuple[str, int]:
    text = str(value).strip()
    if text.startswith("["):  # [::1]:8443
        host, _, port = text.rpartition(":")
        return host.strip("[]"), int(port)
    if text.count(":") == 1:
        host, _, port = text.partition(":")
        return host or "127.0.0.1", int(port)
    if text.isdigit():
        return "127.0.0.1", int(text)
    return text, 8443


def load_server_config(config_path: str) -> ServerConfig:
    path = expand_path(config_path)
    if not path.is_file():
        raise ConfigError(f"configuration file not found: {path}")
    document = read_toml(path)
    server = document.get("server") or {}
    if not isinstance(server, dict):
        raise ConfigError(f"{path}: [server] must be a table")
    storage_value = server.get("storage")
    if not storage_value:
        raise ConfigError(f"{path}: [server] storage is required")
    host, port = _parse_bind(server.get("bind", "127.0.0.1:8443"))
    tokens_file = expand_path(server.get("tokens_file", str(path.parent / "tokens.json")))
    secret_file = server.get("secret_file")
    max_pack = server.get("max_pack_bytes", 512 * 1024 * 1024)
    max_pack_bytes = parse_size(max_pack) if isinstance(max_pack, str) else int(max_pack)
    if max_pack_bytes < 1024 * 1024:
        raise ConfigError("max_pack_bytes must be at least 1 MiB")
    tls_cert = server.get("tls_cert")
    tls_key = server.get("tls_key")
    if bool(tls_cert) != bool(tls_key):
        raise ConfigError("tls_cert and tls_key must be configured together")
    return ServerConfig(
        storage=expand_path(storage_value),
        bind_host=host,
        bind_port=port,
        tls_cert=str(expand_path(tls_cert)) if tls_cert else None,
        tls_key=str(expand_path(tls_key)) if tls_key else None,
        max_pack_bytes=max_pack_bytes,
        tokens_file=tokens_file,
        secret_file=expand_path(secret_file) if secret_file else None,
        log_level=str(server.get("log_level", "INFO")).upper(),
        trust_proxy=bool(server.get("trust_proxy", False)),
        config_path=path,
    )


def read_secret_file(path: Path) -> bytes:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise ConfigError(f"cannot read secret file {path}: {exc}") from exc
    return _secret_from_text(text, str(path))


def write_client_config(
    path: Path,
    *,
    profile: str,
    url: str,
    token: str,
    secret_hex: str,
    chunking: str = "min=64K,avg=1M,max=8M",
    compress: str = "zlib:6",
    exclude: list[str] | None = None,
    insecure: bool = False,
    ca_file: str | None = None,
) -> None:
    """Write a minimal, mode-0600 client profile."""
    from .util import atomic_write_bytes

    lines = [
        "# Haven client configuration — contains credentials, keep mode 0600.",
        f"[profiles.{profile}]",
        f'url = "{url}"',
        f'token = "{token}"',
        f'secret = "{secret_hex}"',
        f'chunking = "{chunking}"',
        f'compress = "{compress}"',
        'cache = "~/.cache/haven/index.sqlite"',
    ]
    if insecure:
        lines.append("insecure = true")
    if ca_file:
        lines.append(f'ca_file = "{ca_file}"')
    if exclude:
        rendered = ", ".join(f'"{item}"' for item in exclude)
        lines.append(f"exclude = [{rendered}]")
    lines.append("")
    lines.append("")
    lines.append("[profiles.%s.retention]" % profile)
    lines.append("keep_last = 3")
    lines.append("keep_daily = 7")
    lines.append("keep_weekly = 4")
    lines.append("keep_monthly = 12")
    lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_bytes(path, "\n".join(lines).encode("utf-8"), mode=0o600)
