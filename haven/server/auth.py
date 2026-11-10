"""Bearer-token authentication for the repository daemon.

Tokens are stored only as SHA-256 hashes; the plaintext is printed once when
created. Two scopes exist:

``backup``  read the repository and write packs/snapshots
``admin``   additionally delete snapshots, prune, collect garbage, verify

A token file must not be readable by other users; the server refuses to start
otherwise (on POSIX), because a leaked token is a leaked backup.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

from ..errors import AuthError, ConfigError, ForbiddenError
from ..util import atomic_write_bytes, read_json, utc_iso

SCOPES = ("backup", "admin")
TOKEN_PREFIX = "hvn_"


@dataclass(frozen=True)
class TokenRecord:
    name: str
    scopes: tuple[str, ...]
    created: str

    def allows(self, scope: str) -> bool:
        return "admin" in self.scopes or scope in self.scopes


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class TokenStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._tokens: dict[str, dict] = {}
        self.reload()

    def reload(self) -> None:
        if not self.path.exists():
            self._tokens = {}
            return
        self._check_permissions()
        try:
            data = read_json(self.path)
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"cannot read token file {self.path}: {exc}") from exc
        entries = data.get("tokens") if isinstance(data, dict) else None
        if not isinstance(entries, list):
            raise ConfigError(f"{self.path}: expected a 'tokens' list")
        tokens: dict[str, dict] = {}
        for entry in entries:
            if not isinstance(entry, dict) or "hash" not in entry or "name" not in entry:
                raise ConfigError(f"{self.path}: malformed token entry")
            scopes = entry.get("scopes") or ["backup"]
            if not isinstance(scopes, list) or any(scope not in SCOPES for scope in scopes):
                raise ConfigError(f"{self.path}: token {entry['name']!r} has invalid scopes")
            tokens[str(entry["hash"])] = {
                "name": str(entry["name"]),
                "scopes": tuple(scopes),
                "created": str(entry.get("created", "")),
            }
        self._tokens = tokens

    def _check_permissions(self) -> None:
        if os.name != "posix":
            return
        mode = stat.S_IMODE(self.path.stat().st_mode)
        if mode & 0o077:
            raise ConfigError(
                f"{self.path} is readable by other users (mode {mode:o}); run: chmod 600 {self.path}"
            )

    def _save(self) -> None:
        payload = {
            "version": 1,
            "tokens": [
                {"name": record["name"], "hash": digest, "scopes": list(record["scopes"]), "created": record["created"]}
                for digest, record in sorted(self._tokens.items(), key=lambda item: item[1]["name"])
            ],
        }
        atomic_write_bytes(self.path, json.dumps(payload, indent=2).encode("utf-8") + b"\n", mode=0o600)

    def authenticate(self, token: str) -> TokenRecord:
        digest = hash_token(token)
        record = self._tokens.get(digest)
        if record is None:
            raise AuthError("invalid or revoked token")
        return TokenRecord(record["name"], record["scopes"], record["created"])

    def require(self, record: TokenRecord, scope: str) -> None:
        if not record.allows(scope):
            raise ForbiddenError(f"token {record.name!r} lacks the {scope!r} scope")

    def ensure_file(self) -> None:
        """Create an empty token file with restrictive permissions."""
        if not self.path.exists():
            self._tokens = {}
            self._save()

    def add(self, name: str, scopes: list[str]) -> str:
        scopes = list(dict.fromkeys(scopes or ["backup"]))
        for scope in scopes:
            if scope not in SCOPES:
                raise ConfigError(f"unknown scope {scope!r}")
        if any(record["name"] == name for record in self._tokens.values()):
            raise ConfigError(f"token named {name!r} already exists")
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        self._tokens[hash_token(token)] = {"name": name, "scopes": tuple(scopes), "created": utc_iso()}
        self._save()
        return token

    def revoke(self, name: str) -> int:
        doomed = [digest for digest, record in self._tokens.items() if record["name"] == name]
        for digest in doomed:
            del self._tokens[digest]
        if doomed:
            self._save()
        return len(doomed)

    def list(self) -> list[dict]:
        return [
            {
                "name": record["name"],
                "scopes": list(record["scopes"]),
                "created": record["created"],
                "fingerprint": digest[:12],
            }
            for digest, record in sorted(self._tokens.items(), key=lambda item: item[1]["name"])
        ]
