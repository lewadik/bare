# Changelog

All notable changes to Haven. The on-disk repository format (`format: 1`) and
the HTTP API (`/v1`) are versioned separately and stay compatible within 1.x.

## 1.0.0 — 2026-11-10

First complete release: client/server file backup for Linux servers.

### Added

* **Client (`haven`)**
  * Content-defined chunking (gear, 64 KiB / 1 MiB / 8 MiB defaults) and a
    `fixed` fast mode for media volumes.
  * Per-file chunk cache keyed on size, mtime, ctime and chunker parameters.
  * One or more packs per run, split at the server's `max_pack_bytes`, uploaded
    only after the server reports which chunks are missing, so unchanged runs
    transfer no data.
  * Snapshot listing, `show`, `diff`, end-to-end `verify`, GFS `prune`, `gc`,
    and `cache` management.
  * Restore with `--include`/`--exclude`, `--overwrite never|if-newer|always`,
    `--dry-run`, `--owner`; preserves modes, mtimes, uid/gid (as root),
    symlinks, hardlinks and sparse holes.
  * Pre/post hooks for database dumps and cleanup.
  * `--json` output and stable exit codes for automation.

* **Server (`havend`)**
  * Threaded HTTP(S) daemon with bearer tokens (`backup`, `admin` scopes),
    hashed at rest and reloadable with SIGHUP.
  * Content-addressed packs with SHA-256 trailers; every object re-hashed on
    ingest; pack uploads idempotent.
  * HMAC-SHA256 signed manifests; structure and path validation on write and on
    every read.
  * SQLite object index that rebuilds itself from packs after a crash
    (`repair-index`).
  * GFS retention, garbage collection with pack rewriting, deep `verify`,
    Prometheus metrics, per-request ids in logs.
  * `init`, `token add|list|revoke`, `rotate-secret` (re-signs all manifests),
    `verify`, `repair-index`.

* **Deployment**
  * systemd units for the daemon (sandboxed) and templated client services and
    timers for backup, maintenance and monthly verification.
  * Installer scripts for server and client, private-CA TLS generator, sample
    configurations, optional logrotate file.

* **Documentation**
  * `README.md`, `docs/architecture.md` (formats, API, failure modes, scaling),
    `docs/operations.md` (install, scheduling, monitoring, restore runbook,
    disaster recovery, troubleshooting), `docs/security.md` (threat model,
    key management, hardening, incident response).

* **Tests**
  * 130 tests: chunking determinism and dedup behaviour, pack round-trip and
    corruption detection, manifest validation and signature forgery, GFS policy
    arithmetic, repository GC/repack/recovery, security (auth, scopes, limits,
    traversal, tampering, restore escapes), and end-to-end runs against a real
    daemon including the CLI.

### Known limitations

* No client-side encryption (volume encryption is delegated to LUKS).
* POSIX ACLs and extended attributes are not captured.
* Repository must be on a local filesystem (SQLite + POSIX locks).
* Chunking runs at roughly 5 MB/s per core in CPython.
