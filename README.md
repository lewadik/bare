# Haven

**Deduplicating client/server backup and restore for Linux servers.**

One repository server (`havend`), one small agent on every machine (`haven`).
Nightly snapshots, block-level deduplication across files and snapshots, signed
metadata, and a restore path that is safe enough to run on a live system.

```
   ┌─────────────┐        HTTPS + bearer token        ┌──────────────────────┐
   │  web-01     │ ─────────────────────────────────► │  havend              │
   │  haven      │   POST /v1/packs   (new chunks)    │  ┌────────────────┐  │
   │             │   PUT  /v1/snapshots (manifest)    │  │ packs/  *.pack │  │
   └─────────────┘                                    │  │ snapshots/ *.json │
   ┌─────────────┐                                    │  │ state/index.sqlite │
   │  db-01      │ ─────────────────────────────────► │  └────────────────┘  │
   │  haven      │ ◄───── GET /v1/packs/<id>?offset ── │  /var/lib/haven/repo │
   └─────────────┘        (range reads on restore)    └──────────────────────┘
```

## Why another backup tool

* **Cheap nightly runs.** A file whose size, mtime and ctime are unchanged is
  never opened; new data is deduplicated against everything already stored.
  Re-running a backup over 100 GB of unchanged data transfers the manifest —
  a few kilobytes.
* **Restores that respect the target.** Absolute paths and `..` in a manifest
  are rejected, and a symlink (in the snapshot *or* on the target disk) can
  never redirect a write outside the restore directory.
* **Signed metadata.** Every manifest is HMAC-signed with the repository
  secret; a tampered snapshot is detected before a single byte is restored.
* **No dependencies.** Pure Python 3.11+ standard library on both sides: no
  virtualenv, no compiler, no third-party wheel on a production server.
* **Boring operations.** systemd units with a real sandbox, Prometheus metrics,
  a health endpoint, token rotation without downtime, and a documented restore
  drill.

## Quickstart

### 1. Repository server

```sh
sudo ./deploy/install-server.sh          # user, dirs, binaries, systemd unit
sudo ./deploy/gen-tls.sh backup.example.com

sudo -u haven havend --config /etc/haven/server.toml init --name primary
#   -> prints the repository secret once; every client needs it

sudo -u haven havend --config /etc/haven/server.toml token add \
     --name web-01 --scope backup
#   -> prints a token once

sudo systemctl start haven-server
curl --cacert /etc/haven/tls/ca.crt https://backup.example.com:8443/v1/health
```

### 2. Client (the machine being backed up)

```sh
sudo ./deploy/install-client.sh system
sudo editor /etc/haven/client.toml     # url, token, secret, paths
haven --config /etc/haven/client.toml --profile system check
haven --config /etc/haven/client.toml --profile system backup
sudo systemctl enable --now haven-backup@system.timer
sudo systemctl enable --now haven-maintenance@system.timer
```

### 3. Prove that a restore works — today, not during an incident

```sh
haven --profile system snapshots
haven --profile system restore <snapshot> --to /var/tmp/restore-test
diff -r /etc /var/tmp/restore-test/etc      # paths are stored relative to /
```

## Commands

### Client — `haven`

| Command | What it does |
| --- | --- |
| `haven init --url URL --token T --secret HEX` | Write a client profile and test the connection |
| `haven check` | Health, credentials, repository identity (`key id`) |
| `haven backup [PATHS...]` | Create a snapshot (paths from the profile if omitted) |
| `haven snapshots [--host H] [--limit N]` | List snapshots |
| `haven show SNAPSHOT` | Details of one snapshot |
| `haven diff A B` | Added / removed / changed paths between two snapshots |
| `haven restore SNAPSHOT --to DIR` | Restore (`--include`, `--exclude`, `--overwrite never\|if-newer\|always`, `--dry-run`, `--owner`) |
| `haven verify SNAPSHOT` / `--all` | Download every chunk and check its SHA-256 |
| `haven prune [--apply]` | Apply the GFS retention policy |
| `haven gc [--apply]` | Reclaim space from deleted snapshots |
| `haven cache info\|clear` | Inspect or drop the per-file chunk cache |

Global flags: `--config`, `--profile`, `--json`, `-v`, `-q`.

### Server — `havend`

| Command | What it does |
| --- | --- |
| `havend init --name NAME` | Create a repository and its secret |
| `havend serve` | Run the daemon (default) |
| `havend token add\|list\|revoke` | Manage client tokens (`backup`, `admin` scopes) |
| `havend verify [--quick]` | Verify every pack, object and manifest |
| `havend repair-index` | Rebuild the SQLite index from pack files |
| `havend rotate-secret --new-secret-file F` | Re-sign all manifests with a new secret |

Exit codes: `0` success, `1` failure (including a restore with errors and a
`verify` that found problems), `2` usage/configuration error. `--json` gives
machine-readable output for every client command; `havend verify` and
`havend repair-index` print JSON reports.

## How it works

**Chunking.** Files are split with a gear rolling hash (min 64 KiB, average
1 MiB, max 8 MiB). Boundaries depend on content, not offsets, so inserting a
line into a 4 GB database dump still reuses every unchanged chunk. The chunk
list is cached per file (`size`, `mtime_ns`, `ctime_ns`), which is what makes a
nightly run cheap.

**Objects.** Each chunk is compressed (zlib) and stored under
`sha256(plaintext)`. Identical chunks — in the same file, another file, or a
snapshot from last month — are stored once.

**Packs.** One backup run writes one pack — or several, each within the
server's `max_pack_bytes` — after walking the filesystem and asking the server
which chunk ids it already has; only the missing ones are written. Each pack is
an immutable file with a SHA-256 trailer. The pack id is the SHA-256 of the
whole file, so uploads are idempotent and verifiable with `sha256sum`.

**Manifests.** A snapshot is one JSON document: every path with mode, uid/gid,
mtime, symlink target, hardlink reference, sparse flag and chunk list. It is
canonicalised and HMAC-signed; the server refuses to store a manifest whose
chunks are not durable, so a snapshot never points at missing data.

**Retention.** `prune` applies a per-host GFS policy (last / daily / weekly /
monthly / yearly, plus an optional "keep everything within N days"). `gc`
deletes packs nobody references and rewrites partially-live packs.

## Layout of a repository

```
/var/lib/haven/repo/
├── repo.json                    identity, format version
├── packs/<id>.pack              immutable chunk packs (id = sha256 of file)
├── packs/<id>.idx.json          per-pack index (rebuildable from the pack)
├── snapshots/<id>.json          signed manifests
├── snapshots/<id>.meta.json     cached summary for `haven snapshots`
├── state/index.sqlite           object -> (pack, offset, length) index
├── tmp/                         upload staging
└── lock                         cross-process lock held by `gc --apply`
```

## Documentation

| Document | Contents |
| --- | --- |
| [docs/architecture.md](docs/architecture.md) | Data formats, HTTP API, failure modes, design decisions, scaling |
| [docs/operations.md](docs/operations.md) | Install, TLS, tokens, scheduling, monitoring, retention, restore runbook, disaster recovery, troubleshooting |
| [docs/security.md](docs/security.md) | Threat model, controls, key management, hardening, incident response, limits |

## Known limits (read before trusting it with production data)

* The repository is **not encrypted at rest by Haven itself**. Use LUKS/dm-crypt
  on the volume; the design and the reasoning are in
  [docs/security.md](docs/security.md).
* POSIX **ACLs and extended attributes are not captured**; modes, ownership,
  timestamps, symlinks, hardlinks and sparse files are.
* Files that change *while* being read are captured as they were during the
  read (no filesystem snapshot integration). Use a pre-hook (`pg_dump`,
  `LVM`/`btrfs` snapshot) for consistent database backups.
* The repository must live on a **local filesystem** (SQLite + POSIX locks);
  NFS/CIFS are not supported.
* Metadata is in memory for one snapshot at a time: a snapshot of ~5 million
  paths works but needs a few GB of RAM on the client.
* A restore downloads and stages every chunk before writing (so a bad repository
  cannot leave a half-written tree). The restore host needs free space in its
  work directory roughly equal to the uncompressed size of the files being
  restored.
* Chunking runs at roughly **5 MB/s per core** in CPython (the hash table is
  generated in Python). Metadata-cached runs skip unchanged files; for media
  volumes use `--chunking fixed=8M`, which trades dedup after in-place edits
  for speed. An accelerated chunker can be dropped in without changing formats.

## Development

```sh
python3 run_tests.py          # unit + integration tests, stdlib unittest, no network
python3 run_tests.py -v test_e2e
make check                    # byte-compile everything
```

Tests start a real daemon on an ephemeral port and drive backup, restore,
prune, gc and the CLI end to end. Symlink-escape and POSIX-permission tests
skip on Windows (they need real symlinks); everything else runs everywhere.

```
haven/
├── chunker.py     content-defined chunking (gear)
├── codec.py       per-chunk compression
├── packfile.py    pack format, spill file
├── manifest.py    snapshot schema, HMAC signing, validation
├── backup.py      client: walk, chunk, upload, commit
├── restore.py     client: fetch, verify, write safely
├── retention.py   GFS policy
├── transport.py   HTTP client + typed API
├── config.py      TOML configuration
├── cli.py         `haven`
└── server/
    ├── store.py   repository: packs, snapshots, gc, verify
    ├── daemon.py  HTTP daemon + `havend`
    └── auth.py    token store
```

## Status

Version 1.0.0 — feature complete for Linux server file-level backup, with an
integration-tested client/server pair. Known gaps: client-side encryption, ACL
capture, a web UI, and multi-repository fan-out. Licensing is left to the
repository owner.
