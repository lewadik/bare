# Architecture

## 1. Scope

Haven backs up **files on Linux servers** to a **central repository**, and
restores them. It is not a block-level imager, not a cluster filesystem, and not
a SaaS product. The requirements that shaped every decision:

| Requirement | Consequence |
| --- | --- |
| Nightly runs must be cheap on a 500 GB server | metadata cache + content-defined dedup + server-side existence check |
| A restore must never damage the target | strict path validation and `realpath` containment checks |
| The server must be able to prove metadata was not edited | HMAC-signed manifests |
| Install on a stock server without a toolchain | Python 3.11+ standard library only |
| Failure must be visible, never silent | hash verification at ingest, on read, and in `verify`; GC refuses to run on unreadable manifests |

## 2. Topology

```
 clients (haven)                  repository host (havend)              storage
┌────────────────────┐          ┌───────────────────────────┐        ┌──────────────┐
│ walker → chunker   │  HTTPS   │ HTTP server (threaded)    │        │ packs/*.pack │
│ → spill → pack     │ ───────► │  → Repository             │ ─────► │ snapshots/   │
│ → manifest (HMAC)  │          │     → SQLite object index │        │ state/       │
└────────────────────┘          └───────────────────────────┘        └──────────────┘
```

The daemon is stateless apart from the repository directory. Any number of
clients can back up concurrently; a single daemon process serialises index
writes with a `threading.RLock` and SQLite transactions.

## 3. Data formats

### 3.1 Objects

An object is one chunk, identified by `sha256(plaintext)` in lowercase hex.
Compression (zlib) and framing are applied *after* hashing, so a codec or
compression-level change never affects deduplication.

### 3.2 Pack files

A pack is an immutable concatenation of objects, written once per backup run:

```
offset 0            b"HAVENPACK1\n"                                   (11 bytes)
per object          b"O"                                             (1)
                    obj_id                                            (32, raw sha256)
                    flags                                             (1: 0=raw, 1=zlib)
                    varint(plainlen)
                    varint(payloadlen)
                    payload                                           (payloadlen)
trailer             b"E"
                    varint(object_count)
                    sha256(all preceding bytes)                       (32)
```

* `pack_id = sha256(entire file)`, so `sha256sum` on the server and the
  `X-Haven-Pack-Id` header agree, and re-uploading the same bytes is a no-op.
* The trailer detects truncation without any external index; the object count
  catches a missing tail.
* Parsing validates `offset + length <= file size`, an unknown tag fails loudly,
  and `deep=True` re-hashes every payload and compares it to its object id.

### 3.3 Object index

`state/index.sqlite` is a cache of the pack indexes, not a source of truth:

```sql
CREATE TABLE objects (obj_id TEXT PRIMARY KEY, pack_id TEXT, offset INTEGER,
                      length INTEGER, flags INTEGER, plainlen INTEGER) WITHOUT ROWID;
CREATE INDEX objects_by_pack ON objects(pack_id);
CREATE TABLE packs (pack_id TEXT PRIMARY KEY, size INTEGER, n_objects INTEGER,
                    created REAL) WITHOUT ROWID;
```

On startup the pack count in SQLite is compared with the `*.pack` files on
disk; a mismatch (crash between rename and index commit, or a restored backup
directory) triggers `rebuild_index()`, which reads the pack indexes and, if one
is missing, re-parses the pack. `havend repair-index` does the same on demand.

### 3.4 Manifests

```json
{
  "format": 1,
  "id": "20261110T051651Z-069f60ed",
  "created": "2026-11-10T05:16:51.318Z",
  "host": "web-01",
  "label": "nightly",
  "paths": ["/etc", "/srv/www"],
  "chunker": {"algo": "gear", "version": 1, "min": 65536, "avg": 1048576, "max": 8388608},
  "codec": "zlib:6",
  "excludes": ["proc", "sys", "dev", "run", "tmp", "lost+found", "*.sock", "*.tmp"],
  "stats": {"files": 4712, "dirs": 612, "symlinks": 88, "errors": 0,
            "bytes_total": 12884901888, "bytes_new": 52428800,
            "chunks": 12288, "chunks_new": 50, "chunks_reused": 12238},
  "entries": [
    {"p": "etc", "t": "d", "m": 493, "u": 0, "g": 0, "mt": 1762742211.0},
    {"p": "etc/hosts", "t": "f", "m": 420, "u": 0, "g": 0, "mt": 1762742211.0,
     "s": 314, "c": [["9c0f…", 314]]},
    {"p": "etc/localtime", "t": "l", "m": 511, "u": 0, "g": 0, "mt": 1762742211.0,
     "tg": "/usr/share/zoneinfo/UTC"},
    {"p": "etc/hosts-hardlink", "t": "f", "m": 420, "u": 0, "g": 0, "mt": 1762742211.0,
     "s": 314, "c": [["9c0f…", 314]], "hl": "etc/hosts", "sp": true},
    {"p": "proc/1/mem", "t": "x", "e": "cannot read file: Permission denied", "m": 0, "mt": 0.0}
  ],
  "duration_ms": 41200,
  "haven_version": "1.0.0",
  "signature": "hmac-sha256:…"
}
```

* Paths are **relative to the filesystem root**, POSIX separators, no leading
  slash. A backup of `/etc` produces `etc/...`; restoring to `/restore` gives
  `/restore/etc/...`, and restoring to `/` reproduces the original layout.
* `t` is `f` file, `d` directory, `l` symlink, `x` skipped/error (with `e`).
* `c` is `[[obj_id, plain_length], …]`; the lengths must sum to `s`.
* `hl` names an earlier entry that is the same inode; `sp` marks a sparse file.
* `id` is `YYYYMMDDTHHMMSSZ-<8 hex>`, which sorts chronologically and is used
  for retention bucketing.
* The signature covers the canonical JSON (sorted keys, compact separators) of
  the document without the `signature` field, keyed with
  `HMAC-SHA256(HMAC-SHA256(secret, "haven-manifest-v1"), body)`. Domain
  separation means the repository secret is never used as a raw key.
* `snapshots/<id>.meta.json` is a small summary written next to the manifest so
  `haven snapshots` does not parse multi-megabyte manifests.

### 3.5 Validation on ingest and before use

`validate_manifest()` enforces: format 1, a syntactically valid id and
timestamp, a host, valid chunker parameters, ≤5,000,000 entries, no duplicate
paths, every path passing `safe_rel_parts()` (no absolute path, no `..`, no NUL),
type-specific fields, chunk ids matching `[0-9a-f]{64}`, and chunk lengths
summing to the file size. The server re-verifies the signature; the client
verifies it again on `get_snapshot`.

## 4. HTTP API (protocol 1)

All endpoints are under `/v1`, speak JSON except pack transfer, and require
`Authorization: Bearer <token>` unless marked public.

| Method | Path | Scope | Request | Response |
| --- | --- | --- | --- | --- |
| GET | `/v1/health` | public | – | `{status, version, protocol, time}` |
| GET | `/v1/repo` | backup | – | repo id, `key_id`, counts, sizes |
| GET | `/v1/metrics` | admin | – | Prometheus text |
| POST | `/v1/objects/exists` | backup | `{ids:[≤5000]}` | `{present:[…]}` |
| POST | `/v1/objects/locate` | backup | `{ids:[≤2000]}` | `{objects:{id:[pack,off,len,flags,plainlen]}, missing:[…]}` |
| POST | `/v1/packs` | backup | pack bytes, `X-Haven-Pack-Id` | `{pack, objects, new_objects, stored_bytes, duplicate}` |
| GET | `/v1/packs/<sha256>?offset=&length=` | backup | – | bytes |
| PUT | `/v1/snapshots` | backup | manifest | `{id, existing, entries, objects}` |
| GET | `/v1/snapshots?host=&limit=` | backup | – | `{snapshots:[summary…]}` |
| GET | `/v1/snapshots/<id>` | backup | – | manifest |
| DELETE | `/v1/snapshots/<id>` | admin | – | `{id, deleted, bytes}` |
| POST | `/v1/prune` | admin | `{policy, apply, host?}` | keep/delete/deleted lists |
| POST | `/v1/gc` | admin | `{apply, min_age_hours}` | dead/partial/reclaimable |
| POST | `/v1/verify` | admin | `{deep}` | `{ok, packs, objects, snapshots, errors}` |

Errors are always `{"error": {"code", "message", "detail"?}}` with a stable
`code`: `usage_error`/`config_error` (400), `unauthorized` (401), `forbidden`
(403), `not_found` (404), `method_not_allowed` (405), `conflict` (409),
`integrity_error` (422), `object_missing` (422), `payload_too_large` (413). The
client maps them back to exception types, so scripts can branch on `exc.code`.

Limits: `Content-Length` is mandatory (no chunked bodies); packs are capped by
`max_pack_bytes` (default 512 MiB, configurable — a pack is one run's new data);
JSON bodies at 128 MiB (≈1 million manifest entries); 5000 ids per `exists`
call and 2000 per `locate` call.

Every response carries `X-Request-Id` (also logged) so a client complaint can be
matched to a server log line.

## 5. Write path

```
 1  client: pre-hook (optional, e.g. pg_dump)
 2  client: walk sources, lstat every path, apply excludes/one-file-system
 3  client: for each regular file
      a  cache lookup by (path, size, mtime_ns, ctime_ns, chunker id)
      b  on miss: open O_NOFOLLOW, fstat vs lstat, read, chunk (gear)
      c  compress each chunk, append payload to a spill file, record id/length
 4  client: collect distinct chunk ids referenced by the manifest
 5  client: POST /v1/objects/exists            (which do we still need?)
 6  client: if a cached file references missing chunks, re-read that file
 7  client: write one or more packs (each below the server's max_pack_bytes)
           containing only the missing chunks
 8  client: POST /v1/packs                      (once per pack; server re-hashes
                                                everything)
 9  client: sign manifest, PUT /v1/snapshots
10  server: validate structure + signature, verify every referenced object
            exists, write manifest + meta atomically
11  client: commit the chunk cache, run post-hook, drop the spill file
```

Steps 5–9 are what make incremental runs cheap: a run with no changes uploads
zero bytes and commits a manifest that typically compresses to a few kilobytes.

### Failure points

| Failure | State afterwards |
| --- | --- |
| Crash during walk / chunking | nothing happened on the server; spill file is in a temp dir |
| Crash during pack write | temp pack never renamed; server sees nothing |
| Upload aborted mid-body | server deletes `tmp/upload-*.part`, no pack registered |
| Pack arrives truncated/corrupt | 422, temp file removed, no index row |
| Crash between pack rename and index commit | startup detects pack-count mismatch and rebuilds the index |
| Crash before manifest PUT | the pack is unreferenced; the next `gc` reclaims it |
| Client killed after manifest PUT | snapshot is complete and restorable; only the local cache is stale |

## 6. Read path

```
1  client: GET /v1/snapshots/<id>      (server and client both verify the HMAC)
2  client: validate paths, filter by --include/--exclude, sort by depth
3  client: plan actions per entry (write | skip | link), honouring --overwrite
4  client: POST /v1/objects/locate for every chunk that will be written
5  client: GET /v1/packs/<id>?offset&length, coalescing nearby ranges
           (≤8 MiB per request), verify sha256 == obj id, decode, stage
6  client: for each entry: create parents (containment-checked), write bytes,
           truncate, chmod, utime; symlinks/hardlinks handled explicitly
7  client: apply directory metadata in reverse depth order (read-only trees work)
```

Nothing is written before every chunk is downloaded and verified, so a restore
either has all its data or leaves the target untouched (except for directories
created while applying, which are harmless and idempotent).

## 7. Integrity layers

| Layer | Detects | Where |
| --- | --- | --- |
| `sha256(plaintext) == obj_id` | bit rot, wrong chunk, bad client | ingest, `verify`, every restore write |
| pack trailer digest | truncation, in-place modification | ingest (`deep=True`), `havend verify` |
| `pack_id == sha256(file)` | corrupted download, mixed-up files | client compares `X-Haven-Pack-Id`, `havend verify` |
| manifest HMAC | edited metadata, wrong repository | PUT, GET, GC, restore |
| chunk lengths sum to `s` | internally inconsistent manifest | `validate_manifest` |

`havend verify --quick` checks structure and references; `havend verify` (and
`haven verify --all`) reads every payload and re-hashes it.

## 8. Concurrency and consistency

* **Server threads**: `ThreadingHTTPServer`, one thread per connection. All
  index mutations go through `Repository._tx()`, which takes an `RLock` and a
  SQLite `BEGIN IMMEDIATE`; reads take the same lock for short queries.
  SQLite runs in WAL mode with `synchronous=NORMAL` and a 30 s busy timeout.
* **Cross-process lock**: `flock`/`msvcrt` on `<repo>/lock`, held exclusively by
  `gc --apply` and by nothing else. Restores and backups never take it, so a GC
  cannot block clients, and a GC started twice refuses to interleave.
* **Atomicity**: every file that readers can see is written to a temp name,
  `fsync`ed, then `os.replace`d; directories are `fsync`ed on POSIX.
* **GC safety window**: packs younger than `--min-age-hours` (default 1 h) are
  never deleted, because a client may have uploaded a pack and not yet
  committed its manifest. The same reason makes GC refuse to run at all if any
  manifest is unreadable.
* **Snapshot idempotency**: `put_snapshot` with an existing id compares bytes;
  identical content returns `existing: true`, different content is a 409.
* **Destructive paths verify first**: `prune` and `gc` re-validate every manifest
  signature before deciding what may be deleted, so a tampered manifest cannot
  drop references and cause its chunks to be collected.
* **GC versus restores**: GC does not take a read lease per restore. It skips
  packs younger than the age window (protecting in-flight uploads), but a pack
  deleted because its last snapshot was pruned can break a restore that is
  running at that moment. Run `prune`/`gc` outside restore windows; a broken
  restore fails loudly with a checksum or 404 error and can simply be re-run
  against a snapshot that is still retained.

## 9. Retention and garbage collection

`select_keep()` sorts snapshots per host newest-first and takes the union of:

* the newest `keep_last` snapshots,
* the newest snapshot of each of the last `keep_daily` days,
* … of each of the last `keep_weekly` ISO weeks, `keep_monthly` months,
  `keep_yearly` years,
* everything younger than `keep_within_days` (optional safety net).

Bucket keys are UTC `(y,m,d)`, `(iso_year, iso_week)`, `(y,m)`, `(y,)`. A policy
that would keep nothing is rejected at construction and again by the CLI.

`gc` computes the union of referenced objects across all manifests, then:

* pack with no live objects and old enough → delete pack + index + rows;
* pack with some live objects → rewrite the live objects into a fresh pack,
  install it, then delete the old pack;
* pack younger than the age threshold → leave it alone.

## 10. Capacity and performance model

| Thing | Cost |
| --- | --- |
| Object row | ~120 B in SQLite (10 M objects ≈ 1.5 GB) |
| Manifest | ~60–200 B per path, compressed only by TLS |
| Pack overhead | 44 B per object + 44 B per pack |
| Pack size | clients split at `max_pack_bytes`, so a first full backup works with any configured cap |
| Chunking | ≈5 MB/s per core (measured, CPython 3.13, single thread) |
| Compression | zlib level 6, ≈40–100 MB/s |
| Restore | network-bound; range reads coalesce to ≤8 MiB |

Example from the smoke test on the development machine: 302 KiB of files
chunked into 3 chunks and stored in a 1.7 KiB pack; the second run of the same
tree reported `0 new chunks`, `0 B transferred`, and committed a manifest in
0.1 s.

Practical ceiling for one repository: a few thousand snapshots and ~10 million
chunks. Beyond that, split by host group into several repositories — the origin
of every chunk is recorded, but nothing shards automatically.

## 11. Failure modes and recovery

| Symptom | Likely cause | Action |
| --- | --- | --- |
| `400 config_error` on PUT snapshot | path validation (absolute, `..`, duplicate) | fix the client; manifests are never silently repaired |
| `422 object_missing` | client uploaded a pack but the index lost it, or packs were deleted | `havend repair-index`; if objects are gone, the snapshot is not restorable and must be retaken |
| `422 integrity_error` on upload | network corruption or client bug | nothing stored; re-run the backup |
| `manifest … signature is invalid` | client secret ≠ repository secret, or metadata edited | compare `key_id` via `haven check`, distribute the right secret |
| `pack checksum mismatch` in `verify` | disk corruption | replace the pack from a replica; the affected snapshots are listed |
| daemon starts and rebuilds the index | crash between pack rename and commit | expected, no action; check the log for how many packs were re-read |

## 12. Design decisions

| Decision | Alternative | Why |
| --- | --- | --- |
| Pure stdlib Python | Go/Rust binary | zero build toolchain on client servers; the daemon is CPU-light and I/O-bound. The chunker is the only hot loop and is isolated behind one function |
| Gear CDC | fixed-size blocks | survives insertions/edits in large files; fixed mode is still available for media volumes |
| One pack per run | per-chunk files | 100 k small files would otherwise create 100 k files and 100 k HTTP requests |
| Pack id = sha256(file) | random uuid | idempotent uploads, verifiable with standard tools |
| SQLite index | in-memory dict | 10 M chunks × 130 B would be ~1.3 GB of RAM and a slow start; SQLite gives indexed lookups and crash-safe writes |
| HMAC manifest | plain JSON | the server must be able to tell a tampered snapshot from a real one; a shared secret is the cheapest mechanism that works with a single repository |
| No client-side encryption in v1 | convergent AES-GCM | convergent encryption is easy to get subtly wrong and would not compose with server-side verification; the volume is encrypted with LUKS instead (see security.md) |
| Bearer tokens, two scopes | mTLS | far simpler to operate on a fleet; TLS already protects the channel, and tokens are hashed at rest |
| Restore refuses symlinked parents | follow and write | a manifest must not be able to write outside the target |

## 13. Compatibility and versioning

* `PROTOCOL_VERSION` is sent on every request; the server rejects nothing today
  but a future breaking change will use `/v2`.
* `format: 1` in `repo.json` and in manifests. Unknown formats are refused
  rather than guessed.
* Chunk boundaries are defined by an immutable 256-entry table in
  `chunker.py`; `chunker.version` travels in the manifest, and the per-file
  cache is keyed by the full parameters, so changing defaults never corrupts
  dedup — it only reduces reuse for old data.
* Codec flags are per object, so new codecs can be added without rewriting
  packs.

## 14. Non-goals

Web UI, Windows/macOS clients, block-level images, application-consistent
database agents, multi-tenant isolation inside one repository, and automatic
replication between repositories. The repository format is simple enough to
replicate with `restic`/`rclone`/`rsync` snapshots of the directory, which is
the recommended approach (see operations.md).
