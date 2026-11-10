# Security model

## 1. What Haven guarantees

| Guarantee | Mechanism |
| --- | --- |
| Backed-up bytes are exactly what was read | SHA-256 per chunk, verified at ingest, at restore, and by `verify` |
| Stored data is not silently corrupted or truncated | per-object hash, pack trailer digest, pack id = sha256(file) |
| Snapshot metadata cannot be edited undetected | HMAC-SHA256 over the canonical manifest, keyed from the repository secret |
| A restore cannot write outside the target directory | path validation plus `realpath` containment on every entry |
| A root backup cannot be turned into a file-exfiltration primitive | `O_NOFOLLOW` + `fstat`/`lstat` inode comparison while reading |
| Credentials are not readable from the token file | only SHA-256 hashes are stored; the plaintext is shown once |
| The daemon cannot be trivially escalated if compromised | systemd sandbox: no capabilities, no new privileges, read-only `/`, writable only `/var/lib/haven` |

## 2. What Haven does **not** guarantee

* **The server does not encrypt data at rest.** Packs and manifests are plain
  files; anyone with the disk sees the data. This is a deliberate v1 decision
  (§6) — encrypt the volume with LUKS/dm-crypt.* **The server operator can read every backed-up file.** Single-tenant trust
  model: the repository is operated by the same organisation that owns the data.
* **A compromised client can forge manifests.** The repository secret is shared
  by all clients (it must be, to verify each other's metadata). See §7.
* **No ACLs or extended attributes are captured**, so a restore may lose SELinux
  contexts, POSIX ACLs, and file capabilities. Modes, ownership, mtimes,
  symlinks, hardlinks and sparse extents are preserved.
* **No per-token rate limiting or quota.** A stolen `backup` token can upload
  until the disk is full. Put the endpoint behind a firewall or a reverse proxy
  with limits if it is reachable from untrusted networks.
* **Deduplication reveals equality, not content.** The server can tell that two
  clients store the same chunk (and therefore probably the same file), and the
  size distribution of chunks. Acceptable in a single-tenant deployment; a
  problem for multi-tenant use.

## 3. Assets and adversaries

| Asset | Where it lives |
| --- | --- |
| Backup data (confidentiality, integrity, availability) | repository packs |
| Snapshot metadata (integrity) | repository manifests, client memory |
| Repository secret (metadata authenticity) | `/etc/haven/repo.secret`, client profiles |
| Client tokens (authorisation) | `tokens.json` (hashes), client profiles (plaintext) |
| TLS private key (channel integrity) | `/etc/haven/tls/server.key` |

Adversaries considered: a network attacker on the path, a compromised client on
the fleet, a compromised server process, a user on a backed-up host who can
create files and symlinks (including while a root backup is running), an
operator making a mistake, and disk failure/bit rot. Not considered: a hostile
hypervisor, physical attacks on RAM, or a compromised CA.

## 4. Controls

### 4.1 Transport

* TLS 1.2+ (`ssl.PROTOCOL_TLS_SERVER`, minimum TLSv1.2) when `tls_cert`/`tls_key`
  are configured. Clients verify the chain against `ca_file` or the system store.
* `insecure = true` exists for lab use and disables verification — never in
  production; it is the difference between a private channel and handing your
  bearer token to whoever answers on port 8443.
* The daemon speaks plain HTTP only if TLS is not configured; `deploy/gen-tls.sh`
  creates a private CA and a server certificate, and the sample config points at
  them.

### 4.2 Authentication and authorisation

* `Authorization: Bearer <token>`; tokens are 32 random bytes (`hvn_` prefix,
  base64url). Only `sha256(token)` is stored, so a leaked token file does not
  yield usable tokens.
* Two scopes: `backup` (read repo, upload packs, write snapshots) and `admin`
  (delete snapshots, prune, gc, verify, metrics). `admin` implies `backup`.
* Token comparison is a hash lookup; the token is never logged and never
  appears in error bodies.
* SIGHUP (`systemctl reload haven-server`) reloads the token file without
  dropping connections, so revocation is immediate and online.
* The token file must be mode 0600 on POSIX; the daemon refuses to start
  otherwise.

### 4.3 Integrity

* Object ids are SHA-256 of the plaintext chunk; the server decompresses and
  re-hashes every object on ingest and rejects the whole pack if one is wrong.
* The pack trailer is a SHA-256 over all preceding bytes; a truncated or edited
  pack fails to parse.
* `pack_id` is the SHA-256 of the file and is checked against the client's
  `X-Haven-Pack-Id` header, so a truncated upload is caught before indexing.
* Manifests are signed with
  `HMAC-SHA256(HMAC-SHA256(secret, "haven-manifest-v1"), canonical_json(body))`.
  Verified on upload and on every read by the server, and again by the client in
  `RemoteRepo.get_snapshot` before a restore uses the entries; prune and GC
  verify every manifest before deciding what to delete.
* `validate_manifest` rejects absolute paths, `..`, NUL bytes, duplicate paths,
  unknown entry types, and chunk lists whose lengths do not add up to the file
  size.

### 4.4 Restore safety

Restoring runs as root and writes files whose names come from a manifest, so it
is treated as an untrusted-input parser:

1. `safe_rel_parts()` rejects absolute paths, drive letters, `..` and empty
   components.
2. Each target path is resolved with `realpath` and compared against the
   resolved target root; if a symlink — from the manifest or already present on
   disk — redirects the path outside, the entry is refused and recorded as an
   error.
3. Existing symlinks are unlinked before writing, never followed; files are
   opened with `O_NOFOLLOW`.
4. Before touching anything, every chunk is downloaded and hash-verified, so a
   partial or tampered repository cannot leave a half-written tree behind.

### 4.5 Backup-side hardening

* Files are read with `O_NOFOLLOW`; `fstat` must match the earlier `lstat`
  (`st_dev`, `st_ino`), otherwise the file is recorded as an error instead of
  read. This defeats a user swapping a file for a symlink to `/etc/shadow`
  between the two calls.
* Only regular files are read; sockets, FIFOs and devices are recorded as
  skipped entries.
* Hooks are shell commands from the client configuration file, which is
  root-owned and 0600; they are not a remote input channel.

### 4.6 Server hardening

`deploy/haven-server.service` runs as the unprivileged `haven` user with
`NoNewPrivileges`, `ProtectSystem=strict` (writable only `/var/lib/haven`),
`ProtectHome`, `PrivateTmp`, `PrivateDevices`, `ProtectKernel*`,
`RestrictAddressFamilies`, `RestrictNamespaces`, `LockPersonality`,
`MemoryDenyWriteExecute`, an empty capability set and a `@system-service`
syscall filter. It binds an unprivileged port (8443).

### 4.7 Availability / abuse limits

| Limit | Value |
| --- | --- |
| Pack upload | `max_pack_bytes` (default 512 MiB, sample config 2 GiB) |
| JSON body | 128 MiB (manifests), 32 MiB (other) |
| Id batches | 5000 (`exists`), 2000 (`locate`) |
| Connection timeout | 300 s idle |
| Request queue | 64 pending connections |
| Concurrent threads | one per connection, no pool cap — protect with a proxy if exposed |

Bodies require `Content-Length`; a request without it (the chunked case) is
refused with `400 usage_error`, so nothing can be streamed without a declared
size.

## 5. Key and credential management

### 5.1 Repository secret

* 32 random bytes, generated by `havend init`, stored in `/etc/haven/repo.secret`
  (0600) and in every client profile (0600).
* Purpose: manifest authenticity. It is **not** an encryption key.
* The server exposes `key_id = sha256(secret)[:16]`; `haven check` compares it,
  which catches the common "wrong secret pasted" failure before a backup runs.

**Rotation** (needed after a client is compromised, or on a schedule):

```sh
sudo systemctl stop haven-server
sudo head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /tmp/haven.newsecret
sudo chmod 600 /tmp/haven.newsecret

sudo -u haven havend --config /etc/haven/server.toml rotate-secret \
     --new-secret-file /tmp/haven.newsecret
#   re-signs every manifest; the previous secret is kept as repo.secret.bak

sudo systemctl start haven-server
sudo shred -u /tmp/haven.newsecret
```

Then update `secret` in every client profile (`haven check` shows the mismatch)
and re-run one backup per host. Manifests are re-signed in place; pack data is
untouched. Rotation is not atomic across a running fleet — that is why the
daemon is stopped. If the command is interrupted, every manifest still verifies
with the old secret; fix the cause (usually permissions on the repository) and
run it again.

### 5.2 Client tokens

* One token per host, scope `backup` (add `admin` only for hosts that run
  `prune`/`gc`).
* Issue: `havend token add --name <host> --scope backup` (prints once).
* Revoke: `havend token revoke --name <host>` then `systemctl reload haven-server`.
* Store in `/etc/haven/client.toml` (0600). Do not put tokens in a
  configuration-management repository that stores secrets in plaintext.

### 5.3 TLS material

`deploy/gen-tls.sh` creates a private CA (4096-bit, 10 years) and a server
certificate (3072-bit, 825 days) with `subjectAltName` for the hostname/IP.
Distribute only `ca.crt` to clients; keep `ca.key` offline after enrolment.
Re-running the script reuses the existing CA and only renews the server
certificate, so clients keep trusting it; pass `--new-ca` to replace the CA
(then redistribute `ca.crt` to every client).

## 6. Encryption at rest: decision and guidance

Haven v1 stores plaintext objects. The alternative — client-side convergent
encryption — was rejected for this version because:

1. Convergent encryption (key derived from plaintext) is what preserves dedup,
   but it leaks equality of plaintexts and is vulnerable to confirmation attacks
   unless the id is keyed, which in turn requires the server to hold a key or to
   give up ingest-time verification.
2. Getting AES-GCM nonces, key derivation and rotation right is exactly the kind
   of code that should not be written from scratch without a review and a test
   matrix.
3. The repository is a single directory on a server that the same team operates;
   full-volume encryption (LUKS) protects the realistic threat (stolen disk,
   decommissioned hardware, backup appliance theft) with mature tooling.

Operational guidance:

```sh
# LUKS2 volume for /var/lib/haven
cryptsetup luksFormat /dev/sdb1
cryptsetup open /dev/sdb1 haven
mkfs.ext4 /dev/mapper/haven
# /etc/crypttab:  haven  /dev/sdb1  /etc/haven/luks.key  luks,discard
```

* Keep the key in TPM/`systemd-cryptenroll` or a key file with 0400 root.
* Encrypt off-site replicas with the replication tool (`restic`, `rclone crypt`)
  — a plain `rsync` of an unencrypted repository to object storage is a data
  breach waiting for a misconfigured bucket.
* Client disks are already covered by whatever disk encryption the fleet uses;
  Haven does not add a second layer.

If client-side encryption becomes a requirement, the extension point is
`codec.py` plus the object-id rule in `backup.py`; the manifest already records
`codec` so old and new snapshots can coexist. It must come with a documented
key hierarchy and a nonce strategy — do not improvise it.

## 7. Residual risks

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Shared repository secret | any client can forge metadata for any host | rotate on suspicion; consider per-host secrets (not implemented) |
| Stolen `backup` token | attacker can read every stored file (any pack range, every manifest), create snapshots, and fill the disk | short-lived tokens, revoke + reload, firewall, disk quota on the volume |
| Stolen `admin` token | delete snapshots, prune, read metrics | admin tokens only on the backup host, not on every client |
| Server process compromise | read all data, modify packs (detected by hashes but not prevented) | sandbox unit, prompt patching, `verify` on a schedule, off-site replica |
| Disk bit rot | a snapshot may become unrestorable | `haven verify --all` monthly + replica; pack hashes localise damage |
| Malicious file names | path traversal on restore | validated on ingest and again with `realpath` containment |
| Symlink race on backup | reading a file the operator did not intend | `O_NOFOLLOW` + inode comparison |
| Clock skew | retention chooses the wrong snapshots | NTP everywhere; `keep_within_days` as a safety net |
| Operator runs GC during a long backup | the new pack is younger than `min-age-hours` and survives; the manifest is not yet written so nothing references it | default 1 h window; do not set `--min-age-hours 0` in production |

## 8. Hardening checklist

Before the first production backup:

- [ ] TLS enabled, `ca_file` set on clients, `insecure` absent.
- [ ] `repo.secret` and `tokens.json` are 0600, owned by `haven`.
- [ ] Repository volume is LUKS-encrypted (or the host's disk is).
- [ ] Daemon reachable only from the backup network (firewall verified from a
      host outside it).
- [ ] One token per host, `backup` scope unless the host runs maintenance.
- [ ] `repo.secret` escrowed outside the repository host.
- [ ] Off-site replica configured, immutable if possible, restore-tested.
- [ ] Alerts on `haven_snapshot_last_created_seconds` and disk usage.
- [ ] Restore drill performed and recorded.
- [ ] `systemd-analyze security haven-server.service` reviewed.

## 9. Incident response

**Token leaked**

```sh
sudo -u haven havend --config /etc/haven/server.toml token revoke --name web-01
sudo systemctl reload haven-server
sudo -u haven havend --config /etc/haven/server.toml token add --name web-01 --scope backup
# update the client profile, then: haven --profile system check
```

Check the daemon log for that token's activity (`client=` and `X-Request-Id`),
and `haven snapshots` for unexpected snapshots (an attacker with a `backup`
token can create snapshots, not delete them).

**Repository secret leaked**

Rotate (§5.1), then treat every manifest created since the leak as suspect:
compare snapshot lists with `haven snapshots --host` against your records; a
forged manifest would reference real chunks, so the tell is an unexpected
snapshot id or an unexpected path set in `haven show`. Delete suspects with
`DELETE /v1/snapshots/<id>` (or `haven prune` after adjusting policy), then
`gc --apply`.

**Server compromised**

Assume data confidentiality is lost. Rebuild from a known-good image, restore
the repository from the immutable replica (verify it first), rotate the
repository secret and every token, and re-run `havend verify`. Compare pack
hashes against the replica to find modified packs.

**Client compromised**

Rotate the secret if that client held it (all clients do), revoke its token,
verify its snapshots (`haven verify`) for the period, and check for unexpected
`paths` in recent manifests.

## 10. What an auditor can check without trusting the code

* `sha256sum packs/*.pack` matches the file names.
* Every manifest's chunk ids exist in `snapshots`/`index.sqlite`; the
  `have verify`/`havend verify` output lists per-pack object counts.
* Each manifest carries an HMAC that the server recomputes with the escrowed
  secret — the check is independent of who wrote the manifest.
* Retention decisions are reproducible: `haven prune` (without `--apply`) prints
  the keep/delete split for the recorded policy.
* The service unit, token file modes and firewall rules are reviewable files in
  this repository.
