# Operations runbook

Everything here is written for a sysadmin at 03:00 with a pager. Commands are
copy-pasteable; paths match `deploy/*.example`.

## 1. Prerequisites

| Item | Requirement |
| --- | --- |
| OS | Any Linux with systemd (tested on Debian/RHEL-family layouts) |
| Python | 3.11 or newer on server and clients (`python3 --version`) |
| Repository disk | Local filesystem, no NFS/CIFS (SQLite + `flock`) |
| Network | TCP/8443 from clients to the repository host, nothing else |
| Time | `chrony`/`ntpd` on every host — snapshot ids and retention buckets use client clock |

The repository is a single directory. Sizing rule of thumb: **1.2 × the total
deduplicated data** plus room for one GC rewrite (a partially-live pack is
rewritten before the old one is deleted). Start with 2 × the first full backup.

## 2. Install the repository server

```sh
git clone <repo> /opt/haven && cd /opt/haven
sudo ./deploy/install-server.sh
```

That creates the `haven` system user, `/var/lib/haven/repo` (0700),
`/etc/haven/{server.toml,repo.secret,tokens.json}`, installs `havend`/`haven`
into `/usr/local/bin`, and enables `haven-server.service`.

TLS (recommended; skip only if a reverse proxy terminates it):

```sh
sudo ./deploy/gen-tls.sh backup.example.com
sudo vi /etc/haven/server.toml     # tls_cert / tls_key already point there
sudo chown -R haven:haven /etc/haven/tls && sudo chmod 600 /etc/haven/tls/server.key
```

Create the repository and the first credentials:

```sh
sudo -u haven havend --config /etc/haven/server.toml init --name primary
#   prints: repo id, key id, and the 64-hex repository secret (once)
sudo -u haven havend --config /etc/haven/server.toml token add --name web-01 --scope backup
#   prints a hvn_… token (once)
sudo systemctl restart haven-server
```

Firewall:

```sh
sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=10.20.0.0/24 port port=8443 protocol=tcp accept'
sudo firewall-cmd --reload
# nftables: tcp dport 8443 ip saddr 10.20.0.0/24 accept
```

Health check from a client network host:

```sh
curl --cacert /etc/haven/tls/ca.crt https://backup.example.com:8443/v1/health
```

## 3. Provision clients

Copy `ca.crt` to the client host, then:

```sh
sudo ./deploy/install-client.sh system
sudo install -m 0644 ca.crt /etc/haven/tls/ca.crt
sudo vi /etc/haven/client.toml
```

Minimum profile:

```toml
[profiles.system]
url = "https://backup.example.com:8443"
token = "hvn_…"
secret = "<64 hex from havend init>"
paths = ["/etc", "/srv", "/var/lib/postgresql"]
ca_file = "/etc/haven/tls/ca.crt"
```

Then:

```sh
haven --config /etc/haven/client.toml --profile system check
```

`check` compares the server's `key id` with `sha256(secret)[:16]`; a mismatch
means the secret is wrong and every manifest upload will fail with
`integrity_error`.

## 4. First backup and a restore drill

```sh
sudo haven --config /etc/haven/client.toml --profile system backup --label first
sudo haven --config /etc/haven/client.toml --profile system snapshots
sudo haven --config /etc/haven/client.toml --profile system verify <snapshot>
sudo haven --config /etc/haven/client.toml --profile system restore <snapshot> --to /var/tmp/restore-test
diff -r /etc /var/tmp/restore-test/etc
```

Do this on every host you onboard, and record in the change ticket that it was
done. A backup that has never been restored is a hypothesis.

## 5. Scheduling

```sh
sudo systemctl enable --now haven-backup@system.timer       # nightly 02:30 ±30 min
sudo systemctl enable --now haven-maintenance@system.timer  # Sunday 04:30: prune + gc
sudo systemctl enable --now haven-verify@system.timer       # first Sunday, monthly, heavy
journalctl -u haven-backup@system -n 50 --no-pager
```

Without systemd:

```cron
30 2 * * * root /usr/local/bin/haven --config /etc/haven/client.toml --profile system backup >/var/log/haven/backup.log 2>&1
30 4 * * 0 root /usr/local/bin/haven --config /etc/haven/client.toml --profile system prune --apply \
             && /usr/local/bin/haven --config /etc/haven/client.toml --profile system gc --apply
```

### Database hooks

Hooks are shell commands run by the client; a non-zero exit aborts the backup
(unless `--ignore-hook-failure`). Dump first, then back the dump up. Both flags
and the `HAVEN_PRE_HOOK` / `HAVEN_POST_HOOK` environment variables are honoured,
which is what makes a systemd drop-in work:

```ini
# systemctl edit haven-backup@system
[Service]
Environment=HAVEN_PRE_HOOK=/usr/local/sbin/haven-pg-dump
Environment=HAVEN_POST_HOOK=/usr/local/sbin/haven-pg-cleanup
```

```sh
# /usr/local/sbin/haven-pg-dump
#!/bin/sh
set -eu
sudo -u postgres pg_dumpall --clean | gzip -1 > /var/backups/postgres/all.sql.gz
```

or pass them on the command line where a scheduler is not involved:

```sh
haven --profile system backup /etc /srv --pre-hook '/usr/local/sbin/haven-pg-dump' \
      --post-hook '/usr/local/sbin/haven-pg-cleanup'
```

For MySQL use `mysqldump --single-transaction --all-databases`; for filesystems
that support snapshots (LVM, btrfs, ZFS) mount the snapshot and back that up
instead — Haven does not freeze the filesystem itself.

## 6. Monitoring

Scrape `GET /v1/metrics` with an admin token (Prometheus text format):

```yaml
- job_name: haven
  scheme: https
  metrics_path: /v1/metrics
  bearer_token_file: /etc/prometheus/haven.token
  tls_config:
    ca_file: /etc/prometheus/haven-ca.crt
  static_configs:
    - targets: ["backup.example.com:8443"]
```

Metrics: `haven_repo_packs`, `haven_repo_objects`, `haven_repo_stored_bytes`,
`haven_repo_logical_bytes`, `haven_snapshots{host}`, and
`haven_snapshot_last_created_seconds{host}`.

Alert on the last one — the failure mode that matters is *silence*:

```yaml
- alert: HavenSnapshotStale
  expr: time() - haven_snapshot_last_created_seconds > 129600   # 36 h
  for: 30m
  labels: { severity: warning }
  annotations:
    summary: "{{ $labels.host }} has no successful backup for 36 h"
```

Also alert on: `up{job="haven"} == 0`, `haven server journal` containing
`token reload failed` or `internal error`, and disk space below 15 %.

Health endpoint (`/v1/health`, no auth) is safe for load balancers and uptime
checks.

## 7. Retention

Per host, in the client profile:

```toml
[profiles.system.retention]
keep_last = 3        # always keep the 3 newest
keep_daily = 7
keep_weekly = 4
keep_monthly = 12
keep_yearly = 0
keep_within_days = 0 # e.g. 2.0 as a safety net during a policy change
```

`haven prune` **without flags applies this profile**; any `--keep-*` flag given
on the command line overrides that one field. The weekly maintenance unit calls
`prune --apply` with no flags, so the profile is the single place to tune
retention.

Preview then apply:

```sh
haven --profile system prune                                  # what would be deleted
haven --profile system prune --apply                          # delete manifests
haven --profile system gc --apply --min-age-hours 1           # reclaim space
```

`prune` only removes manifests; **nothing is freed until `gc` runs**. Both
commands read and verify every manifest signature before acting: a tampered or
unreadable manifest aborts them rather than risking the deletion of data it
might reference. `gc` also skips packs younger than `--min-age-hours` so a
client that is mid-backup cannot lose its upload.

## 8. Backing up the backup

The repository is a plain directory; replicate it off-site, read-only:

```sh
# nightly, from a machine that has read access (rclone to S3-compatible storage)
rclone sync /var/lib/haven/repo remote:offsite/haven-repo --immutable --checksum

# or restic, which gives you encryption + retention of its own
restic backup /var/lib/haven/repo --tag haven

# or ZFS/btrfs snapshots locally then send
zfs snapshot tank/haven@$(date +%F) && zfs send -i @yesterday tank/haven@$(date +%F) | ssh offsite zfs recv tank/haven
```

Rules that keep a replica usable:

1. Copy `packs/`, `snapshots/`, `repo.json`; `state/` and `tmp/` are disposable.
2. Use an immutable or append-only target if you can (S3 Object Lock, a
   write-once bucket) — ransomware that reaches the server should not be able to
   rewrite history.
3. Verify a replica by restoring from it: `havend --config <copy> verify` on a
   test host with the same secret.
4. Keep `repo.secret` **out of band** (password manager / sealed envelope). A
   replica without the secret cannot be validated; a secret without a replica is
   useless.

## 9. Restore runbook

### 9.1 Single file or directory

```sh
haven --profile system snapshots --host web-01
haven --profile system restore <snapshot> --to /var/tmp/restore \
      --include '**/etc/nginx/nginx.conf' --overwrite always
install -m 0644 /var/tmp/restore/etc/nginx/nginx.conf /etc/nginx/nginx.conf
nginx -t && systemctl reload nginx
```

`--include`/`--exclude` match the path as stored (relative to `/`). Restoring
to a scratch directory and copying the file into place avoids surprising a
running daemon.

### 9.2 Whole host, in place (the common disaster case)

Boot the host from rescue media or a live image, mount its root at `/mnt`, then:

```sh
haven --profile system restore <snapshot> --to /mnt --overwrite always --owner
```

If the host is running and you are restoring over it (e.g. `/etc` was deleted):

```sh
haven --profile system restore <snapshot> --to /var/tmp/restore --overwrite always --owner
rsync -aHAX --numeric-ids /var/tmp/restore/ /
```

The staging + `rsync` pattern is the recommended one: you can inspect what is
about to change, `rsync` handles existing files and hardlinks well, and an
interrupted restore can be restarted.

Restoring directly to `/` is possible (`--to / --yes`), but it writes through
whatever symlinks the live system has and is harder to audit.

### 9.3 Restore to a different host (migration)

```sh
# on the new host, with a profile pointing at the same repository
haven --profile system restore <snapshot> --to /srv/newhost --overwrite always --owner
```

Paths are stored relative to the filesystem root, so `/srv/newhost/etc/...`
reproduces the original layout. Then adjust `fstab`, hostname, network config
and machine-id by hand — Haven restores files, not identity.

### 9.4 Always verify after a restore

```sh
haven --profile system verify <snapshot>          # re-reads and hashes all chunks
diff -r /etc /var/tmp/restore/etc                  # spot-check the files you care about
```

`restore` already verifies every chunk hash while writing; `verify` additionally
proves the repository copy is intact.

## 10. Disaster recovery scenarios

| Scenario | Impact | Recovery |
| --- | --- | --- |
| Client disk lost | data gone on client | restore latest snapshot to new disk (§9.2), then re-run `check` and a backup |
| Repository disk lost, replica exists | none if replica is current | restore `packs/`, `snapshots/`, `repo.json` from replica; run `havend repair-index`; `havend verify` |
| Repository lost, no replica | **all backups lost** | nothing; this is why §8 exists |
| `repo.secret` lost but repository intact | cannot validate manifests; clients cannot upload; GC refuses | restore the secret from escrow. Without it, `havend` cannot prove metadata integrity; manifests can be re-signed only by the holder of the old secret |
| Server host rebuilt | downtime only | reinstall, restore repo directory, re-issue tokens (`havend token add`), clients update `token` |
| Suspicious manifest changes | possible tampering | `havend verify`, compare `key_id`, rotate the secret (`havend rotate-secret`) and re-provision clients |
| Ransomware on a client | files encrypted, backups intact | restore from the last clean snapshot; **do not** delete snapshots until the timeline is clear |
| Clock skew on a client | snapshot ids and retention buckets look wrong | fix NTP; retention uses recorded `created` times, so ordering may be off until corrected |

## 11. Restore drills

Monthly, on one host per environment:

```sh
sudo systemctl start haven-verify@system.service     # full read-back + hash check
sudo haven --profile system restore <recent> --to /var/tmp/drill-$(date +%F)
sudo du -sh /var/tmp/drill-*; sudo rm -rf /var/tmp/drill-*
```

Record: snapshot id, duration, bytes, any `errors` in the restore report, and
the time to first useful file. Rehearse the "repository host is dead" path once
a year with the off-site replica.

## 12. Upgrades

```sh
sudo systemctl stop haven-server
sudo git -C /opt/haven pull && sudo make -C /opt/haven install
sudo -u haven havend --config /etc/haven/server.toml verify --quick
sudo systemctl start haven-server
```

The on-disk format (`format: 1`) and the protocol (`/v1`) are stable within
1.x; a future breaking format arrives with a migration command, not silently.
Clients can be upgraded independently — old clients keep working because the
protocol is additive.

Rollback: keep the previous checkout, `make install` from it, restart. Data
written by a newer version into an older format is refused loudly rather than
misread.

## 13. Troubleshooting

| Symptom | Diagnosis | Fix |
| --- | --- | --- |
| `error: configuration file not found` | wrong `--config`/`--profile` | `haven --profile <name> check`; profiles are listed in the error of an unknown name |
| `401 unauthorized` | token wrong or revoked | `havend token list`, re-issue, update client |
| `403 forbidden` | token lacks `admin` | issue a token with `--scope backup,admin` for prune/gc |
| `422 integrity_error` on backup | secret mismatch or corrupted upload | `haven check` for `key_id`; retry (uploads are idempotent) |
| `413 payload_too_large` on backup | a single chunk is larger than `max_pack_bytes`, or a proxy caps the body | keep `max_pack_bytes` above the chunk maximum (8 MiB by default) and above your proxy limit; uploads are split per pack |
| `500 internal server error` | server bug or disk problem | check `journalctl -u haven-server`, look for the `X-Request-Id` of the failed call |
| Backup is slow and `chunk cache: 0 hits` | cache path not writable, or files always change | check `/var/cache/haven`, permissions; `--no-cache` for a baseline measurement |
| Backup fails with `no work directory with free space` | pack staging needs room ≈ one run's new data | set `work_dir` in the profile to a volume with space |
| `timed out waiting for lock` | a `gc` is running, or a crashed process left the lock | `fuser /var/lib/haven/repo/lock`; the OS releases `flock` when the process dies, so a stale lock means a live process |
| `pack checksum mismatch` in `verify` | bit rot on the server disk | replace the pack from a replica; listed snapshots are affected |
| `snapshot … signature is invalid` on GET | manifest edited on disk, or wrong secret | compare with a replica; if edited, treat as an incident |
| Disk full on server | packs + GC headroom | add space; `prune --apply && gc --apply`; GC needs room for one pack rewrite |
| `database is locked` | two daemons on one repository | run exactly one `havend` per repository directory |

Diagnostic commands:

```sh
sudo -u haven havend --config /etc/haven/server.toml verify --quick
sudo -u haven havend --config /etc/haven/server.toml verify          # deep, slow
sudo -u haven havend --config /etc/haven/server.toml repair-index
sudo -u haven havend --config /etc/haven/server.toml token list
du -sh /var/lib/haven/repo/*; df -h /var/lib/haven
sqlite3 /var/lib/haven/repo/state/index.sqlite 'select count(*) from objects;'
```

## 14. Reference

| Path | Purpose |
| --- | --- |
| `/etc/haven/server.toml` | daemon configuration |
| `/etc/haven/repo.secret` | repository secret, 0600, root/haven only |
| `/etc/haven/tokens.json` | token hashes, 0600 |
| `/var/lib/haven/repo/` | repository |
| `/etc/haven/client.toml` | client profiles, 0600 |
| `/var/cache/haven/index.sqlite` | per-file chunk cache (safe to delete) |

| Command | Meaning |
| --- | --- |
| `systemctl reload haven-server` | re-read `tokens.json` (SIGHUP) |
| `systemctl stop haven-server` | graceful shutdown, flushes SQLite |
| `haven cache clear` | force a full re-read on the next backup |
| `haven prune --apply` | apply retention; `gc` frees the space |
