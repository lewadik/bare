"""``haven`` — the client command line interface.

Exit codes: ``0`` success, ``1`` failure (including a restore with errors),
``2`` usage or configuration error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys
import time
from pathlib import Path

from . import __version__
from .backup import BackupOptions, BackupRunner
from .cache import ChunkCache
from .chunker import parse_chunking_spec
from .codec import decode, parse_compress_spec
from .config import (
    ClientConfig,
    expand_path,
    load_client_config,
    write_client_config,
)
from .errors import ConfigError, HavenError, UsageError
from .manifest import entry_chunks
from .restore import RestoreOptions, RestoreRunner
from .retention import RetentionPolicy
from .transport import RemoteRepo
from .util import human_bytes, human_duration, parse_iso


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
class Context:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.json = bool(getattr(args, "json", False))
        self.quiet = bool(getattr(args, "quiet", False))
        self.verbose = bool(getattr(args, "verbose", False))
        self._config: ClientConfig | None = None
        self._repo: RemoteRepo | None = None

    @property
    def config(self) -> ClientConfig:
        if self._config is None:
            overrides = {}
            self._config = load_client_config(
                getattr(self.args, "config", None), getattr(self.args, "profile", None)
            )
            chunking = getattr(self.args, "chunking", None)
            compress = getattr(self.args, "compress", None)
            if chunking:
                self._config.chunking = parse_chunking_spec(chunking)
            if compress:
                self._config.compress = parse_compress_spec(compress)
        return self._config

    @property
    def repo(self) -> RemoteRepo:
        if self._repo is None:
            self._repo = RemoteRepo.from_config(self.config)
        return self._repo

    def log(self, message: str) -> None:
        if not self.quiet:
            print(message, file=sys.stderr, flush=True)

    def emit(self, payload) -> None:
        print(json.dumps(payload, indent=2, default=str))

    def progress(self, label: str):
        state = {"next": 10}

        def callback(done: int, total: int) -> None:
            if self.quiet or total <= 0:
                return
            percent = int(done * 100 / total)
            if percent >= state["next"]:
                state["next"] = (percent // 10 + 1) * 10
                print(f"{label}: {percent}% ({done}/{total})", file=sys.stderr, flush=True)

        return callback


def _fmt_time(iso_text: str | None) -> str:
    if not iso_text:
        return "-"
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(parse_iso(iso_text)))
    except Exception:  # noqa: BLE001
        return iso_text


def _table(rows: list[list[str]], headers: list[str]) -> str:
    if not rows:
        return ""
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))
    lines = ["  ".join(header.ljust(widths[index]) for index, header in enumerate(headers))]
    lines.append("  ".join("-" * width for width in widths))
    for row in rows:
        lines.append("  ".join(cell.ljust(widths[index]) for index, cell in enumerate(row)))
    return "\n".join(lines)


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------
def cmd_init(ctx: Context, args) -> int:
    profile = getattr(args, "profile", None) or "default"
    path = expand_path(getattr(args, "config", None) or str(Path("~/.config/haven/client.toml")))
    if path.exists() and not args.force:
        raise ConfigError(f"{path} already exists (use --force to overwrite)")
    secret_hex = args.secret.strip() if args.secret else secrets.token_hex(32)
    try:
        bytes.fromhex(secret_hex)
    except ValueError as exc:
        raise UsageError("--secret must be a hex string") from exc
    write_client_config(
        path,
        profile=profile,
        url=args.url.rstrip("/"),
        token=args.token,
        secret_hex=secret_hex,
        chunking=args.chunking or "min=64K,avg=1M,max=8M",
        compress=args.compress or "zlib:6",
        exclude=args.exclude or [],
        insecure=args.insecure,
        ca_file=args.ca_file,
    )
    result = {
        "config": str(path),
        "profile": profile,
        "checked": False,
        "connected": False,
        "key_id": None,
        "secret_generated": not args.secret,
    }
    status = 0
    if not args.no_check:
        result["checked"] = True
        try:
            config = load_client_config(str(path), profile)
            repo = RemoteRepo.from_config(config)
            info = repo.repo_info()
        except HavenError as exc:
            result["error"] = exc.message
            status = 1
        else:
            expected_key = hashlib.sha256(config.secret).hexdigest()[:16]
            result["key_id"] = info.get("key_id")
            if info.get("key_id") and info["key_id"] != expected_key:
                result["error"] = "repository secret does not match the server"
                result["expected_key_id"] = expected_key
                status = 1
            else:
                result["connected"] = True
                result["repository"] = info.get("name")
    if ctx.json:
        ctx.emit(result)
        return status
    print(f"wrote {path} (mode 0600)")
    if result["secret_generated"]:
        print("a repository secret was generated; give the same value to every client")
    if not result["checked"]:
        return 0
    if result["connected"]:
        print(f"connected to repository {result.get('repository')!r}, key id matches")
        return 0
    print(f"warning: {result.get('error')}", file=sys.stderr)
    return status


def cmd_check(ctx: Context, args) -> int:
    health = ctx.repo.health()
    info = ctx.repo.repo_info()
    expected_key = hashlib.sha256(ctx.config.secret).hexdigest()[:16]
    key_ok = not info.get("key_id") or info["key_id"] == expected_key
    payload = {"health": health, "repo": info, "secret_matches": key_ok, "profile": ctx.config.profile}
    if ctx.json:
        ctx.emit(payload)
    else:
        print(f"server      : {ctx.config.url} ({health.get('status')}, version {health.get('version')})")
        print(f"repository  : {info['name']} ({info['repo_id'][:12]})")
        print(f"profile     : {ctx.config.profile} ({ctx.config.config_path})")
        print(f"snapshots   : {info['snapshots']} on hosts {', '.join(info['hosts']) or '-'}")
        print(f"stored      : {human_bytes(info['stored_bytes'])} for {human_bytes(info['logical_bytes'])} of data")
        print(f"dedup       : {info['dedup_ratio'] * 100:.1f}% saved")
        print(f"secret      : {'matches' if key_ok else 'MISMATCH (wrong repository secret)'}")
    return 0 if key_ok else 1


def cmd_backup(ctx: Context, args) -> int:
    config = ctx.config
    sources = list(args.sources or config.paths)
    if not sources:
        raise UsageError("no sources given and none configured (profile 'paths = [...]')")
    options = BackupOptions(
        sources=sources,
        excludes=list(args.exclude or []),
        one_file_system=args.one_file_system,
        label=args.label or "",
        dry_run=args.dry_run,
        use_cache=not args.no_cache,
        pre_hook=args.pre_hook or os.environ.get("HAVEN_PRE_HOOK"),
        post_hook=args.post_hook or os.environ.get("HAVEN_POST_HOOK"),
        ignore_hook_failure=args.ignore_hook_failure,
        work_dir=expand_path(args.work_dir) if args.work_dir else None,
    )
    runner = BackupRunner(
        ctx.repo, config, options, log=ctx.log, progress=ctx.progress("upload")
    )
    result = runner.run()
    if ctx.json:
        ctx.emit(result)
    else:
        stats = result["stats"]
        print(f"snapshot    : {result['snapshot'] or '(dry run, not committed)'}")
        print(f"host        : {result['host']}")
        print(f"files       : {stats['files']} files, {stats['dirs']} dirs, {stats['symlinks']} symlinks")
        print(f"data        : {human_bytes(stats['bytes_total'])} total, {human_bytes(stats['bytes_new'])} new")
        print(
            f"chunks      : {stats['chunks']} referenced, {stats['chunks_new']} new, "
            f"{stats.get('chunks_reused', 0)} reused"
        )
        print(f"transferred : {human_bytes(result['upload'].get('pack_bytes', 0))}")
        print(f"duration    : {human_duration(result['duration_ms'] / 1000)}")
        if result["warnings"]:
            print(f"warnings    : {len(result['warnings'])} (first: {result['warnings'][0]})")
    return 0 if result["stats"]["errors"] == 0 else 1


def cmd_snapshots(ctx: Context, args) -> int:
    snapshots = ctx.repo.list_snapshots(host=args.host, limit=args.limit)
    if ctx.json:
        ctx.emit({"snapshots": snapshots})
        return 0
    if not snapshots:
        print("no snapshots")
        return 0
    rows = []
    for snap in snapshots:
        stats = snap.get("stats") or {}
        rows.append(
            [
                snap["id"],
                _fmt_time(snap.get("created")),
                str(snap.get("host", "")),
                snap.get("label", "") or "-",
                f"{stats.get('files', 0)}",
                human_bytes(stats.get("bytes_total", 0)),
                human_bytes(stats.get("bytes_new", 0)),
            ]
        )
    print(_table(rows, ["SNAPSHOT", "CREATED", "HOST", "LABEL", "FILES", "SIZE", "NEW"]))
    return 0


def _describe_chunker(spec: dict | None) -> str:
    if not spec:
        return "-"
    if spec.get("algo") == "fixed":
        return f"fixed {human_bytes(int(spec.get('avg', 0)))}"
    return (
        f"gear, average {human_bytes(int(spec.get('avg', 0)))}"
        f" (min {human_bytes(int(spec.get('min', 0)))}, max {human_bytes(int(spec.get('max', 0)))})"
    )


def cmd_show(ctx: Context, args) -> int:
    manifest = ctx.repo.get_snapshot(args.snapshot)
    entries = manifest.get("entries", [])
    counts = {"f": 0, "d": 0, "l": 0, "x": 0}
    for entry in entries:
        counts[entry.get("t", "x")] = counts.get(entry.get("t", "x"), 0) + 1
    if ctx.json:
        ctx.emit({"manifest_summary": {key: value for key, value in manifest.items() if key != "entries"}, "counts": counts})
        return 0
    print(f"snapshot    : {manifest['id']}")
    print(f"created     : {_fmt_time(manifest.get('created'))}")
    print(f"host        : {manifest.get('host')}  label: {manifest.get('label') or '-'}")
    print(f"sources     : {', '.join(manifest.get('paths', []))}")
    print(f"chunker     : {_describe_chunker(manifest.get('chunker'))}")
    print(f"compression : {manifest.get('codec')}")
    print(f"entries     : {counts['f']} files, {counts['d']} dirs, {counts['l']} symlinks, {counts['x']} skipped")
    stats = manifest.get("stats") or {}
    print(f"size        : {human_bytes(stats.get('bytes_total', 0))}")
    print(f"duration    : {human_duration((manifest.get('duration_ms') or 0) / 1000)}")
    excludes = manifest.get("excludes") or []
    if excludes:
        print(f"excludes    : {', '.join(excludes)}")
    return 0


def cmd_diff(ctx: Context, args) -> int:
    left = ctx.repo.get_snapshot(args.from_snapshot)
    right = ctx.repo.get_snapshot(args.to_snapshot)
    left_map = {entry["p"]: entry for entry in left.get("entries", [])}
    right_map = {entry["p"]: entry for entry in right.get("entries", [])}
    added = sorted(set(right_map) - set(left_map))
    removed = sorted(set(left_map) - set(right_map))
    changed = []
    for path in sorted(set(left_map) & set(right_map)):
        first, second = left_map[path], right_map[path]
        if (
            first.get("t") != second.get("t")
            or first.get("s") != second.get("s")
            or first.get("c") != second.get("c")
            or first.get("m") != second.get("m")
            or first.get("tg") != second.get("tg")
        ):
            changed.append(path)
    payload = {
        "from": left.get("id"),
        "to": right.get("id"),
        "added": added,
        "removed": removed,
        "changed": changed,
    }
    if ctx.json:
        ctx.emit(payload)
        return 0
    limit = args.limit
    for label, items in (("added", added), ("removed", removed), ("changed", changed)):
        print(f"{label}: {len(items)}")
        for path in items[:limit]:
            print(f"  {path}")
        if len(items) > limit:
            print(f"  ... {len(items) - limit} more")
    return 0


def cmd_restore(ctx: Context, args) -> int:
    if not args.to:
        raise UsageError("--to is required (restore somewhere safe, then rsync into place)")
    target = expand_path(args.to)
    manifest = ctx.repo.get_snapshot(args.snapshot)
    options = RestoreOptions(
        target=target,
        include=list(args.include or []),
        exclude=list(args.exclude or []),
        overwrite=args.overwrite,
        dry_run=args.dry_run,
        preserve_owner=args.owner,
        work_dir=expand_path(args.work_dir) if args.work_dir else None,
    )
    if os.path.realpath(str(target)) == os.path.realpath(os.sep) and not args.yes:
        raise UsageError("refusing to restore into '/' without --yes")
    runner = RestoreRunner(
        ctx.repo, manifest, options, log=ctx.log, progress=ctx.progress("download")
    )
    result = runner.run()
    if ctx.json:
        ctx.emit(result)
    else:
        print(f"snapshot    : {result['snapshot']}")
        print(f"target      : {result['target']}")
        if result.get("dry_run"):
            print(f"would write : {result['planned_files']} files, {human_bytes(result['planned_bytes'])}")
            for item in result.get("skipped", [])[:20]:
                print(f"  skip {item['path']}: {item['reason']}")
            return 0
        print(f"restored    : {result['files']} files, {result['dirs']} dirs, {result['symlinks']} symlinks")
        print(f"data        : {human_bytes(result['bytes_written'])}")
        print(f"skipped     : {result['skipped']}")
        print(f"duration    : {human_duration(result['duration_ms'] / 1000)}")
        if result["errors"]:
            print(f"errors      : {len(result['errors'])}")
            for message in result["errors"][:20]:
                print(f"  {message}")
    return 0 if result.get("ok", True) else 1


def cmd_verify(ctx: Context, args) -> int:
    snapshots = (
        ctx.repo.list_snapshots() if args.all else [{"id": args.snapshot}]
    )
    if not snapshots:
        raise UsageError("no snapshot given and the repository has none")
    checked: set[str] = set()
    reports = []
    failures = 0
    for summary in snapshots:
        snapshot_id = summary["id"]
        ctx.log(f"verifying {snapshot_id}")
        manifest = ctx.repo.get_snapshot(snapshot_id)
        ids = []
        for entry in manifest.get("entries", []):
            if entry.get("t") == "f":
                for obj_id, _length in entry_chunks(entry):
                    if obj_id not in checked:
                        ids.append(obj_id)
        ids = list(dict.fromkeys(ids))
        located, missing = ctx.repo.objects_locate(ids) if ids else ({}, [])
        corrupt: list[str] = []
        if not args.quick and located:
            total = len(located)
            done = 0
            for obj_id, payload, flags in ctx.repo.download_chunks(located):
                done += 1
                try:
                    data = decode(flags, payload, located[obj_id][4])
                    if hashlib.sha256(data).hexdigest() != obj_id:
                        corrupt.append(obj_id)
                    else:
                        checked.add(obj_id)
                except HavenError as exc:
                    corrupt.append(obj_id)
                    ctx.log(f"  {obj_id[:12]}: {exc}")
                if ctx.verbose and done % 1000 == 0:
                    ctx.log(f"  checked {done}/{total}")
        report = {
            "snapshot": snapshot_id,
            "chunks": len(ids),
            "missing": missing,
            "corrupt": corrupt,
            "ok": not missing and not corrupt,
        }
        reports.append(report)
        if not report["ok"]:
            failures += 1
    if ctx.json:
        ctx.emit({"reports": reports, "ok": failures == 0})
    else:
        for report in reports:
            status = "ok" if report["ok"] else "FAILED"
            print(
                f"{report['snapshot']}: {status} ({report['chunks']} chunks, "
                f"{len(report['missing'])} missing, {len(report['corrupt'])} corrupt)"
            )
            for obj_id in report["missing"][:5]:
                print(f"  missing {obj_id}")
            for obj_id in report["corrupt"][:5]:
                print(f"  corrupt {obj_id}")
    return 0 if failures == 0 else 1


def cmd_prune(ctx: Context, args) -> int:
    base = ctx.config.retention
    policy = RetentionPolicy(
        keep_last=base.keep_last if args.keep_last is None else args.keep_last,
        keep_daily=base.keep_daily if args.keep_daily is None else args.keep_daily,
        keep_weekly=base.keep_weekly if args.keep_weekly is None else args.keep_weekly,
        keep_monthly=base.keep_monthly if args.keep_monthly is None else args.keep_monthly,
        keep_yearly=base.keep_yearly if args.keep_yearly is None else args.keep_yearly,
        keep_within_days=(
            base.keep_within_days if args.keep_within_days is None else args.keep_within_days
        ),
    )
    if policy.keep_last == 0 and args.apply:
        raise UsageError("refusing to prune with --keep-last 0 (that would delete every snapshot)")
    report = ctx.repo.prune(policy.to_json(), apply=args.apply, host=args.host)
    if ctx.json:
        ctx.emit(report)
        return 0
    print(f"policy      : {policy.describe()}")
    print(f"evaluated   : {report['evaluated']} snapshots")
    print(f"keep        : {len(report['keep'])}")
    print(f"delete      : {len(report['delete'])}")
    for snapshot_id in report["delete"]:
        print(f"  delete {snapshot_id}")
    if args.apply:
        print(f"deleted     : {len(report['deleted'])}")
        print("note: run 'haven gc --apply' to reclaim the freed space")
    else:
        print("dry run: re-run with --apply to delete")
    return 0


def cmd_gc(ctx: Context, args) -> int:
    report = ctx.repo.gc(apply=args.apply, min_age_hours=args.min_age_hours)
    if ctx.json:
        ctx.emit(report)
        return 0
    print(f"packs       : {report['packs']}")
    print(f"dead packs  : {report['dead_packs']}")
    print(f"partial     : {report['partial_packs']} (packs that still hold live and dead chunks)")
    print(f"reclaimable : {report['reclaimable_human']}")
    if args.apply:
        print(f"deleted     : {len(report['deleted'])} packs")
        if report["repacked"]:
            print(f"repacked    : {len(report['repacked'])} packs")
    else:
        print("dry run: re-run with --apply to reclaim")
    return 0


def cmd_cache(ctx: Context, args) -> int:
    cache = ChunkCache(ctx.config.cache_path, ctx.config.chunking.identifier())
    try:
        if args.action == "clear":
            count = cache.clear()
            if ctx.json:
                ctx.emit({"cleared": count, "path": str(ctx.config.cache_path)})
            else:
                print(f"cleared {count} cached file entries")
        else:
            path = ctx.config.cache_path
            size = path.stat().st_size if path and path.exists() else 0
            if ctx.json:
                ctx.emit({"path": str(path), "size": size})
            else:
                print(f"cache       : {path}")
                print(f"size        : {human_bytes(size)}")
    finally:
        cache.close()
    return 0


# --------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default=argparse.SUPPRESS, help="client configuration file")
    common.add_argument("--profile", default=argparse.SUPPRESS, help="profile name in the config")
    common.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="machine readable output")
    common.add_argument("-v", "--verbose", action="store_true", default=argparse.SUPPRESS)
    common.add_argument("-q", "--quiet", action="store_true", default=argparse.SUPPRESS)

    parser = argparse.ArgumentParser(
        prog="haven",
        description="Deduplicating client/server backup for Linux servers",
        parents=[common],
    )
    parser.add_argument("--version", action="version", version=f"haven {__version__}")
    sub = parser.add_subparsers(dest="command")

    init = sub.add_parser("init", parents=[common], help="write a client configuration and test the connection")
    init.add_argument("--url", required=True)
    init.add_argument("--token", required=True)
    init.add_argument("--secret", help="repository secret (hex); generated if omitted")
    init.add_argument("--chunking")
    init.add_argument("--compress")
    init.add_argument("--exclude", action="append")
    init.add_argument("--ca-file")
    init.add_argument("--insecure", action="store_true")
    init.add_argument("--force", action="store_true")
    init.add_argument("--no-check", action="store_true", help="do not contact the server")
    init.set_defaults(func=cmd_init)

    check = sub.add_parser("check", parents=[common], help="check connectivity, credentials and repo identity")
    check.set_defaults(func=cmd_check)

    backup = sub.add_parser("backup", parents=[common], help="create a snapshot")
    backup.add_argument("sources", nargs="*")
    backup.add_argument("--exclude", action="append", help="glob to exclude (repeatable)")
    backup.add_argument("--one-file-system", action="store_true")
    backup.add_argument("--label")
    backup.add_argument("--dry-run", action="store_true")
    backup.add_argument("--no-cache", action="store_true", help="re-read every file, ignore the chunk cache")
    backup.add_argument("--pre-hook", help="command to run before reading files (e.g. a database dump)")
    backup.add_argument("--post-hook", help="command to run after the backup")
    backup.add_argument("--ignore-hook-failure", action="store_true")
    backup.add_argument("--chunking", help="e.g. 'min=64K,avg=1M,max=8M' or 'fixed=8M'")
    backup.add_argument("--compress", help="none or zlib[:1-9]")
    backup.add_argument("--work-dir", help="where to stage the upload pack")
    backup.set_defaults(func=cmd_backup)

    snapshots = sub.add_parser("snapshots", parents=[common], aliases=["list"], help="list snapshots")
    snapshots.add_argument("--host")
    snapshots.add_argument("--limit", type=int, default=50)
    snapshots.set_defaults(func=cmd_snapshots)

    show = sub.add_parser("show", parents=[common], help="show one snapshot")
    show.add_argument("snapshot")
    show.set_defaults(func=cmd_show)

    diff = sub.add_parser("diff", parents=[common], help="compare two snapshots")
    diff.add_argument("from_snapshot")
    diff.add_argument("to_snapshot")
    diff.add_argument("--limit", type=int, default=50)
    diff.set_defaults(func=cmd_diff)

    restore = sub.add_parser("restore", parents=[common], help="restore a snapshot")
    restore.add_argument("snapshot")
    restore.add_argument("--to", help="target directory")
    restore.add_argument("--include", action="append", help="only restore matching paths")
    restore.add_argument("--exclude", action="append")
    restore.add_argument("--overwrite", choices=["never", "if-newer", "always"], default="if-newer")
    restore.add_argument("--dry-run", action="store_true")
    restore.add_argument("--owner", action="store_true", help="restore uid/gid (needs root)")
    restore.add_argument("--yes", action="store_true", help="required when --to /")
    restore.add_argument("--work-dir")
    restore.set_defaults(func=cmd_restore)

    verify = sub.add_parser("verify", parents=[common], help="verify snapshot data end to end")
    verify.add_argument("snapshot", nargs="?")
    verify.add_argument("--all", action="store_true")
    verify.add_argument("--quick", action="store_true", help="only check that chunks exist")
    verify.set_defaults(func=cmd_verify)

    prune = sub.add_parser("prune", parents=[common], help="apply the retention policy")
    # None means "take it from [profiles.<name>.retention]".
    prune.add_argument("--keep-last", type=int, default=None)
    prune.add_argument("--keep-daily", type=int, default=None)
    prune.add_argument("--keep-weekly", type=int, default=None)
    prune.add_argument("--keep-monthly", type=int, default=None)
    prune.add_argument("--keep-yearly", type=int, default=None)
    prune.add_argument("--keep-within-days", type=float, default=None)
    prune.add_argument("--host")
    prune.add_argument("--apply", action="store_true")
    prune.set_defaults(func=cmd_prune)

    gc = sub.add_parser("gc", parents=[common], help="reclaim space from deleted snapshots")
    gc.add_argument("--apply", action="store_true")
    gc.add_argument("--min-age-hours", type=float, default=1.0)
    gc.set_defaults(func=cmd_gc)

    cache = sub.add_parser("cache", parents=[common], help="inspect or clear the local chunk cache")
    cache.add_argument("action", choices=["info", "clear"], nargs="?", default="info")
    cache.set_defaults(func=cmd_cache)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 2
    ctx = Context(args)
    try:
        return int(args.func(ctx, args) or 0)
    except (UsageError, ConfigError) as exc:
        if ctx.json:
            print(json.dumps({"error": exc.as_dict()}, indent=2))
        else:
            print(f"error: {exc.message}", file=sys.stderr)
            if exc.detail:
                print(f"       {exc.detail}", file=sys.stderr)
        return 2
    except HavenError as exc:
        if ctx.json:
            print(json.dumps({"error": exc.as_dict()}, indent=2))
        else:
            print(f"error: {exc.message}", file=sys.stderr)
            if exc.detail:
                print(f"       {exc.detail}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
