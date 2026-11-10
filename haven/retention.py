"""GFS retention: decide which snapshots survive ``haven prune``.

The policy is a union of independent rules, all evaluated per host:

``keep_last``     the N most recent snapshots, regardless of age
``keep_daily``    the newest snapshot of each of the last N days
``keep_weekly``   ... of each of the last N ISO weeks
``keep_monthly``  ... of each of the last N months
``keep_yearly``   ... of each of the last N years
``keep_within``   everything younger than this many days (safety net)

Nothing is deleted unless the caller explicitly asks to apply the plan, and
``keep_last >= 1`` is enforced by the CLI so a policy mistake cannot empty a
repository.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import Iterable

from .errors import UsageError

TIERS = ("daily", "weekly", "monthly", "yearly")


@dataclass
class RetentionPolicy:
    keep_last: int = 3
    keep_daily: int = 7
    keep_weekly: int = 4
    keep_monthly: int = 12
    keep_yearly: int = 0
    keep_within_days: float = 0.0

    def __post_init__(self) -> None:
        for name in ("keep_last", "keep_daily", "keep_weekly", "keep_monthly", "keep_yearly"):
            value = getattr(self, name)
            if not isinstance(value, int) or value < 0:
                raise UsageError(f"retention {name} must be a non-negative integer")
        if self.keep_within_days < 0:
            raise UsageError("retention keep_within_days must be >= 0")
        if not any(
            (self.keep_last, self.keep_daily, self.keep_weekly, self.keep_monthly, self.keep_yearly)
        ) and not self.keep_within_days:
            raise UsageError("retention policy would delete every snapshot")

    def to_json(self) -> dict:
        return {
            "keep_last": self.keep_last,
            "keep_daily": self.keep_daily,
            "keep_weekly": self.keep_weekly,
            "keep_monthly": self.keep_monthly,
            "keep_yearly": self.keep_yearly,
            "keep_within_days": self.keep_within_days,
        }

    @classmethod
    def from_json(cls, data: dict | None) -> "RetentionPolicy":
        if not data:
            return cls()
        allowed = {
            "keep_last",
            "keep_daily",
            "keep_weekly",
            "keep_monthly",
            "keep_yearly",
            "keep_within_days",
        }
        unknown = set(data) - allowed
        if unknown:
            raise UsageError(f"unknown retention keys: {', '.join(sorted(unknown))}")
        values = dict(data)
        if "keep_within_days" in values:
            values["keep_within_days"] = float(values["keep_within_days"])
        return cls(**values)

    def describe(self) -> str:
        parts = []
        for name, label in (
            ("keep_last", "last"),
            ("keep_daily", "daily"),
            ("keep_weekly", "weekly"),
            ("keep_monthly", "monthly"),
            ("keep_yearly", "yearly"),
        ):
            value = getattr(self, name)
            if value:
                parts.append(f"{value} {label}")
        if self.keep_within_days:
            parts.append(f"{self.keep_within_days:g} days")
        return ", ".join(parts) or "nothing"


def _bucket(created: float, tier: str) -> tuple[int, ...]:
    moment = datetime.datetime.fromtimestamp(created, datetime.timezone.utc)
    if tier == "daily":
        return (moment.year, moment.month, moment.day)
    if tier == "weekly":
        iso = moment.isocalendar()
        return (iso.year, iso.week)
    if tier == "monthly":
        return (moment.year, moment.month)
    return (moment.year,)


def select_keep(
    snapshots: Iterable[dict],
    policy: RetentionPolicy,
    *,
    now: float | None = None,
) -> tuple[set[str], set[str]]:
    """Return ``(keep_ids, drop_ids)`` for the given snapshot summaries.

    Each summary must provide ``id`` and ``created``; ``created`` may be a
    float epoch or an ISO string.
    """
    from .util import parse_iso

    normalised: list[dict] = []
    for snap in snapshots:
        created = snap["created"]
        if isinstance(created, str):
            created = parse_iso(created)
        normalised.append({"id": snap["id"], "created": float(created)})
    ordered = sorted(normalised, key=lambda item: (item["created"], item["id"]), reverse=True)
    keep: set[str] = {item["id"] for item in ordered[: policy.keep_last]}
    if policy.keep_within_days and ordered:
        newest = ordered[0]["created"]
        cutoff = newest - policy.keep_within_days * 86400.0
        keep.update(item["id"] for item in ordered if item["created"] >= cutoff)
    counts = {
        "daily": policy.keep_daily,
        "weekly": policy.keep_weekly,
        "monthly": policy.keep_monthly,
        "yearly": policy.keep_yearly,
    }
    for tier in TIERS:
        budget = counts[tier]
        if budget <= 0:
            continue
        seen: set[tuple[int, ...]] = set()
        for item in ordered:
            key = _bucket(item["created"], tier)
            if key in seen:
                continue
            seen.add(key)
            keep.add(item["id"])
            if len(seen) >= budget:
                break
    all_ids = {item["id"] for item in ordered}
    return keep, all_ids - keep
